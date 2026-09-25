"""Run the parsers that read attacker bytes in a separate, locked-down process.

gzip, tarfile, JSON and tree-sitter (C code) all read what a package author wrote. They run in a child process
that cannot open a network connection, cannot write files, and cannot read the user's home directory (outside
the Python install and this package): Seatbelt (`sandbox-exec`) on macOS, `systemd-run` on Linux. The parent
downloads, sends the tarballs in on stdin, and gets JSON back. It checks that JSON before storing it, and
recomputes the score itself.

The sandbox keeps a parser exploit from reaching the network, the database, other releases or the user's files.
It cannot make an exploited parser tell the truth about the package that exploited it."""
import dataclasses
import hashlib
import json
import logging
import math
import os
import resource
import shutil
import subprocess
import sys
from pathlib import Path

from . import differ, engine, execclass, fetcher, rules
from .config import Config
from .models import Diff, Download, FileDiff, FiredRule, Hunk, PkgJsonChange, TriageResult
from .rules import Rule

logger = logging.getLogger(__name__)

_backend = "off"      # chosen once per run by choose(); "seatbelt" | "systemd" | "off"
_PATH_FIELDS = ("db_path", "cache_dir", "lock_path", "rules_dir", "top_npm_path")
_ROOT = Path(__file__).resolve().parent.parent      # the directory npmdiffwatch is imported from
# What the probe must find. home_read may also be "unknown" (no readable file in the home directory to try).
_PROBE_OK = {"network": "blocked", "write": "blocked", "db_read": "blocked", "env": "clean"}
_PROBE_OK_SEATBELT = {"exec": "blocked", "services": "blocked"}     # Linux children inherit the unit's limits
_PKG = _ROOT / "npmdiffwatch"
_SYSTEMD_ENV = ("PATH", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
_PARENT_RULES = {"maintainer", "dep"}     # rule types computed from registry metadata, never the tarball


class SandboxError(Exception):
    """The sandbox could not be used, or the worker failed or sent back something malformed."""


# ---- the work itself: no network, no database ----
def compute(cfg, dl: Download, maintainer_context, ruleset):
    art = fetcher.extract_download(cfg, dl)
    d = differ.build_diff(art)
    return art, d, engine.triage(d, cfg, ruleset, maintainer_context)


# ---- parent -> worker: one JSON line, then the raw tarballs ----
def _cfg_to_dict(cfg) -> dict:
    d = {f.name: getattr(cfg, f.name) for f in dataclasses.fields(cfg) if f.name != "reviewer"}
    for k in _PATH_FIELDS:
        if d[k] is not None:
            d[k] = str(Path(d[k]).resolve())
    return d


def _cfg_from_dict(d: dict) -> Config:
    return Config(**{k: (Path(v) if k in _PATH_FIELDS and v is not None else v) for k, v in d.items()})


def _encode_input(cfg, dl: Download, maintainer_context, ruleset) -> bytes:
    # The parent's loaded rules travel with the request: rule files edited mid-run can't make the two disagree.
    head = {"cfg": _cfg_to_dict(cfg), "maintainer_context": maintainer_context, "sys_path": _import_paths(),
            "rules": [dataclasses.asdict(r) for r in ruleset],
            "dl": {"package": dl.package, "version": dl.version, "prior_version": dl.prior_version,
                   "is_new_package": dl.is_new_package, "maintainer_metadata": dl.maintainer_metadata,
                   "added_dep_findings": dl.added_dep_findings, "scripts_field": dl.scripts_field,
                   "new_len": len(dl.new_blob), "prior_len": None if dl.prior_blob is None else len(dl.prior_blob)}}
    return json.dumps(head).encode() + b"\n" + dl.new_blob + (dl.prior_blob or b"")


def _decode_input(head: dict, stream):
    m = head["dl"]
    new = stream.read(m["new_len"])
    prior = stream.read(m["prior_len"]) if m["prior_len"] is not None else None
    dl = Download(m["package"], m["version"], m["prior_version"], m["is_new_package"], new, prior,
                  maintainer_metadata=m["maintainer_metadata"], added_dep_findings=m["added_dep_findings"],
                  scripts_field=m["scripts_field"])
    return _cfg_from_dict(head["cfg"]), dl, head["maintainer_context"], [Rule(**r) for r in head["rules"]]


# ---- worker -> parent: JSON, checked field by field ----
def _encode_output(art, d: Diff, tr: TriageResult) -> dict:
    return {"flags": {"has_lockfile": art.has_lockfile, "has_shrinkwrap": art.has_shrinkwrap},
            "diff": {"package": d.package, "version": d.version, "is_first_release": d.is_first_release,
                     "changed": [{"path": f.path, "change_kind": f.change_kind, "new_text": f.new_text,
                                  "hunks": [{"old_range": list(h.old_range), "new_range": list(h.new_range),
                                             "added": h.added, "removed": h.removed} for h in f.hunks]}
                                 for f in d.changed],
                     "added_binaries": d.added_binaries,
                     "package_json_changes": [{"field": c.field, "old": c.old, "new": c.new}
                                              for c in d.package_json_changes],
                     "description": d.description,
                     "file_classes": d.file_classes, "loaders": d.loaders, "listed": d.listed,
                     "lock_meta": getattr(d, "_lock_meta", {}),
                     "changed_scripts": sorted(getattr(d, "_changed_scripts", frozenset())),
                     "changed_script_text": getattr(d, "_changed_script_text", "")},
            "triage": {"fired_rules": [{"rule": r.rule, "weight": r.weight, "file": r.file, "lines": list(r.lines)}
                                       for r in tr.fired_rules]}}


def _check(ok: bool, what: str):
    if not ok:
        raise SandboxError(f"sandbox sent back a malformed {what}")


def _str(v, what, optional=False):
    _check(isinstance(v, str) or (optional and v is None), what)
    return v


def _strs(v, what):
    _check(isinstance(v, list) and all(isinstance(x, str) for x in v), what)
    return v


def _pair(v, what):
    _check(isinstance(v, list) and len(v) == 2 and all(type(x) is int for x in v), what)
    return tuple(v)


def _dict(v, what):
    _check(isinstance(v, dict) and all(isinstance(k, str) for k in v), what)
    return v


def _decode_output(raw: bytes, cfg, ruleset):
    try:
        out = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise SandboxError(f"sandbox sent back something that is not JSON: {e}") from e
    _dict(out, "reply")
    if "error" in out:
        if out.get("error_type") == "RefusedToExtract":
            raise fetcher.RefusedToExtract(_str(out["error"], "refusal"))
        raise SandboxError(f"sandbox worker failed: {str(out['error'])[:500]}")
    try:
        flags = _dict(out["flags"], "flags")
        _check(set(flags) == {"has_lockfile", "has_shrinkwrap"} and all(type(v) is bool for v in flags.values()),
               "flags")
        dd = _dict(out["diff"], "diff")
        changed = []
        for f in dd["changed"]:
            _dict(f, "file diff")
            _check(f["change_kind"] in ("added", "removed", "modified"), "change kind")
            hunks = [Hunk(_pair(h["old_range"], "hunk range"), _pair(h["new_range"], "hunk range"),
                          _strs(h["added"], "hunk"), _strs(h["removed"], "hunk")) for h in f["hunks"]]
            changed.append(FileDiff(_str(f["path"], "path"), f["change_kind"], hunks,
                                    _str(f["new_text"], "file text", optional=True)))
        bins = dd["added_binaries"]
        _check(isinstance(bins, list) and all(isinstance(b, dict) and all(
            isinstance(k, str) and (v is None or type(v) in (str, int)) for k, v in b.items()) for b in bins),
            "binary list")
        pkg = [PkgJsonChange(_str(c["field"], "package.json change"), _str(c["old"], "package.json change", True),
                             _str(c["new"], "package.json change", True)) for c in dd["package_json_changes"]]
        lock_meta = _dict(dd["lock_meta"], "lockfile facts")
        _check(all(type(v) is bool for v in lock_meta.values()), "lockfile facts")
        _check(type(dd["is_first_release"]) is bool, "diff")
        fc = _dict(dd["file_classes"], "file classes")
        _check(all(isinstance(v, list) and len(v) == 2 and v[0] in execclass.CLASSES and isinstance(v[1], str)
                   for v in fc.values()), "file classes")
        ld = _dict(dd["loaders"], "loaders")
        for v in ld.values():
            _strs(v, "loader lines")
        listed = dd["listed"]
        _check(isinstance(listed, list) and all(
            isinstance(x, dict) and set(x) == {"path", "size", "class"} and isinstance(x["path"], str)
            and type(x["size"]) is int and x["size"] >= 0 and x["class"] == "inert" for x in listed), "listed files")
        d = Diff(_str(dd["package"], "diff"), _str(dd["version"], "diff"), dd["is_first_release"], changed, bins,
                 [], pkg, _str(dd["description"], "description"), fc, ld, listed)
        object.__setattr__(d, "_lock_meta", lock_meta)
        object.__setattr__(d, "_changed_scripts", frozenset(_strs(dd["changed_scripts"], "script list")))
        object.__setattr__(d, "_changed_script_text", _str(dd["changed_script_text"], "script text"))

        known = {r.id for r in ruleset}
        fired = []
        for r in _dict(out["triage"], "triage")["fired_rules"]:
            _dict(r, "fired rule")
            _check(r["rule"] in known, "rule id")
            _check(type(r["weight"]) in (int, float) and math.isfinite(r["weight"]) and r["weight"] >= 0, "weight")
            fired.append(FiredRule(r["rule"], float(r["weight"]), _str(r["file"], "rule file"),
                                   _pair(r["lines"], "rule lines")))
    except (KeyError, TypeError, AttributeError) as e:
        raise SandboxError(f"sandbox sent back a malformed reply: {e!r}") from e
    score = sum(r.weight for r in fired)
    return flags, d, TriageResult(score, fired, score >= cfg.threshold_t)


# ---- launching the worker ----
def _home() -> str:
    return os.path.realpath(os.path.expanduser("~"))


def _import_paths() -> list[str]:
    """Where the worker may import from: the parent's own import path, minus anything that would open up the
    whole home directory."""
    home = _home()
    out = []
    for p in [str(_ROOT)] + sys.path:
        rp = os.path.realpath(p or os.getcwd())
        if os.path.isdir(rp) and not (home == rp or home.startswith(rp.rstrip("/") + "/")) and rp not in out:
            out.append(rp)
    return out


def _readable(cfg) -> list[str]:
    """Directories the worker may read everything in. A directory that contains npmdiffwatch (the repo root, in
    a source checkout) is left out: only the package itself is opened up, not the repo's other files."""
    pkg = str(_PKG.resolve())
    paths = [p for p in _import_paths() if not (pkg + "/").startswith(p.rstrip("/") + "/")]
    paths += [pkg, os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix), os.path.realpath(cfg.rules_dir)]
    return list(dict.fromkeys(paths))


def _listable(cfg) -> list[str]:
    """Directories on the import path that contain npmdiffwatch: listable so the import works, contents closed."""
    pkg = str(_PKG.resolve())
    return [p for p in _import_paths() if (pkg + "/").startswith(p.rstrip("/") + "/")]


def _private_dirs(cfg) -> list[str]:
    """The database, cache and lock directories: never readable by the worker, wherever they are."""
    return list(dict.fromkeys([os.path.realpath(Path(cfg.db_path).parent), os.path.realpath(Path(cfg.lock_path).parent),
                               os.path.realpath(cfg.cache_dir)]))


def _worker_argv() -> list[str]:
    # -I: ignore PYTHON* variables, the user site and the current directory; the parent's import path is
    # passed in instead, so the worker runs exactly the code the parent runs.
    return [sys.executable, "-I", "-c",
            f"import sys; sys.path.insert(0, {str(_ROOT)!r}); from npmdiffwatch._parse_worker import main; main()"]


def _quote(p: str) -> str:
    return '"' + p.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _seatbelt_profile(cfg) -> str:
    """Later rules win. Beyond network and writes it denies: starting any program but this Python (and so
    `open`), forking, and Mach service lookups (LaunchServices could open a URL for the worker, outside the
    sandbox)."""
    allow = " ".join(f"(subpath {_quote(p)})" for p in _readable(cfg))
    listable = " ".join(f"(literal {_quote(p)})" for p in _listable(cfg))
    private = " ".join(f"(subpath {_quote(p)})" for p in _private_dirs(cfg))
    exe = " ".join(f"(literal {_quote(p)})" for p in dict.fromkeys([sys.executable, os.path.realpath(sys.executable)]))
    return ("(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n"
            "(deny process-exec*)\n"
            f"(allow process-exec {exe} (subpath {_quote(os.path.realpath(sys.base_prefix))}))\n"
            "(deny process-fork)\n(deny mach-lookup)\n"
            f"(deny file-read-data (subpath {_quote(_home())}))\n"
            f"(allow file-read-data {allow}{' ' + listable if listable else ''})\n"
            f"(deny file-read-data {private})\n")


def _seatbelt_cmd(cfg) -> list[str]:
    return ["sandbox-exec", "-p", _seatbelt_profile(cfg)] + _worker_argv()


def _systemd_cmd(cfg) -> list[str]:
    user = os.geteuid() != 0
    cmd = ["systemd-run", "--pipe", "--wait", "--collect", "--quiet"] + (["--user"] if user else [])
    props = ["PrivateNetwork=yes", "ProtectSystem=strict", "ProtectHome=tmpfs", "PrivateTmp=yes",
             "NoNewPrivileges=yes", "SystemCallFilter=@system-service", f"MemoryMax={cfg.parse_memory_max}",
             f"RuntimeMaxSec={int(cfg.parse_timeout_s)}", "TasksMax=16"]
    if user:
        props.append("PrivateUsers=yes")        # a user manager needs its own user namespace for the rest
    props += [f"BindReadOnlyPaths=-{p}" for p in _readable(cfg)]
    props += [f"InaccessiblePaths=-{p}" for p in _private_dirs(cfg)]
    return cmd + [f"--property={p}" for p in props] + ["--"] + _worker_argv()


def _run(cfg, backend: str, payload: bytes) -> bytes:
    # The worker gets none of this process's environment (API keys, tokens). systemd-run only needs what it
    # takes to reach the service manager; the unit it starts does not inherit these.
    env = {} if backend == "seatbelt" else {k: os.environ[k] for k in _SYSTEMD_ENV if k in os.environ}
    if backend == "seatbelt":
        cmd = _seatbelt_cmd(cfg)
        cpu = int(cfg.parse_timeout_s)
        pre = lambda: resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))     # noqa: E731
    elif backend == "systemd":
        cmd, pre = _systemd_cmd(cfg), None
    else:
        raise SandboxError(f"unknown sandbox {backend!r}")
    try:
        proc = subprocess.run(cmd, input=payload, capture_output=True, timeout=cfg.parse_timeout_s + 10,
                              preexec_fn=pre, env=env)
    except subprocess.TimeoutExpired as e:
        raise SandboxError(f"{backend} sandbox timed out after {cfg.parse_timeout_s:.0f}s") from e
    except OSError as e:
        raise SandboxError(f"could not start the {backend} sandbox: {e}") from e
    if proc.returncode != 0:
        raise SandboxError(f"{backend} sandbox exited {proc.returncode}: "
                           f"{proc.stderr.decode('utf-8', 'replace')[:500]}")
    return proc.stdout


def analyze(cfg, dl: Download, maintainer_context, backend: str | None = None, ruleset=None):
    """Unpack, diff and triage one download. Returns ({has_lockfile, has_shrinkwrap}, Diff, TriageResult).
    Raises fetcher.RefusedToExtract when the tarball breaks a limit, SandboxError when the worker fails."""
    backend = backend or _backend
    ruleset = ruleset if ruleset is not None else rules.load_rules(cfg.rules_dir)
    if backend == "off":
        art, d, tr = compute(cfg, dl, maintainer_context, ruleset)
        flags = {"has_lockfile": art.has_lockfile, "has_shrinkwrap": art.has_shrinkwrap}
    else:
        flags, d, tr = _decode_output(_run(cfg, backend, _encode_input(cfg, dl, maintainer_context, ruleset)),
                                      cfg, ruleset)
        _check(d.package == dl.package and d.version == dl.version, "diff (wrong release)")
        d.added_dep_findings.extend(dl.added_dep_findings)     # the parent's own findings, not the worker's copy
    object.__setattr__(d, "publishing", dict((dl.maintainer_metadata or {}).get("publishing") or {}))
    return flags, d, _with_registry_rules(cfg, dl, d, tr, maintainer_context, ruleset)


def _with_registry_rules(cfg, dl: Download, d: Diff, tr: TriageResult, maintainer_context, ruleset) -> TriageResult:
    """Rules the parent can evaluate from registry metadata, without the tarball, so a worker taken over by the
    package cannot drop them.
    - Ownership and dependency rules: the parent's results replace the worker's.
    - package.json rules, on the registry's copy of package.json (new vs prior version): added to the worker's
      tarball-based results, each rule once. They also catch a registry manifest that differs from the
      package.json in the tarball."""
    own = {r.id for r in ruleset if r.applies_to in _PARENT_RULES}
    meta = engine.triage(Diff(d.package, d.version, d.is_first_release, [], [], list(dl.added_dep_findings)),
                         cfg, [r for r in ruleset if r.id in own], maintainer_context)
    fired = [r for r in tr.fired_rules if r.rule not in own] + meta.fired_rules
    if dl.manifest is not None:
        have = {r.rule for r in fired}
        reg = engine.triage(_manifest_diff(dl), cfg, [r for r in ruleset if r.applies_to == "package_json"])
        fired += [r for r in reg.fired_rules if r.rule not in have]
    score = sum(r.weight for r in fired)
    return TriageResult(score, fired, score >= cfg.threshold_t)


def _manifest_diff(dl: Download) -> Diff:
    first = dl.prior_manifest is None
    changes, scripts, text = differ._diff_json(None if first else json.dumps(dl.prior_manifest).encode(),
                                               json.dumps(dl.manifest).encode())
    if first:   # as for a tarball: on a first release only an install-time script is a signal
        changes = [c for c in changes if c.field == "scripts"] if scripts else []
    md = Diff(dl.package, dl.version, first, [], [], [], changes)
    object.__setattr__(md, "_lock_meta", {})
    object.__setattr__(md, "_changed_scripts", scripts)
    object.__setattr__(md, "_changed_script_text", text)
    return md


# ---- checking that the sandbox actually holds ----
def _home_sentinel() -> str | None:
    """A file in the home directory the worker must not be able to read."""
    home = _home()
    try:
        names = sorted(os.listdir(home))
    except OSError:
        return None
    for n in names:
        p = os.path.join(home, n)
        if os.path.isfile(p) and os.access(p, os.R_OK):
            return p
    return None


_PLAIN_ENV = {"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "TERM", "TMPDIR", "PWD", "SHLVL", "_",
              "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "__CF_USER_TEXT_ENCODING"}


def probe(cfg, backend: str) -> dict:
    """Run the worker in probe mode. It tries to reach the network, write next to the database, read the
    database directory and a file in the home directory, start a program, look up a macOS service, and find
    this process's environment values. Returns {check: "blocked"|"open"|"unknown"|"n/a"}, env "clean"|"leaked"."""
    db_dir = Path(cfg.db_path).resolve().parent
    db_dir.mkdir(parents=True, exist_ok=True)
    target = db_dir / f".sandbox-probe-write-{os.getpid()}"
    sentinel = db_dir / f".sandbox-probe-read-{os.getpid()}"
    sentinel.write_text("x")
    # Hashes of this process's environment values (not the values): the worker reports any it can see.
    env_hashes = sorted({hashlib.sha256(v.encode()).hexdigest() for k, v in os.environ.items()
                         if k not in _PLAIN_ENV and not k.startswith("LC_") and len(v) >= 8})
    head = {"probe": True, "write_target": str(target), "db_file": str(sentinel), "home_file": _home_sentinel(),
            "env_hashes": env_hashes, "sys_path": _import_paths()}
    try:
        raw = _run(cfg, backend, json.dumps(head).encode() + b"\n")
    finally:
        for p in (target, sentinel):
            if p.exists():
                p.unlink()
    try:
        res = json.loads(raw)
    except ValueError as e:
        raise SandboxError(f"sandbox probe sent back something that is not JSON: {e}") from e
    _check(isinstance(res, dict) and set(res) == {"network", "write", "home_read", "db_read", "exec", "services",
                                                  "env"}, "probe result")
    return res


def _holds(res: dict, backend: str) -> bool:
    need = {**_PROBE_OK, **(_PROBE_OK_SEATBELT if backend == "seatbelt" else {})}
    return all(res.get(k) == v for k, v in need.items()) and res.get("home_read") != "open"


def choose(cfg, which=shutil.which, probe=probe, platform=sys.platform) -> str:
    """Pick the sandbox for this run and prove it holds. "auto" falls back to scanning without one, loudly;
    "on" refuses."""
    mode = cfg.parse_sandbox
    if mode == "off":
        return "off"
    backend = ("seatbelt" if platform == "darwin" and which("sandbox-exec")
               else "systemd" if platform.startswith("linux") and which("systemd-run") else None)
    why = "no sandbox-exec (macOS) or systemd-run (Linux) on this machine"
    if backend:
        try:
            res = probe(cfg, backend)
            if _holds(res, backend):
                return backend
            why = f"the {backend} sandbox did not hold: {res}"
        except SandboxError as e:
            why = f"the {backend} sandbox could not run: {e}"
    if mode == "on":
        raise SandboxError(f"parse_sandbox = \"on\" but {why}")
    msg = (f"[npmdiffwatch] WARNING: scanning WITHOUT a sandbox ({why}). Package files are unpacked and parsed "
           f"inside this process. Set parse_sandbox = \"on\" to refuse to scan instead.")
    print(msg, flush=True)
    logger.warning(msg)
    return "off"
