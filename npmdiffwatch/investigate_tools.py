"""The investigator's tools: fixed, read-only functions over packages held in memory and registry/GitHub
metadata. The model supplies names, versions, paths and strings; every URL is built here. Nothing runs."""
import base64
import codecs
import difflib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from . import egress, execclass, fetcher, sandbox

_REGISTRY = "https://registry.npmjs.org"
_GITHUB = "https://api.github.com"
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)
_VERSION = re.compile(r"^[0-9A-Za-z.+-]{1,64}$")
_SEG = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_MAX_GREP = 50
_DECODE_PER_CALL, _DECODE_MAX_DEPTH = 3, 8
_ADDRESSES_REVIEWER = re.compile(
    r"ignore (?:all |any )?(?:previous|prior|above) instructions|verdict\s*[:=]\s*(?:benign|safe|suspicious)"
    r"|classify (?:this|it) as|this package is (?:safe|benign)|(?:ai|llm|model|reviewer|assistant)[, ]+"
    r"(?:please |you must )?(?:ignore|report|mark|treat)", re.I)
_HOOKS = ("preinstall", "install", "postinstall", "prepare")


class ToolError(Exception):
    pass


def _http_get(url: str, cfg, token: str | None = None) -> tuple[int, bytes]:
    headers = {"User-Agent": "npmdiffwatch-investigator/0.1"}
    if token and url.startswith(_GITHUB + "/repos/"):
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s) as r:
            return r.status, fetcher.read_body(r, cfg, cfg.max_download_bytes)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except urllib.error.URLError as e:
        if isinstance(e.reason, egress.EgressDenied):
            raise e.reason
        raise


def _extract_off(cfg, blob):
    return sandbox.extract_files(cfg, blob, "off")


def _inflate_off(data, method, n):
    return sandbox.inflate(None, data, method, n, "off")


def _seg(v, what) -> str:
    if not isinstance(v, str) or not _SEG.match(v) or v in (".", ".."):
        raise ToolError(f"invalid {what}: {v!r}")
    return v


def _name(v) -> str:
    if not isinstance(v, str) or len(v) > 214 or not _NPM_NAME.match(v):
        raise ToolError(f"invalid package name: {v!r}")
    return v


def _ver(v) -> str:
    if not isinstance(v, str) or not _VERSION.match(v):
        raise ToolError(f"invalid version: {v!r}")
    return v


def _pkg_url(name: str) -> str:
    return f"{_REGISTRY}/{urllib.parse.quote(name, safe='@')}"


class Workspace:
    def __init__(self, cfg, flagged, *, http=None, extract=None, inflate=None):
        self.cfg, self.inv = cfg, cfg.investigator
        token = os.environ.get(self.inv.github_token_env) if self.inv.github_token_env else None
        self._http = http or (lambda url: _http_get(url, cfg, token))
        self._extract = extract or (lambda c, blob: sandbox.extract_files(c, blob))
        self._inflate = inflate or (lambda c, data, m, n: sandbox.inflate(c, data, m, n))
        self.package, self.version, self.prior_version = flagged.package, flagged.version, flagged.prior_version
        self.files: dict[str, dict[str, bytes]] = {}
        self.binaries: dict[str, list[dict]] = {}
        self.read_full: set[tuple[str, str]] = set()
        self.read_text: dict[tuple[str, str], str] = {}
        self.scripts_seen: set[str] = set()
        self.facts: list[str] = []
        self.log: list[dict] = []
        self.decoded: dict[str, tuple[bytes, int]] = {}
        self.decoded_budget = self.inv.max_decoded_bytes
        self.downloaded = 0
        self.extracted = 0
        self._load("flagged", flagged.new_blob)
        if flagged.prior_blob is not None:
            self._load("prior", flagged.prior_blob)

    # ---- plumbing ----
    def _load(self, label, blob):
        files, bins = self._extract(self.cfg, blob)
        size = sum(len(b) for b in files.values())
        if self.extracted + size > self.inv.max_extracted_mb * 1_000_000:
            raise ToolError("unpacked size limit for this investigation reached")
        self.extracted += size
        self.files[label], self.binaries[label] = files, bins

    def _get(self, url) -> bytes:
        try:
            status, body = self._http(url)
        except egress.EgressDenied as e:
            self.facts.append(f"a tool request was denied by the egress allowlist: {e}")
            raise ToolError(f"denied: {e}") from e
        if status == 404:
            raise ToolError("not found")
        if status != 200:
            raise ToolError(f"HTTP {status}")
        self.downloaded += len(body)
        if self.downloaded > self.inv.max_download_mb * 1_000_000:
            raise ToolError("download limit for this investigation reached")
        return body

    def _json(self, url) -> dict:
        try:
            return json.loads(self._get(url))
        except ValueError as e:
            raise ToolError(f"not JSON: {e}") from e

    def _version_files(self, label) -> dict[str, bytes]:
        if label not in self.files:
            raise ToolError(f"unknown version {label!r}: use flagged, prior, or fetch one first")
        return self.files[label]

    def _seen(self, label, path, text) -> str:
        key = (label, path)
        self.read_text[key] = self.read_text.get(key, "") + "\n" + text
        if _ADDRESSES_REVIEWER.search(text):
            self.facts.append(f"{label}:{path} contains text that addresses the reviewer (possible injection)")
        return text

    def call(self, name: str, args: dict) -> str:
        fn = getattr(self, f"_t_{name}", None)
        if fn is None:
            raise ToolError(f"unknown tool {name!r}")
        if not isinstance(args, dict):
            raise ToolError("arguments must be an object")
        try:
            out = fn(**args)
        except (TypeError, ValueError, AttributeError, KeyError) as e:
            raise ToolError(f"bad arguments or data for {name}: {e}") from e
        except (fetcher.RefusedToExtract, sandbox.SandboxError) as e:
            raise ToolError(f"could not unpack: {e}") from e
        self.log.append({"tool": name, "args": {k: str(v)[:200] for k, v in args.items()}})
        return out

    def required_files(self) -> list[str]:
        files = self.files["flagged"]
        out: list[str] = []
        for cls, _, roots in execclass._roots(execclass._manifest(files), files):
            out += [p for p in roots if p not in out]
        return out

    def too_large(self) -> list[str]:
        files = self.files["flagged"]
        return [p for p in self.required_files() if len(files.get(p, b"")) > self.inv.whole_file_chars]

    # ---- tools ----
    def _t_files(self, version):
        files = self._version_files(version)
        classes, _ = execclass.classify(files)
        lines = [f"{p}  {len(b)} bytes  {classes.get(p, ('other',))[0]}" for p, b in sorted(files.items())]
        lines += [f"{b['path']}  {b.get('size', '?')} bytes  binary or too large (sha256 {b.get('sha256', '?')})"
                  for b in self.binaries.get(version, [])]
        return "\n".join(lines[:500]) + (f"\n... and {len(lines) - 500} more" if len(lines) > 500 else "")

    def _t_read(self, version, path, from_line=None, to_line=None):
        files = self._version_files(version)
        if path not in files:
            raise ToolError(f"no such file {path!r} in {version}")
        text = files[path].decode("utf-8", errors="replace")
        if from_line is None and to_line is None and len(text) <= self.inv.whole_file_chars:
            self.read_full.add((version, path))
            return self._seen(version, path, text)
        lines = text.splitlines()
        a = max(1, int(from_line or 1)); b = int(to_line or len(lines))
        chunk = "\n".join(lines[a - 1:b])[: self.inv.read_chars]
        note = "" if from_line or to_line else (f"[too large to read whole ({len(text)} chars); "
                                                f"lines {a}-{b} shown up to {self.inv.read_chars} chars]\n")
        return note + self._seen(version, path, chunk)

    def _t_grep(self, version, text):
        if not isinstance(text, str) or not text:
            raise ToolError("text must be a non-empty string")
        hits = []
        for p, b in sorted(self._version_files(version).items()):
            for i, ln in enumerate(b.decode("utf-8", errors="replace").splitlines(), 1):
                if text in ln:
                    hits.append(f"{p}:{i}: {ln.strip()[:200]}")
                    if len(hits) >= _MAX_GREP:
                        break
        out = "\n".join(hits) if hits else "no matches"
        for h in hits:
            p = h.split(":", 1)[0]
            self._seen(version, p, h.split(": ", 1)[1] if ": " in h else h)
        return out

    def _t_scripts(self, version):
        files = self._version_files(version)
        scripts = execclass._manifest(files).get("scripts")
        scripts = scripts if isinstance(scripts, dict) else {}
        self.scripts_seen.add(version)
        out = []
        for hook in _HOOKS:
            cmd = scripts.get(hook)
            if not isinstance(cmd, str):
                continue
            targets = execclass._command_files(cmd, files)
            note = " (runs only from a git checkout or npm publish, not on a registry install)" if hook == "prepare" else ""
            out.append(f"{hook}: {cmd}{note}\n  runs: " + (", ".join(targets) if targets else "inline (no file in package)"))
        return self._seen("scripts", version, "\n".join(out) if out else "no install scripts")   # a summary, not a file

    def _t_decode(self, methods, value=None, ref=None):
        if not isinstance(methods, list) or not 1 <= len(methods) <= _DECODE_PER_CALL:
            raise ToolError(f"methods must be a list of 1-{_DECODE_PER_CALL} steps")
        if ref is not None:
            if ref not in self.decoded:
                raise ToolError(f"unknown ref {ref!r}")
            data, depth = self.decoded[ref]
        elif isinstance(value, str):
            data, depth = value.encode("utf-8", errors="replace"), 0
        else:
            raise ToolError("give value or ref")
        if depth + len(methods) > _DECODE_MAX_DEPTH:
            raise ToolError(f"decode depth limit ({_DECODE_MAX_DEPTH} layers) reached")
        truncated = False
        for m in methods:
            data, cut = self._decode_one(data, m)
            truncated = truncated or cut
        self.decoded_budget -= len(data)
        if self.decoded_budget < 0:
            raise ToolError("decode output limit for this investigation reached")
        rid = f"d{len(self.decoded) + 1}"
        self.decoded[rid] = (data, depth + len(methods))
        if depth + len(methods) > _DECODE_PER_CALL:
            self.facts.append(f"a payload is nested more than {_DECODE_PER_CALL} encodings deep")
        text = data.decode("utf-8", errors="replace")[: self.inv.read_chars]
        head = f"[{rid}] depth {depth + len(methods)}" + (" (truncated)" if truncated else "") + "\n"
        return head + self._seen("decoded", rid, text)

    def _decode_one(self, data: bytes, m: str) -> tuple[bytes, bool]:
        try:
            if m == "base64":
                return base64.b64decode(data + b"=" * (-len(data) % 4), validate=False), False
            if m == "hex":
                return bytes.fromhex(data.decode().strip()), False
            if m == "reverse":
                return data[::-1], False
            if m == "unescape":
                return codecs.decode(urllib.parse.unquote(data.decode("latin-1")), "unicode_escape").encode(
                    "utf-8", errors="replace"), False
            if m == "charcodes":
                return bytes(int(x) for x in re.findall(rb"\d+", data)[:100_000] if int(x) < 256), False
            if m in ("gzip", "zlib"):
                n = max(0, min(self.decoded_budget, self.inv.max_decoded_bytes))
                out = self._inflate(self.cfg, data, m, n + 1)
                return (out[:n], True) if len(out) > n else (out, False)
        except (ValueError, UnicodeDecodeError, sandbox.SandboxError) as e:
            raise ToolError(f"{m} failed: {e}") from e
        raise ToolError(f"unknown method {m!r}")

    def _t_diff(self, version_a, version_b):
        a, b = self._version_files(version_a), self._version_files(version_b)
        out = []
        for p in sorted(set(a) | set(b)):
            if a.get(p) == b.get(p):
                continue
            la = a.get(p, b"").decode("utf-8", "replace").splitlines()
            lb = b.get(p, b"").decode("utf-8", "replace").splitlines()
            out += list(difflib.unified_diff(la, lb, f"{version_a}/{p}", f"{version_b}/{p}", lineterm="", n=1))
            if sum(len(x) for x in out) > self.inv.read_chars:
                out.append("... (diff truncated)")
                break
        text = "\n".join(out)[: self.inv.read_chars] or "no differences"
        return self._seen("diff", f"{version_a}..{version_b}", text)    # never quotable as a flagged file

    def _t_versions(self, package):
        meta = self._json(_pkg_url(_name(package)))
        times = meta.get("time") if isinstance(meta.get("time"), dict) else {}
        rows = []
        for v, data in list((meta.get("versions") or {}).items())[-30:]:
            pub = (data.get("_npmUser") or {}).get("name") if isinstance(data, dict) else None
            prov = bool(((data or {}).get("dist") or {}).get("attestations"))
            rows.append(f"{v}  published {times.get(v, '?')}  by {pub or '?'}  provenance {'yes' if prov else 'no'}")
        return "\n".join(rows) or "no versions"

    def _t_maintainer(self, name):
        _seg(name, "maintainer name")
        q = urllib.parse.urlencode({"text": f"maintainer:{name}", "size": 50})
        res = self._json(f"{_REGISTRY}/-/v1/search?{q}")
        pkgs = [o.get("package", {}).get("name") for o in res.get("objects", []) if isinstance(o, dict)]
        rows = []
        for p in [p for p in pkgs if isinstance(p, str)][:10]:
            try:
                t = self._json(_pkg_url(_name(p))).get("time") or {}
                rows.append(f"{p}  first published {t.get('created', '?')}")
            except ToolError as e:
                rows.append(f"{p}  ({e})")
        more = f"\n... {len(pkgs) - 10} more packages" if len(pkgs) > 10 else ""
        return ("\n".join(rows) + more) if rows else "no packages found"

    def _t_fetch(self, package, version):
        label = f"{_name(package)}@{_ver(version)}"
        if label in self.files:
            return f"{label} already loaded"
        meta = self._json(_pkg_url(package))
        tarball = (((meta.get("versions") or {}).get(version) or {}).get("dist") or {}).get("tarball")
        if not isinstance(tarball, str):
            raise ToolError(f"{label} has no tarball")
        if urllib.parse.urlsplit(tarball).hostname != "registry.npmjs.org" or not tarball.startswith("https://"):
            raise ToolError(f"tarball for {label} is not on the registry: refused")
        self._load(label, self._get(tarball))
        return f"loaded {label}: {len(self.files[label])} text files"

    def _t_github(self, owner, repo):
        o, r = _seg(owner, "owner"), _seg(repo, "repo")
        meta = self._json(f"{_GITHUB}/repos/{o}/{r}")
        tags = self._json(f"{_GITHUB}/repos/{o}/{r}/tags?per_page=20")
        tag_names = [t.get("name") for t in tags if isinstance(t, dict)] if isinstance(tags, list) else []
        return (f"repository {o}/{r}: created {meta.get('created_at')}, pushed {meta.get('pushed_at')}, "
                f"default branch {meta.get('default_branch')}, archived {meta.get('archived')}\n"
                f"latest tags: {', '.join(str(t) for t in tag_names) or 'none'}")

    def _t_github_file(self, owner, repo, path, ref):
        o, r = _seg(owner, "owner"), _seg(repo, "repo")
        parts = [_seg(p, "path segment") for p in str(path).split("/")]
        refq = urllib.parse.urlencode({"ref": "/".join(_seg(p, "ref segment") for p in str(ref).split("/"))})
        data = self._json(f"{_GITHUB}/repos/{o}/{r}/contents/{'/'.join(parts)}?{refq}")
        if not isinstance(data, dict) or data.get("encoding") != "base64":
            raise ToolError("not a file")
        text = base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
        return self._seen(f"github:{o}/{r}@{ref}", "/".join(parts), text[: self.inv.read_chars])


def _spec(name, desc, props, required):
    return {"name": name, "description": desc,
            "parameters": {"type": "object", "properties": props, "required": required, "additionalProperties": False}}


_S, _I = {"type": "string"}, {"type": "integer"}
TOOL_SPECS = [
    _spec("files", "List a version's files with size and when each runs.", {"version": _S}, ["version"]),
    _spec("read", "Read a file. With no line range, the whole file (counts as examined if it fits).",
          {"version": _S, "path": _S, "from_line": _I, "to_line": _I}, ["version", "path"]),
    _spec("grep", "Find lines containing this exact text (not a regex).", {"version": _S, "text": _S},
          ["version", "text"]),
    _spec("scripts", "Install scripts and the file each actually runs.", {"version": _S}, ["version"]),
    _spec("decode", "Decode a value or an earlier decode output (ref like d1): base64, hex, reverse, unescape, "
          "charcodes, gzip, zlib. Up to 3 steps per call.",
          {"methods": {"type": "array", "items": _S}, "value": _S, "ref": _S}, ["methods"]),
    _spec("diff", "Changes between two loaded versions.", {"version_a": _S, "version_b": _S},
          ["version_a", "version_b"]),
    _spec("versions", "Every version of a package with publish time, publisher, provenance.", {"package": _S},
          ["package"]),
    _spec("maintainer", "A maintainer's packages with first-publish dates.", {"name": _S}, ["name"]),
    _spec("fetch", "Load another version or package from the npm registry (never run).",
          {"package": _S, "version": _S}, ["package", "version"]),
    _spec("github", "A GitHub repository's metadata and latest tags.", {"owner": _S, "repo": _S},
          ["owner", "repo"]),
    _spec("github_file", "A file from a GitHub repository at a ref.",
          {"owner": _S, "repo": _S, "path": _S, "ref": _S}, ["owner", "repo", "path", "ref"]),
]
