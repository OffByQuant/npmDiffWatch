import json
from pathlib import Path

from npmdiffwatch import differ, engine, reviewer, rules, sandbox
from npmdiffwatch.config import Config
from npmdiffwatch.models import ArtifactSet, TriageResult

_RULES = rules.load_rules(Path("rules/community"))


def _art(prior, new):
    def enc(d):
        return {k: v.encode() for k, v in d.items()}
    return ArtifactSet("p", "1.0.1", "1.0.0", "tgz", enc(new), enc(prior), {})


_SCRIPT = "console.log('setup');\n"
_PJ0 = json.dumps({"name": "p", "version": "1.0.0"})
_PJ1 = json.dumps({"name": "p", "version": "1.0.1", "scripts": {"postinstall": "node scripts/setup.js"}})


def _d():
    return differ.build_diff(_art({"package.json": _PJ0, "scripts/setup.js": _SCRIPT},
                                  {"package.json": _PJ1, "scripts/setup.js": _SCRIPT}))


def test_an_unchanged_script_a_new_hook_runs_is_shown():
    d = _d()
    fd = next(f for f in d.changed if f.path == "scripts/setup.js")
    assert fd.change_kind == "unchanged" and fd.new_text == _SCRIPT and fd.hunks == []
    assert d.file_classes["scripts/setup.js"][0] == "install"
    text = reviewer.build_review_input(d, TriageResult(0.0, [], False), max_chars=60_000)
    assert "--- file: scripts/setup.js (unchanged; a changed install script runs it) ---" in text
    assert "  console.log('setup');" in text


def test_unchanged_kind_round_trips_through_the_worker_encoding():
    d = _d()
    tr = engine.triage(d, Config(), _RULES)
    art = type("A", (), {"has_lockfile": False, "has_shrinkwrap": False})()
    _, back, _ = sandbox._decode_output(json.dumps(sandbox._encode_output(art, d, tr)).encode(), Config(), _RULES)
    assert any(f.change_kind == "unchanged" for f in back.changed)


def test_an_unchanged_file_with_hunks_is_malformed():
    import pytest
    d = _d()
    tr = engine.triage(d, Config(), _RULES)
    art = type("A", (), {"has_lockfile": False, "has_shrinkwrap": False})()
    out = sandbox._encode_output(art, d, tr)
    for f in out["diff"]["changed"]:
        if f["change_kind"] == "unchanged":
            f["hunks"] = [{"old_range": [0, 0], "new_range": [0, 1], "added": ["x"], "removed": []}]
    with pytest.raises(sandbox.SandboxError):
        sandbox._decode_output(json.dumps(out).encode(), Config(), _RULES)
