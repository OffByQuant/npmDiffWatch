import json
from pathlib import Path

import pytest

from npmdiffwatch import differ, engine, rules, sandbox
from npmdiffwatch.config import Config
from npmdiffwatch.models import ArtifactSet

_RULES = rules.load_rules(Path("rules/community"))


def _art(prior: dict, new: dict) -> ArtifactSet:
    def enc(d):
        return {k: v.encode() for k, v in d.items()}
    return ArtifactSet("p", "1.0.1", "1.0.0", "tgz", enc(new), enc(prior), {})


_PJ = json.dumps({"name": "p", "version": "1.0.1", "main": "index.js"})
_PJ0 = json.dumps({"name": "p", "version": "1.0.0", "main": "index.js"})
_LOADER = "const d = require('./config/data.json');\nmodule.exports = d;\n"


def test_changed_data_file_is_classed_with_its_loader():
    d = differ.build_diff(_art({"package.json": _PJ0, "index.js": _LOADER, "config/data.json": "{}"},
                               {"package.json": _PJ, "index.js": _LOADER, "config/data.json": '{"a": 1}'}))
    assert d.file_classes["config/data.json"][0] == "data"
    assert d.loaders["config/data.json"] == ["index.js:1: const d = require('./config/data.json');"]
    assert "config/data.json" in {f.path for f in d.changed}


def test_changed_inert_files_carry_text_not_hunks_and_huge_ones_are_data():
    d = differ.build_diff(_art({"package.json": _PJ0, "index.js": ""},
                               {"package.json": _PJ, "index.js": "", "dist/a.js.map": '{"version":3}',
                                "dist/b.js.map": "x" * 900_000}))
    a = next(f for f in d.changed if f.path == "dist/a.js.map")
    assert a.hunks == [] and a.new_text == '{"version":3}' and d.file_classes["dist/a.js.map"][0] == "inert"
    assert d.file_classes["dist/b.js.map"][0] == "data"

def test_a_data_file_does_not_change_triage():
    base = {"package.json": _PJ0, "index.js": _LOADER, "config/data.json": "{}"}
    same = differ.build_diff(_art(base, {**base, "package.json": _PJ}))
    more = differ.build_diff(_art(base, {**base, "package.json": _PJ,
                                         "config/data.json": '{"u": "https://x.example.invalid", '
                                                             '"b": "' + "QUJD" * 60 + '"}'}))
    cfg = Config()
    assert engine.triage(more, cfg, _RULES).score == engine.triage(same, cfg, _RULES).score


def test_classes_round_trip_through_the_worker_encoding():
    d = differ.build_diff(_art({"package.json": _PJ0, "index.js": _LOADER, "config/data.json": "{}"},
                               {"package.json": _PJ, "index.js": _LOADER, "config/data.json": '{"a": 1}',
                                "README.md": "hi"}))
    tr = engine.triage(d, Config(), _RULES)
    art = type("A", (), {"has_lockfile": False, "has_shrinkwrap": False})()
    raw = json.dumps(sandbox._encode_output(art, d, tr)).encode()
    _, back, _ = sandbox._decode_output(raw, Config(), _RULES)
    assert back.file_classes == d.file_classes and back.loaders == d.loaders and back.listed == d.listed


@pytest.mark.parametrize("bad", [
    {"file_classes": {"a.js": ["evil", "x"]}},
    {"loaders": {"a.json": [1]}},
    {"listed": [{"path": "a.map", "size": -1, "class": "inert"}]},
])
def test_decode_rejects_a_bad_file_class(bad):
    d = differ.build_diff(_art({"package.json": _PJ0, "index.js": ""}, {"package.json": _PJ, "index.js": "1"}))
    tr = engine.triage(d, Config(), _RULES)
    art = type("A", (), {"has_lockfile": False, "has_shrinkwrap": False})()
    out = sandbox._encode_output(art, d, tr)
    out["diff"].update(bad)
    with pytest.raises(sandbox.SandboxError):
        sandbox._decode_output(json.dumps(out).encode(), Config(), _RULES)


def test_a_code_file_named_like_a_doc_is_diffed():
    d = differ.build_diff(_art({"package.json": _PJ0, "index.js": ""},
                               {"package.json": _PJ, "index.js": "", "lib/notice.js": "eval(x)"}))
    assert "lib/notice.js" in {f.path for f in d.changed}


def test_a_removed_inert_file_is_listed_not_diffed():
    d = differ.build_diff(_art({"package.json": _PJ0, "index.js": "", "dist/a.js.map": "x" * 900_000},
                               {"package.json": _PJ, "index.js": ""}))
    assert "dist/a.js.map" not in {f.path for f in d.changed}
    assert d.listed == [{"path": "dist/a.js.map", "size": 0, "class": "inert"}]


def test_the_worker_cannot_supply_publishing():
    d = differ.build_diff(_art({"package.json": _PJ0, "index.js": ""}, {"package.json": _PJ, "index.js": "1"}))
    tr = engine.triage(d, Config(), _RULES)
    art = type("A", (), {"has_lockfile": False, "has_shrinkwrap": False})()
    out = sandbox._encode_output(art, d, tr)
    out["diff"]["publishing"] = {"provenance_now": True}
    _, back, _ = sandbox._decode_output(json.dumps(out).encode(), Config(), _RULES)
    assert back.publishing == {}
