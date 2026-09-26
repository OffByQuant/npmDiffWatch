"""Routing must not be talked into clearing: dependency specs that fetch other code, labels a worker could
forge, entry points moved onto code nobody diffed, documentation that crowds out the change."""
import dataclasses
import io
import json
import tarfile
from pathlib import Path

import pytest

from npmdiffwatch import differ, engine, orchestrator, reviewer, routing, rules, sandbox, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import ArtifactSet, Diff, FileDiff, NewRelease, PkgJsonChange, TriageResult

_RULES = rules.load_rules(Path("rules/community"))
_PUB = {"provenance_now": False, "provenance_before": False, "trusted_publisher_now": None,
        "trusted_publisher_before": None, "publisher_changed": False, "maintainers_changed": False}
_TR = TriageResult(0.0, [], False)


def _d(changed=(), classes=None, pkg=()):
    return Diff("p", "1.0.1", False, list(changed), [], [], list(pkg), "", classes or {}, {}, [], dict(_PUB))


@pytest.mark.parametrize("spec", ["npm:other-pkg@1.0.0", "git+https://example.invalid/x.git",
                                  "https://example.invalid/x.tgz", "file:../x", "someone/lodash"])
def test_an_existing_dependency_pointed_elsewhere_is_not_a_bump(spec):
    c = PkgJsonChange("dependencies", json.dumps({"lodash": "^4.17.0"}), json.dumps({"lodash": spec}))
    assert routing.route(_d(pkg=[c])).tier == "model"


def test_a_range_bump_is_still_a_bump():
    c = PkgJsonChange("dependencies", json.dumps({"a": "^1.2.0", "b": "latest"}),
                      json.dumps({"a": ">=1.3.0 <2", "b": "latest"}))
    assert routing.route(_d(pkg=[c])).tier == "fact"


def test_registry_manifest_changes_count_even_if_the_tarball_shows_none():
    reg = [PkgJsonChange("scripts", None, json.dumps({"postinstall": "node x.js"}))]
    r = routing.route(_d(), registry_changes=reg)
    assert r.tier == "model" and r.priority == 3


def test_an_inert_label_on_a_code_path_is_not_trusted():
    r = routing.route(_d([FileDiff("index.js", "modified", [], "hello")], {"index.js": ["inert", "docs"]}))
    assert r.tier == "model"


def test_only_install_hook_script_changes_are_top_priority():
    c = PkgJsonChange("scripts", json.dumps({"test": "a"}), json.dumps({"test": "b"}))
    assert routing.route(_d(pkg=[c])).priority == 1


def _art(prior, new):
    def enc(d):
        return {k: v.encode() for k, v in d.items()}
    return ArtifactSet("p", "1.0.1", "1.0.0", "tgz", enc(new), enc(prior), {})


def test_a_removed_file_with_text_is_malformed():
    d = differ.build_diff(_art({"package.json": '{"name":"p","version":"1.0.0"}', "a.js": "1"},
                               {"package.json": '{"name":"p","version":"1.0.1"}'}))
    tr = engine.triage(d, Config(), _RULES)
    art = type("A", (), {"has_lockfile": False, "has_shrinkwrap": False})()
    out = sandbox._encode_output(art, d, tr)
    for f in out["diff"]["changed"]:
        if f["change_kind"] == "removed":
            f["new_text"] = "x"
    with pytest.raises(sandbox.SandboxError):
        sandbox._decode_output(json.dumps(out).encode(), Config(), _RULES)


def test_main_moved_onto_an_unchanged_file_shows_that_file():
    alt = "module.exports = require('./impl');\n"
    d = differ.build_diff(_art({"package.json": '{"name":"p","version":"1.0.0","main":"index.js"}',
                                "index.js": "1", "lib/alt.js": alt},
                               {"package.json": '{"name":"p","version":"1.0.1","main":"lib/alt.js"}',
                                "index.js": "1", "lib/alt.js": alt}))
    fd = next(f for f in d.changed if f.path == "lib/alt.js")
    assert fd.change_kind == "unchanged" and d.file_classes["lib/alt.js"][0] == "load"


_MAP = json.dumps({"version": 3, "mappings": ";".join("AAAA" * 20 for _ in range(600))})


def test_a_regenerated_source_map_does_not_crowd_out_the_short_check():
    d = differ.build_diff(_art({"package.json": '{"name":"p","version":"1.0.0"}', "index.js": "x()",
                                "dist/i.js.map": '{"version":3}'},
                               {"package.json": '{"name":"p","version":"1.0.1"}', "index.js": "y()",
                                "dist/i.js.map": _MAP}))
    fd = next(f for f in d.changed if f.path == "dist/i.js.map")
    assert fd.hunks == [] and fd.new_text == _MAP          # text for the content check, no hunks
    text = reviewer.short_input(d, _TR)
    assert text is not None and "AAAA" not in text and "dist/i.js.map (inert," in text


def test_a_huge_doc_named_file_fails_closed_as_data():
    big = "a" * 300_000
    d = differ.build_diff(_art({"package.json": '{"name":"p","version":"1.0.0"}', "index.js": "1"},
                               {"package.json": '{"name":"p","version":"1.0.1"}', "index.js": "1",
                                "README.md": big}))
    assert d.file_classes["README.md"][0] == "data"


def test_a_relabelled_doc_is_shown_whole():
    js = "const h = require('https');\nmodule.exports = () => eval(process.env.X);\n"
    d = Diff("p", "1.0.1", False, [FileDiff("docs.md", "added", [], js)], [], [], [], "",
             {"docs.md": ["data", "named like documentation, but its content is not"]}, {}, [], {})
    text = reviewer.build_review_input(d, _TR, max_chars=60_000)
    assert "--- file: docs.md (added; whole file) ---" in text and "  const h = require('https');" in text


def _cfg(tmp_path):
    return dataclasses.replace(Config(), db_path=tmp_path / "d.sqlite", lock_path=tmp_path / "l")


def test_a_failing_re_download_does_not_stop_the_drain(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    for i, p in enumerate(("a", "b")):
        rid = store.record_release(conn, p, "1.0.0", i + 1, False, None, "tgz")
        store.park_for_review(conn, rid, "not_reviewed_yet", "busy", "")
    monkeypatch.setattr(orchestrator, "_scan_release", lambda *a, **k: (_ for _ in ()).throw(OSError("reset")))
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=object()), auto=True)
    reasons = {r["package"]: r["pending_reason"] for r in store.pending_reviews(conn)}
    assert reasons == {"a": "review_failed", "b": "review_failed"}


def _tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for n, b in files.items():
            ti = tarfile.TarInfo(f"package/{n}"); ti.size = len(b); t.addfile(ti, io.BytesIO(b))
    return buf.getvalue()


def test_the_unsandboxed_path_gets_publishing_facts_and_can_clear_by_fact(tmp_path):
    cfg = dataclasses.replace(_cfg(tmp_path), rules_dir=Path("rules/community"))
    conn = store.connect(cfg); store.init_schema(conn)
    meta = {"publishing": {k: v for k, v in _PUB.items() if k not in ("publisher_changed", "maintainers_changed")}}
    art = ArtifactSet("p", "1.0.1", "1.0.0", "tgz",
                      {"package.json": b'{"name":"p","version":"1.0.1"}', "README.md": b"# new\n"},
                      {"package.json": b'{"name":"p","version":"1.0.0"}', "README.md": b"# old\n"}, {},
                      maintainer_metadata=meta)
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), NewRelease("p", "1.0.1", 5), art)
    assert store.get_stage(conn, "p", "1.0.1") == "cleared_by_fact"
