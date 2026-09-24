"""The scan database must not grow without bound.

Every release used to store npm's full packument (packument_json) — up to 65 MB each,
never read back: 4.5 GB of a 4.8 GB database after one overnight run. It is no longer
stored, and `prune` clears it from existing databases and compacts the file, keeping
verdicts, evidence and queued review inputs.
"""
import dataclasses
from pathlib import Path
from types import SimpleNamespace

from npmdiffwatch import orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import NewRelease


def _cfg(tmp_path):
    return dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l",
                               cache_dir=tmp_path / "c", rules_dir=Path("rules/community"),
                               reviewer_enabled=False)


def test_processing_a_release_does_not_store_the_packument(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    art = SimpleNamespace(prior_version=None, is_new_package=True, maintainer_metadata=None,
                          packument_json="x" * 100_000, scripts_field={"test": "jest"},
                          has_lockfile=False, has_shrinkwrap=False, new_files={}, prior_files={},
                          added_binaries=[], added_dep_findings=[], package="p", version="1.0.0")
    orchestrator._process_fetched(dataclasses.replace(cfg, new_package_policy="skip"), conn, None,
                                  orchestrator._load_ruleset(cfg), NewRelease("p", "1.0.0", 1), art)
    row = conn.execute("SELECT packument_json, scripts_json FROM releases WHERE package='p'").fetchone()
    assert row["packument_json"] is None
    assert row["scripts_json"] is not None          # the small, used fields are still kept


def test_prune_clears_packuments_keeps_findings_and_shrinks_the_file(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    for i in range(20):
        rid = store.record_release(conn, f"p{i}", "1.0.0", i, False, None, "tgz")
        conn.execute("UPDATE releases SET packument_json=?, evidence=? WHERE id=?", ("{" + "x" * 200_000 + "}", "ev", rid))
    store.park_for_review(conn, rid, "too_large", "needs 1 chars, cap 0",
                          "untrusted_content_marker: M\n\nM\ncode\nM")
    conn.commit(); conn.close()
    before = cfg.db_path.stat().st_size

    freed = orchestrator.prune(cfg)

    conn = store.connect(cfg)
    assert conn.execute("SELECT count(*) FROM releases WHERE packument_json IS NOT NULL").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM releases WHERE evidence='ev'").fetchone()[0] == 20
    assert store.review_input(store.pending_reviews(conn)[0]).endswith("code\nM")
    assert cfg.db_path.stat().st_size < before / 5 and freed > 0
