"""A release the registry no longer serves when we come to scan it. npm marks a removed package explicitly
(`time.unpublished`); a single removed version is just missing. Either way nothing was scanned, nobody is
asked to review it, and nothing alerts: the release is kept on record with how it went, and counted."""
import dataclasses
from pathlib import Path

from npmdiffwatch import dashboard, fetcher, orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import NewRelease

_UNPUBLISHED = {"_id": "gone-pkg", "name": "gone-pkg",
                "time": {"unpublished": {"time": "2026-09-24T16:20:00.905Z", "versions": ["1.0.0"]}}}
_VERSION_GONE = {"_id": "kept-pkg", "name": "kept-pkg", "dist-tags": {"latest": "0.9.0"},
                 "versions": {"0.9.0": {"dist": {"tarball": "https://registry.npmjs.org/kept-pkg/-/kept-pkg-0.9.0.tgz"}}},
                 "time": {"0.9.0": "2026-09-01T00:00:00Z", "1.0.0": "2026-09-24T00:00:00Z"}}


def _cfg(tmp_path):
    return dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l",
                               cache_dir=tmp_path / "c", reviewer_enabled=False, rules_dir=Path("rules/community"))


def test_the_registrys_unpublished_marker_is_identified_with_its_time(tmp_path):
    got = fetcher.download(_cfg(tmp_path), NewRelease("gone-pkg", "1.0.0", 1), _UNPUBLISHED)
    assert got == fetcher.Removed("unpublished", "2026-09-24T16:20:00.905Z")


def test_a_missing_version_of_a_live_package_is_identified_without_a_time(tmp_path):
    got = fetcher.download(_cfg(tmp_path), NewRelease("kept-pkg", "1.0.0", 1), _VERSION_GONE)
    assert got == fetcher.Removed("version_gone", None)


def test_a_removed_release_is_recorded_not_alerted_not_queued(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    orchestrator._process_fetched(cfg, conn, None, None, NewRelease("gone-pkg", "1.0.0", 7),
                                  fetcher.Removed("unpublished", "2026-09-24T16:20:00.905Z"))
    assert store.get_stage(conn, "gone-pkg", "1.0.0") == "removed_before_scan"
    row = conn.execute("SELECT removed_reason, removed_at FROM releases WHERE package='gone-pkg'").fetchone()
    assert tuple(row) == ("unpublished", "2026-09-24T16:20:00.905Z")
    assert conn.execute("SELECT count(*) FROM verdicts").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0
    assert capsys.readouterr().out == ""
    assert orchestrator.list_pending(cfg) == []
    assert store.removed_counts(conn) == {"unpublished": 1}


def test_the_status_strip_counts_removed_releases_by_identifier():
    html = dashboard.render_dashboard([], status=dict(
        releases_total=3, verdicts_total=0, flagged_total=0, reviewer="x", model_reachable=None,
        removed={"unpublished": 2, "version_gone": 1}))
    assert "3 removed before scan (unpublished: 2, version gone: 1)" in html


def test_export_passes_removed_counts_to_the_dashboard(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    orchestrator._process_fetched(cfg, conn, None, None, NewRelease("kept-pkg", "1.0.0", 7),
                                  fetcher.Removed("version_gone", None))
    text = Path(orchestrator.export_dashboard(cfg, tmp_path / "d.html")).read_text()
    assert "1 removed before scan (version gone: 1)" in text
