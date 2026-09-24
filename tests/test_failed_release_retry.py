"""A release that fails to download or process never holds the cursor: the scan moves on to newer releases, and
the failed one is retried from the database at the start of the next scans (the retry limit and longer
deadlines are covered in test_scan_retry_limit)."""
import dataclasses
from pathlib import Path

from npmdiffwatch import fetcher, ingest, orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.ingest import ChangesPage
from npmdiffwatch.models import NewRelease

BAD = NewRelease("fresh-pkg", "1.0.0", 5010)
GOOD = NewRelease("other-pkg", "2.0.0", 5020)


def _cfg(tmp_path):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "run.lock",
                              cache_dir=tmp_path / "c", reviewer_enabled=False, rules_dir=Path("rules/community"))
    conn = store.connect(cfg); store.init_schema(conn)
    store.set_last_serial(conn, 5000)
    conn.close()
    return cfg


def _tick(cfg, monkeypatch, page, fetch):
    monkeypatch.setattr(ingest, "changes_since", lambda *a, **k: page)
    monkeypatch.setattr(fetcher, "fetch_artifacts", fetch)
    orchestrator.run_once(cfg, seed_if_fresh=False)
    return store.connect(cfg)


def _fails_for(*bad):
    calls = []

    def fetch(cfg, rel, meta=None):
        calls.append(rel.package)
        if rel.package in bad:
            raise OSError("HTTP Error 404: Not Found")
        return None          # no tarball: a terminal outcome, enough for these tests
    return fetch, calls


def test_a_failed_release_does_not_hold_the_cursor(tmp_path, monkeypatch):
    fetch, _ = _fails_for("fresh-pkg")
    conn = _tick(_cfg(tmp_path), monkeypatch, ChangesPage(releases=[BAD, GOOD], watermark=5030), fetch)
    assert store.get_last_serial(conn) == 5030
    assert store.get_stage(conn, "fresh-pkg", "1.0.0") == "fetch_failed"
    assert store.get_stage(conn, "other-pkg", "2.0.0") == "no_sdist"


def test_the_failed_release_is_retried_on_the_next_scan(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    fetch, _ = _fails_for("fresh-pkg")
    _tick(cfg, monkeypatch, ChangesPage(releases=[BAD], watermark=5010), fetch)
    fetch, calls = _fails_for()
    conn = _tick(cfg, monkeypatch, ChangesPage(releases=[], watermark=5010), fetch)
    assert calls == ["fresh-pkg"]
    assert store.get_stage(conn, "fresh-pkg", "1.0.0") == "no_sdist"


def test_a_retried_release_is_not_scanned_again_once_it_succeeds(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _tick(cfg, monkeypatch, ChangesPage(releases=[BAD], watermark=5010), _fails_for("fresh-pkg")[0])
    _tick(cfg, monkeypatch, ChangesPage(releases=[], watermark=5010), _fails_for()[0])
    fetch, calls = _fails_for()
    _tick(cfg, monkeypatch, ChangesPage(releases=[BAD], watermark=5010), fetch)
    assert calls == []


def test_a_failed_release_seen_again_in_the_feed_is_tried_once_per_scan(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _tick(cfg, monkeypatch, ChangesPage(releases=[BAD], watermark=5010), _fails_for("fresh-pkg")[0])
    fetch, calls = _fails_for("fresh-pkg")
    conn = _tick(cfg, monkeypatch, ChangesPage(releases=[BAD], watermark=5010), fetch)
    assert calls == ["fresh-pkg"]
    assert store.scan_attempts(conn, "fresh-pkg", "1.0.0") == 2
