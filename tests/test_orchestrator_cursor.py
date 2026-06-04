"""Cursor advancement in run_once: the watermark must move past release-less
pages, but a blocked (retryable) release must pin the cursor so it is retried."""
import dataclasses
from pathlib import Path

from npmdiffwatch import orchestrator, ingest, fetcher, store
from npmdiffwatch.config import Config
from npmdiffwatch.ingest import ChangesPage
from npmdiffwatch.models import NewRelease


def _cfg(tmp_path) -> Config:
    return dataclasses.replace(
        Config(),
        db_path=tmp_path / "db.sqlite",
        lock_path=tmp_path / "run.lock",
        cache_dir=tmp_path / "cache",
        reviewer_enabled=False,
        rules_dir=Path("rules/community"),
    )


def _seed_cursor(cfg, value):
    conn = store.connect(cfg)
    store.init_schema(conn)
    store.set_last_serial(conn, value)
    conn.close()


def test_release_less_page_advances_cursor_to_watermark(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _seed_cursor(cfg, 5000)
    monkeypatch.setattr(ingest, "changes_since",
                        lambda *a, **k: ChangesPage(releases=[], watermark=5100))

    n = orchestrator.run_once(cfg, seed_if_fresh=False)

    assert n == 0
    conn = store.connect(cfg)
    assert store.get_last_serial(conn) == 5100


def test_blocked_release_pins_cursor_for_retry(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _seed_cursor(cfg, 5000)
    rel = NewRelease("stuck-pkg", "1.0.0", 5050)
    monkeypatch.setattr(ingest, "changes_since",
                        lambda *a, **k: ChangesPage(releases=[rel], watermark=5100))

    def boom(cfg, rel):
        raise ConnectionError("registry down")
    monkeypatch.setattr(fetcher, "fetch_artifacts", boom)

    orchestrator.run_once(cfg, seed_if_fresh=False)

    conn = store.connect(cfg)
    # Must NOT jump to the watermark (5100) past the unprocessed release.
    assert store.get_last_serial(conn) == 5000
