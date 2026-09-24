"""A release whose package metadata can't be downloaded must never vanish. Live: a 33 MB packument hit the
120 s deadline, ingest couldn't tell which version was released, dropped the row and moved the cursor past
it — no release row, no retry, only a log line."""
import dataclasses

from npmdiffwatch import fetcher, ingest, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import NewRelease

_OK = {"versions": {"1.0.0": {}}, "time": {"1.0.0": "2026-09-24T00:00:00.000Z"}}


def _feed(monkeypatch, packument):
    changes = {"results": [{"seq": 1010, "id": "huge-meta"}], "last_seq": 1010}
    state = {"packument": packument}

    def fake(url, cfg, **k):
        if "_changes" in url:
            return changes if state.get("feed", True) else {"results": [], "last_seq": 1020}
        return state["packument"]
    monkeypatch.setattr(ingest, "_fetch_json", fake)
    return state


def _conn(tmp_path):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite")
    conn = store.connect(cfg); store.init_schema(conn)
    return conn


def test_failed_metadata_is_kept_for_retry_not_dropped(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    _feed(monkeypatch, {})                                   # {} = download failed (None would be a 404)
    page = ingest.changes_since(Config(), 1000, conn, limit=200)
    assert page.releases == [] and page.watermark == 1010    # the cursor still moves on
    assert store.feed_retry_counts(conn) == {"retrying": 1, "gave_up": 0}


def test_next_tick_retries_it_and_emits_the_release(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    st = _feed(monkeypatch, {})
    ingest.changes_since(Config(), 1000, conn, limit=200)
    st.update(packument=_OK, feed=False)
    page = ingest.changes_since(Config(), 1010, conn, limit=200)
    assert [(r.package, r.version, r.serial) for r in page.releases] == [("huge-meta", "1.0.0", 1010)]
    assert store.feed_retry_counts(conn) == {"retrying": 0, "gave_up": 0}


def test_gives_up_visibly_after_three_attempts(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    st = _feed(monkeypatch, {})
    ingest.changes_since(Config(), 1000, conn, limit=200)
    st["feed"] = False
    for _ in range(3):
        ingest.changes_since(Config(), 1010, conn, limit=200)
    assert store.feed_retry_counts(conn) == {"retrying": 0, "gave_up": 1}


def test_fetcher_metadata_failure_is_a_fetch_failure_not_no_sdist(monkeypatch):
    monkeypatch.setattr(fetcher, "_fetch_json", lambda *a, **k: {})
    try:
        fetcher.fetch_artifacts(Config(), NewRelease("huge-meta", "1.0.0", 1))
        raise AssertionError("expected a fetch failure")
    except fetcher.MetadataUnavailable:
        pass


def test_packument_gets_the_longer_metadata_deadline(monkeypatch):
    seen = []
    monkeypatch.setattr(fetcher, "read_body", lambda r, cfg, limit=None, deadline=None: seen.append(deadline) or b"{}")

    class R:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(fetcher.urllib.request, "urlopen", lambda *a, **k: R())
    monkeypatch.setattr(ingest.urllib.request, "urlopen", lambda *a, **k: R())
    monkeypatch.setattr(ingest, "read_body", fetcher.read_body)
    cfg = Config()
    fetcher._fetch_json("https://registry.npmjs.org/x", cfg)
    ingest._fetch_json("https://registry.npmjs.org/x", cfg)
    assert seen == [cfg.packument_deadline_s] * 2 and cfg.packument_deadline_s == 300.0


def test_pending_view_reports_metadata_failures(tmp_path, monkeypatch):
    from npmdiffwatch import orchestrator
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite")
    conn = store.connect(cfg); store.init_schema(conn)
    _feed(monkeypatch, {})
    ingest.changes_since(cfg, 1000, conn, limit=200)
    assert orchestrator.feed_retry_counts(cfg) == {"retrying": 1, "gave_up": 0}
