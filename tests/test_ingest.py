"""Ingest against the npm _changes replication feed.

The feed is the real front door: monotonic integer `seq` from
https://replicate.npmjs.com/registry/_changes drives the cursor. These tests
inject the HTTP layer by monkeypatching ingest._fetch_json keyed on URL, so no
network is touched.
"""
from npmdiffwatch import ingest
from npmdiffwatch.config import Config


def _fake_http(routes):
    """Return a fake _fetch_json(url, cfg) that dispatches on URL substrings."""
    def fake(url, cfg):
        for needle, payload in routes.items():
            if needle in url:
                return payload
        raise AssertionError(f"unexpected URL: {url}")
    return fake


def _packument(versions, times=None, latest=None):
    doc = {"versions": {v: {} for v in versions}}
    if times:
        doc["time"] = times
    if latest:
        doc["dist-tags"] = {"latest": latest}
    return doc


def test_current_serial_reads_update_seq(monkeypatch):
    cfg = Config()
    monkeypatch.setattr(ingest, "_fetch_json",
                        _fake_http({"/registry/": {"db_name": "registry", "update_seq": 113259473}}))
    assert ingest.current_serial(cfg) == 113259473


def test_current_serial_none_when_unavailable(monkeypatch):
    cfg = Config()
    monkeypatch.setattr(ingest, "_fetch_json", _fake_http({"/registry/": {}}))
    assert ingest.current_serial(cfg) is None


def test_changes_since_emits_release_with_seq_as_serial(monkeypatch):
    cfg = Config()
    changes = {"results": [{"seq": 1010, "id": "leftpad", "changes": [{"rev": "2-x"}]}],
               "last_seq": 1010}
    monkeypatch.setattr(ingest, "_fetch_json", _fake_http({
        "_changes": changes,
        "/leftpad": _packument(["1.0.0"], times={"1.0.0": "2024-01-01T00:00:00.000Z"}),
    }))
    page = ingest.changes_since(cfg, 1000, conn=None, limit=200)
    assert [(r.package, r.version, r.serial) for r in page.releases] == [("leftpad", "1.0.0", 1010)]


def test_changes_since_skips_deleted(monkeypatch):
    cfg = Config()
    changes = {"results": [{"seq": 2000, "id": "gone-pkg", "changes": [{"rev": "3-y"}],
                            "deleted": True}],
               "last_seq": 2000}
    monkeypatch.setattr(ingest, "_fetch_json", _fake_http({"_changes": changes}))
    page = ingest.changes_since(cfg, 1500, conn=None, limit=200)
    assert page.releases == []


def test_watermark_advances_past_release_less_page(monkeypatch):
    """A page of only deleted/non-release changes must still advance the cursor,
    otherwise the poller re-reads the same page forever (cursor-stall)."""
    cfg = Config()
    changes = {"results": [{"seq": 2001, "id": "a", "deleted": True},
                           {"seq": 2002, "id": "b", "deleted": True}],
               "last_seq": 2002}
    monkeypatch.setattr(ingest, "_fetch_json", _fake_http({"_changes": changes}))
    page = ingest.changes_since(cfg, 2000, conn=None, limit=200)
    assert page.releases == []
    assert page.watermark == 2002


def test_changes_since_picks_newest_unseen_version_by_time(monkeypatch):
    """The change fires on the just-published version; pick the newest-by-time
    version not already known, not just dist-tags.latest."""
    cfg = Config()
    changes = {"results": [{"seq": 3000, "id": "pkg", "changes": [{"rev": "5-z"}]}],
               "last_seq": 3000}
    pack = _packument(
        ["1.0.0", "1.0.1", "2.0.0"],
        times={"1.0.0": "2024-01-01T00:00:00.000Z",
               "2.0.0": "2024-02-01T00:00:00.000Z",
               "1.0.1": "2024-06-01T00:00:00.000Z"},  # newest by time, not semver
        latest="2.0.0",
    )
    monkeypatch.setattr(ingest, "_fetch_json", _fake_http({"_changes": changes, "/pkg": pack}))
    page = ingest.changes_since(cfg, 2999, conn=None, limit=200)
    assert [r.version for r in page.releases] == ["1.0.1"]


def test_empty_feed_returns_watermark_equal_to_since(monkeypatch):
    cfg = Config()
    monkeypatch.setattr(ingest, "_fetch_json", _fake_http({"_changes": {"results": [], "last_seq": 5000}}))
    page = ingest.changes_since(cfg, 5000, conn=None, limit=200)
    assert page.releases == []
    assert page.watermark == 5000


def test_changes_url_targets_replicate_feed_with_since_and_limit():
    cfg = Config()
    url = ingest._changes_url(cfg, 1234, 200)
    assert url.startswith("https://replicate.npmjs.com/registry/_changes")
    assert "since=1234" in url
    assert "limit=200" in url


def _conn_with(package, versions):
    import sqlite3
    from npmdiffwatch import store
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    store.init_schema(conn)
    conn.executemany("INSERT INTO releases(package, version) VALUES (?, ?)", [(package, v) for v in versions])
    return conn


_HISTORY = _packument(
    ["1.0.0", "2.0.0", "3.0.0"],
    times={"1.0.0": "2020-01-01T00:00:00.000Z",
           "2.0.0": "2022-01-01T00:00:00.000Z",
           "3.0.0": "2026-09-23T18:00:00.000Z"},
    latest="3.0.0",
)


def test_reseen_row_resolves_to_known_newest_not_older_history(monkeypatch):
    """A retry / re-read of the same feed row (or a metadata-only change such as a
    deprecation) must resolve to the version already recorded, so run_once can skip
    it (terminal) or retry it (review_failed) — never walk back to 2.0.0 from 2022."""
    cfg = Config()
    changes = {"results": [{"seq": 4000, "id": "pkg", "changes": [{"rev": "9-a"}]}], "last_seq": 4000}
    monkeypatch.setattr(ingest, "_fetch_json", _fake_http({"_changes": changes, "/pkg": _HISTORY}))
    page = ingest.changes_since(cfg, 3999, conn=_conn_with("pkg", ["3.0.0"]), limit=200)
    assert [r.version for r in page.releases] == ["3.0.0"]


def test_new_version_after_known_is_still_picked(monkeypatch):
    cfg = Config()
    changes = {"results": [{"seq": 4001, "id": "pkg", "changes": [{"rev": "10-b"}]}], "last_seq": 4001}
    monkeypatch.setattr(ingest, "_fetch_json", _fake_http({"_changes": changes, "/pkg": _HISTORY}))
    page = ingest.changes_since(cfg, 4000, conn=_conn_with("pkg", ["2.0.0"]), limit=200)
    assert [r.version for r in page.releases] == ["3.0.0"]


def test_packuments_are_fetched_concurrently(monkeypatch):
    """At ~1s per packument, a serial loop tops out near npm's own feed rate (~58 packages/min at
    peak) and never catches up. Two lookups must be in flight at once: the barrier only releases
    when both threads reach it, and a serial loop would time out on the first."""
    import threading
    cfg = Config()
    barrier = threading.Barrier(2, timeout=5)
    changes = {"results": [{"seq": 5001, "id": "a"}, {"seq": 5002, "id": "b"}], "last_seq": 5002}

    def fake(url, cfg):
        if "_changes" in url:
            return changes
        barrier.wait()
        return _packument(["1.0.0"], times={"1.0.0": "2026-01-01T00:00:00.000Z"})
    monkeypatch.setattr(ingest, "_fetch_json", fake)
    page = ingest.changes_since(cfg, 5000, conn=None, limit=200)
    assert [(r.package, r.serial) for r in page.releases] == [("a", 5001), ("b", 5002)]
