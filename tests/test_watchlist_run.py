# tests/test_watchlist_run.py
import dataclasses
import os
import time
from pathlib import Path

from npmdiffwatch import fetcher, ingest, orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.ingest import ChangesPage
from npmdiffwatch.watchlist import Watchlist


def _cfg(tmp_path, **over):
    return dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l",
                               cache_dir=tmp_path / "c", reviewer_enabled=False, rules_dir=Path("rules/community"),
                               **over)


def _seeded(cfg, serial=1000):
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, serial); conn.close()


def _no_feed(monkeypatch, seen=None):
    def feed(c, since, conn=None, *, limit=None, watch=None):
        if seen is not None:
            seen.append(watch)
        return ChangesPage([], since)
    monkeypatch.setattr(ingest, "changes_since", feed)


def _registry(monkeypatch, latest):
    """latest: {pkg: version or None(404) or {} (no versions)}"""
    def packument(name, cfg):
        v = latest[name]
        if v is None:
            return None
        return {"dist-tags": {"latest": v}, "versions": {v: {}}} if v else {"versions": {}}
    monkeypatch.setattr(fetcher, "_packument", packument)
    fetched = []
    monkeypatch.setattr(orchestrator, "_fetch_one", lambda cfg, rel: fetched.append((rel.package, rel.version)) or None)
    return fetched


_W = Watchlist("deps.txt", "names", frozenset({"a", "b", "gone", "empty"}), ())


def test_baseline_reviews_each_listed_latest_once_and_never_moves_the_cursor(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); _seeded(cfg)
    _no_feed(monkeypatch)
    fetched = _registry(monkeypatch, {"a": "1.2.0", "b": "3.0.0", "gone": None, "empty": {}})
    orchestrator.run_once(cfg, watch=_W)
    orchestrator.run_once(cfg, watch=_W)
    conn = store.connect(cfg)
    assert sorted(fetched) == [("a", "1.2.0"), ("b", "3.0.0")]
    assert store.baseline_counts(conn, _W.names) == (4, 4) and store.get_last_serial(conn) == 1000
    assert dict(conn.execute("SELECT package, result FROM watchlist_baseline").fetchall()) == \
        {"a": "scanned", "b": "scanned", "gone": "not_found", "empty": "no_versions"}


def test_baseline_is_batched_per_tick(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, watchlist_baseline_per_tick=2); _seeded(cfg)
    _no_feed(monkeypatch)
    _registry(monkeypatch, {"a": "1.0.0", "b": "1.0.0", "gone": "1.0.0", "empty": "1.0.0"})
    orchestrator.run_once(cfg, watch=_W)
    assert store.baseline_counts(store.connect(cfg), _W.names) == (2, 4)


def test_already_recorded_latest_is_marked_without_a_second_review(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); _seeded(cfg)
    conn = store.connect(cfg); store.init_schema(conn)
    store.record_release(conn, "a", "1.2.0", 999, False, None, "tgz", stage="reviewed")
    _no_feed(monkeypatch)
    fetched = _registry(monkeypatch, {"a": "1.2.0", "b": "3.0.0", "gone": None, "empty": {}})
    orchestrator.run_once(cfg, watch=_W)
    assert ("a", "1.2.0") not in fetched and store.baseline_counts(store.connect(cfg), _W.names) == (4, 4)


def test_feed_page_is_filtered_by_the_watchlist(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); _seeded(cfg)
    seen = []
    _no_feed(monkeypatch, seen)
    _registry(monkeypatch, {"a": "1.0.0", "b": "1.0.0", "gone": None, "empty": {}})
    orchestrator.run_once(cfg, watch=_W)
    assert seen == [_W]


def test_watch_keeps_going_while_the_baseline_is_incomplete(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, watchlist_baseline_per_tick=1); _seeded(cfg)
    lst = tmp_path / "deps.txt"; lst.write_text("a\nb\n")
    _no_feed(monkeypatch)
    _registry(monkeypatch, {"a": "1.0.0", "b": "1.0.0"})
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda *a, **k: None)
    slept = []
    orchestrator.watch(cfg, interval=300, iterations=3, sleep_fn=slept.append,
                       watchlist=orchestrator.WatchlistFile(lst))
    assert slept == [300]          # ticks 1-2 do the baseline back to back; tick 2 completes it; then it sleeps


def test_pattern_only_list_has_no_baseline_work(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); _seeded(cfg)
    lst = tmp_path / "deps.txt"; lst.write_text("@team/*\n")
    _no_feed(monkeypatch)
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda *a, **k: None)
    slept = []
    orchestrator.watch(cfg, interval=300, iterations=2, sleep_fn=slept.append,
                       watchlist=orchestrator.WatchlistFile(lst))
    assert slept == [300]


def test_a_broken_reload_keeps_the_last_good_list(tmp_path, capsys):
    lst = tmp_path / "deps.txt"; lst.write_text("a\n")
    wf = orchestrator.WatchlistFile(lst)
    assert wf.current().names == {"a"}
    lst.write_text("")
    os.utime(lst, (time.time() + 5, time.time() + 5))
    assert wf.current().names == {"a"} and "keeping the last good list" in capsys.readouterr().out
    lst.write_text("b\n")
    os.utime(lst, (time.time() + 10, time.time() + 10))
    assert wf.current().names == {"b"}
