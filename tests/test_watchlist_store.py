# tests/test_watchlist_store.py
import dataclasses

from npmdiffwatch import store
from npmdiffwatch.config import Config


def _conn(tmp_path):
    conn = store.connect(dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite")); store.init_schema(conn)
    return conn


def test_pending_is_listed_names_without_a_result(tmp_path):
    conn = _conn(tmp_path)
    names = {"c", "a", "b"}
    assert store.baseline_pending(conn, names, limit=2) == ["a", "b"]
    store.mark_baseline(conn, "a", "scanned")
    store.mark_baseline(conn, "b", "not_found")
    assert store.baseline_pending(conn, names, limit=10) == ["c"]
    assert store.baseline_counts(conn, names) == (2, 3)


def test_fetch_failed_is_retried_and_counts_as_not_done(tmp_path):
    conn = _conn(tmp_path)
    store.mark_baseline(conn, "a", "fetch_failed")
    assert store.baseline_pending(conn, {"a"}, limit=10) == ["a"]
    assert store.baseline_counts(conn, {"a"}) == (0, 1)
    store.mark_baseline(conn, "a", "scanned")
    assert store.baseline_pending(conn, {"a"}, limit=10) == []


def test_names_removed_from_the_list_do_not_count(tmp_path):
    conn = _conn(tmp_path)
    store.mark_baseline(conn, "gone", "scanned")
    assert store.baseline_counts(conn, {"a"}) == (0, 1)
