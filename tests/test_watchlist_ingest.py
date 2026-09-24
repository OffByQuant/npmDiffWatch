# tests/test_watchlist_ingest.py
from npmdiffwatch import ingest
from npmdiffwatch.config import Config
from npmdiffwatch.watchlist import Watchlist

_W = Watchlist("deps.txt", "names", frozenset({"mine"}), ("@team/*",))


def _fake(fetched):
    changes = {"results": [{"seq": 11, "id": "other"}, {"seq": 12, "id": "mine"}, {"seq": 13, "id": "@team/x"},
                           {"seq": 14, "id": "zzz"}], "last_seq": 14}

    def f(url, cfg, **k):
        if "_changes" in url:
            return changes
        fetched.append(url.rsplit("/", 2)[-1] if "@" not in url else "/".join(url.rsplit("/", 2)[-2:]))
        return {"versions": {"1.0.0": {}}, "time": {"1.0.0": "2026-09-24T00:00:00.000Z"}}
    return f


def test_unlisted_rows_are_never_fetched_and_the_watermark_covers_the_page(monkeypatch):
    fetched = []
    monkeypatch.setattr(ingest, "_fetch_json", _fake(fetched))
    page = ingest.changes_since(Config(), 10, conn=None, limit=200, watch=_W)
    assert sorted(r.package for r in page.releases) == ["@team/x", "mine"]
    assert sorted(fetched) == ["@team/x", "mine"] and page.watermark == 14


def test_without_a_watchlist_everything_is_fetched(monkeypatch):
    fetched = []
    monkeypatch.setattr(ingest, "_fetch_json", _fake(fetched))
    page = ingest.changes_since(Config(), 10, conn=None, limit=200)
    assert len(page.releases) == 4 and len(fetched) == 4
