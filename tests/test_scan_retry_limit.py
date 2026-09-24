"""A release that can't be downloaded or processed is retried on the next scans, but not forever: it holds the
cursor while it waits, so one that always fails would stall the whole scan. After the first try and 3 retries
it is given up on visibly (an UNREVIEWED alert and a `pending` entry) and the cursor moves on. Each download
retry gets a longer deadline, like the LLM review retries."""
import dataclasses
import logging
from pathlib import Path

from npmdiffwatch import differ, fetcher, ingest, orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.ingest import ChangesPage
from npmdiffwatch.models import ArtifactSet, NewRelease

REL = NewRelease("slow-pkg", "2.0.0", 5010)


def _cfg(tmp_path):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "run.lock",
                              cache_dir=tmp_path / "c", reviewer_enabled=False, rules_dir=Path("rules/community"))
    conn = store.connect(cfg); store.init_schema(conn)
    store.set_last_serial(conn, 5000)
    conn.close()
    return cfg


def _scan(cfg, monkeypatch, fetch):
    monkeypatch.setattr(ingest, "changes_since", lambda *a, **k: ChangesPage(releases=[REL], watermark=5010))
    monkeypatch.setattr(fetcher, "fetch_artifacts", fetch)
    orchestrator.run_once(cfg, seed_if_fresh=False)
    conn = store.connect(cfg)
    return store.get_last_serial(conn), store.get_stage(conn, REL.package, REL.version)


def _timeout(cfg, rel, meta=None):
    raise TimeoutError(f"download took longer than {cfg.fetch_deadline_s:.0f}s")


def test_a_download_that_keeps_failing_is_given_up_after_three_retries(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path)
    for _ in range(3):
        assert _scan(cfg, monkeypatch, _timeout) == (5000, "fetch_failed")    # held for retry
    assert _scan(cfg, monkeypatch, _timeout) == (5010, "scan_failed")          # 4th failure: cursor moves on
    out = capsys.readouterr().out
    assert "slow-pkg 2.0.0" in out and "UNREVIEWED" in out and "TimeoutError" in out and "manual review" in out
    [item] = orchestrator.list_pending(cfg)
    assert item["package"] == "slow-pkg" and "could not be scanned" in item["fetch_error"]


def test_each_download_retry_gets_a_longer_deadline(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    seen = []

    def fetch(c, rel, meta=None):
        seen.append((c.fetch_deadline_s, c.packument_deadline_s))
        raise TimeoutError("slow")
    for _ in range(4):
        _scan(cfg, monkeypatch, fetch)
    base, meta = Config().fetch_deadline_s, Config().packument_deadline_s
    assert seen == [(base * n, meta * n) for n in (1, 2, 3, 4)]


def test_a_processing_crash_is_given_up_on_too(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    art = ArtifactSet(REL.package, REL.version, "1.0.0", "tgz", {"index.js": b"x=2\n"}, {"index.js": b"x=1\n"}, {})
    monkeypatch.setattr(differ, "build_diff", lambda a: (_ for _ in ()).throw(ValueError("boom")))
    for _ in range(3):
        assert _scan(cfg, monkeypatch, lambda *a, **k: art)[1] == "fetch_failed"
    assert _scan(cfg, monkeypatch, lambda *a, **k: art) == (5010, "scan_failed")


def test_the_log_says_why_a_download_failed(tmp_path, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        _scan(_cfg(tmp_path), monkeypatch, _timeout)
    assert "slow-pkg==2.0.0" in caplog.text and "TimeoutError: download took longer than 120s" in caplog.text
