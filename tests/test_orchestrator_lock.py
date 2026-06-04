"""Lock-contention reporting.

When another run already holds the flock, run_once must exit cleanly (rc 0) with
a message that (a) names the lock file, (b) names the holder it recorded, and
(c) explains that the OS advisory lock frees on process exit — so the operator
of a hung run knows to kill the pid, not delete the lock file.
"""
import dataclasses
import fcntl
from pathlib import Path

from npmdiffwatch import orchestrator
from npmdiffwatch.config import Config


def _cfg(tmp_path) -> Config:
    return dataclasses.replace(
        Config(),
        db_path=tmp_path / "db.sqlite",
        lock_path=tmp_path / "run.lock",
        cache_dir=tmp_path / "cache",
        reviewer_enabled=False,
        rules_dir=Path("rules/community"),
    )


def test_lock_contention_prints_actionable_message(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    cfg.lock_path.parent.mkdir(parents=True, exist_ok=True)
    holder = open(cfg.lock_path, "a+")                       # simulate a scan already running
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    holder.write("pid=99999 since=2026-06-05T00:00:00+00:00"); holder.flush()
    try:
        rc = orchestrator.run_once(cfg, seed_if_fresh=False)
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN); holder.close()

    out = capsys.readouterr().out
    assert rc == 0
    assert "already running" in out
    assert str(cfg.lock_path) in out                         # tells them WHERE the lock is
    assert "pid=99999" in out                                # and WHO holds it
    assert "does NOT release a live lock" in out             # recovery guidance for a hung run


def test_lock_winner_records_holder_info(tmp_path, monkeypatch):
    # The run that acquires the lock must write its pid into the lock file so a
    # colliding run can report it. We force run_once to do nothing else by seeding
    # a fresh cursor with an unavailable registry (returns early, still under lock).
    from npmdiffwatch import ingest
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(ingest, "current_serial", lambda cfg: None)
    orchestrator.run_once(cfg, seed_if_fresh=True)
    holder_info = cfg.lock_path.read_text()
    assert "pid=" in holder_info
