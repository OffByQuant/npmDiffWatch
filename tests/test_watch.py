"""The watch daemon loop: scan tick -> refresh dashboard -> sleep, repeated until
interrupted. A failed scan must not kill the daemon; Ctrl-C must stop it cleanly."""
import dataclasses

from npmdiffwatch import orchestrator
from npmdiffwatch.config import Config


def _cfg(tmp_path) -> Config:
    return dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite",
                               lock_path=tmp_path / "run.lock", cache_dir=tmp_path / "cache",
                               reviewer_enabled=False)


def test_watch_runs_n_ticks_and_refreshes_each(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    calls = {"run": 0, "export": 0}
    monkeypatch.setattr(orchestrator, "run_once", lambda c, **k: calls.__setitem__("run", calls["run"] + 1))
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda c, out_path=None, **k: calls.__setitem__("export", calls["export"] + 1))
    n = orchestrator.watch(cfg, interval=0, iterations=3, sleep_fn=lambda s: None)
    assert n == 3
    assert calls == {"run": 3, "export": 3}


def test_watch_survives_a_failed_scan(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    seq = iter([RuntimeError("network blip"), None, None])
    def fake_run(c, **k):
        x = next(seq)
        if isinstance(x, Exception):
            raise x
    exported = {"n": 0}
    monkeypatch.setattr(orchestrator, "run_once", fake_run)
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda c, out_path=None, **k: exported.__setitem__("n", exported["n"] + 1))
    n = orchestrator.watch(cfg, interval=0, iterations=2, sleep_fn=lambda s: None)
    assert n == 2          # the failing tick did not crash the daemon
    assert exported["n"] == 2  # dashboard still refreshed on every tick


def test_watch_stops_on_keyboard_interrupt(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    def boom(c, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(orchestrator, "run_once", boom)
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda *a, **k: None)
    n = orchestrator.watch(cfg, interval=0, iterations=None, sleep_fn=lambda s: None)
    assert n == 0  # interrupted mid-tick, returns cleanly
