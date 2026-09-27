import dataclasses

from npmdiffwatch import flagged, orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import Download, Verdict


def _cfg(tmp_path):
    inv = dataclasses.replace(Config().investigator, enabled=True)
    return dataclasses.replace(Config(), db_path=tmp_path / "d.sqlite", lock_path=tmp_path / "l", investigator=inv)


def _flag(cfg, conn, version):
    rid = store.record_release(conn, "p", version, 1, False, None, "tgz")
    store.record_verdict(conn, rid, Verdict("p", version, "malicious", 0.0, [], True, reasoning="r"))
    flagged.capture(cfg, conn, rid, download=lambda c, rel: Download("p", version, None, True, b"N", None))
    return rid


class _Inv:
    def __init__(self, outcome="confirmed"): self.outcome, self.seen = outcome, []
    def __call__(self, cfg, backend, ws, original, clock=None):
        self.seen.append(original["version"])
        return {"status": "ok", "verdict": "malicious", "outcome": self.outcome, "confidence": 1.0,
                "answer": {"verdict": "malicious"}, "reason": "r", "indicators": ["1.2.3.4"], "gate_notes": [], "facts": [],
                "steps": 3, "tools": [], "seconds": 1.0, "error": None}


def _run(cfg, monkeypatch, inv, only=None):
    monkeypatch.setattr(orchestrator.investigator, "investigate", inv)
    return orchestrator.run_investigations(cfg, only, backend=object(), workspace=lambda cfg, dl: object())


def test_every_flagged_release_without_an_ok_investigation_is_investigated_newest_first(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); conn = store.connect(cfg); store.init_schema(conn)
    _flag(cfg, conn, "1.0.0"); _flag(cfg, conn, "1.0.1")
    inv = _Inv()
    _run(cfg, monkeypatch, inv)
    assert inv.seen == ["1.0.1", "1.0.0"]
    _run(cfg, monkeypatch, inv)          # already done: nothing new
    assert inv.seen == ["1.0.1", "1.0.0"]


def test_a_named_release_is_investigated_again(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); conn = store.connect(cfg); store.init_schema(conn)
    rid = _flag(cfg, conn, "1.0.0")
    inv = _Inv()
    _run(cfg, monkeypatch, inv); _run(cfg, monkeypatch, inv, ("p", "1.0.0"))
    assert len(store.investigations_for(conn, rid)) == 2


def test_the_verdict_row_is_never_changed(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); conn = store.connect(cfg); store.init_schema(conn)
    rid = _flag(cfg, conn, "1.0.0")
    _run(cfg, monkeypatch, _Inv("disputed"))
    assert conn.execute("SELECT classification FROM verdicts WHERE release_id=?", (rid,)).fetchone()[0] == "malicious"
    assert store.latest_investigation(conn, rid)["outcome"] == "disputed"


def test_missing_blob_is_partial_and_the_run_continues(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); conn = store.connect(cfg); store.init_schema(conn)
    r1 = _flag(cfg, conn, "1.0.0"); _flag(cfg, conn, "1.0.1")
    import os; os.unlink(store.flagged_get(conn, r1)["new_path"])
    out = _run(cfg, monkeypatch, _Inv())
    assert {o["version"]: o["status"] for o in out} == {"1.0.0": "partial", "1.0.1": "ok"}


def test_a_failed_run_is_retried_next_time(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); conn = store.connect(cfg); store.init_schema(conn)
    rid = _flag(cfg, conn, "1.0.0")
    fail = lambda *a, **k: {"status": "failed", "error": "down", "facts": [], "tools": [], "steps": 1,  # noqa: E731
                            "seconds": 0.1, "verdict": None, "outcome": None, "confidence": None, "answer": {"verdict": "malicious"},
                            "reason": "", "indicators": [], "gate_notes": []}
    _run(cfg, monkeypatch, fail)
    inv = _Inv(); _run(cfg, monkeypatch, inv)
    assert inv.seen == ["1.0.0"] and store.failed_investigations(conn, rid) == 1


def test_an_unreadable_stored_package_is_recorded_once_then_dropped(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); conn = store.connect(cfg); store.init_schema(conn)
    rid = _flag(cfg, conn, "1.0.0")
    import os; os.unlink(store.flagged_get(conn, rid)["new_path"])
    _run(cfg, monkeypatch, _Inv()); _run(cfg, monkeypatch, _Inv())
    assert len(store.investigations_for(conn, rid)) == 1 and store.flagged_get(conn, rid) is None


def test_the_daily_prune_also_prunes_flagged_packages(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    seen = []
    monkeypatch.setattr(orchestrator.flagged, "prune", lambda c, conn, now=None: seen.append(1) or 0)
    orchestrator.prune(cfg)
    assert seen == [1]


def test_investigations_are_indexed_by_release(tmp_path):
    cfg = _cfg(tmp_path); conn = store.connect(cfg); store.init_schema(conn)
    names = [r[1] for r in conn.execute("PRAGMA index_list(investigations)")]
    assert "ix_inv_release" in names
