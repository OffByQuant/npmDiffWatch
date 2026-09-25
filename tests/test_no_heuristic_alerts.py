"""Only the LLM can confirm a finding. A release that crosses the static threshold waits in the review queue,
with no alert, until the LLM has looked at it: when the reviewer is disabled, when the endpoint is down, and
when the input is too large or the model is busy."""
import sys

from npmdiffwatch import __main__ as cli, notifier, orchestrator, reviewer, store

sys.path.insert(0, "tests")
from test_pending_queue import _Backend, _T, _diff, _pending, _setup  # noqa: E402


def _no_alerts(monkeypatch):
    sent = []
    monkeypatch.setattr(notifier, "emit", lambda *a, **k: sent.append(a))
    return sent


def test_reviewer_disabled_queues_without_an_alert(tmp_path, monkeypatch):
    sent = _no_alerts(monkeypatch)
    cfg, conn, rid, _ = _setup(tmp_path, _Backend())
    orchestrator._review_escalated(cfg, conn, None, _diff(), _T, rid)
    assert sent == []
    assert store.get_stage(conn, "pkg", "1.0.0") == "pending_review"
    assert _pending(conn)["pkg"]["pending_reason"] == "reviewer_disabled"


def test_unreachable_endpoint_queues_without_an_alert(tmp_path, monkeypatch):
    sent = _no_alerts(monkeypatch)
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend())
    orchestrator._review_escalated(cfg, conn, rvw, _diff(), _T, rid, offline=True)
    assert sent == [] and _pending(conn)["pkg"]["pending_reason"] == "endpoint_unreachable"


def test_too_large_queues_without_an_alert(tmp_path, monkeypatch):
    sent = _no_alerts(monkeypatch)
    cfg, conn, rid, rvw = _setup(tmp_path, _Backend(), max_input_chars=10_000)
    orchestrator._review_escalated(cfg, conn, rvw, _diff("x" * 50_000), _T, rid)
    assert sent == [] and _pending(conn)["pkg"]["pending_reason"] == "too_large"


def test_a_disabled_reviewer_queue_stores_no_review_input(tmp_path):
    cfg, conn, rid, _ = _setup(tmp_path, _Backend())
    orchestrator._review_escalated(cfg, conn, None, _diff("x" * 50_000), _T, rid)
    assert store.review_input(_pending(conn)["pkg"]) == ""     # a heuristic-only queue must not grow the DB


def test_releases_queued_while_the_reviewer_was_off_are_rescanned_and_reviewed_once_it_is_on(tmp_path, monkeypatch):
    cfg, conn, rid, _ = _setup(tmp_path, _Backend())
    orchestrator._review_escalated(cfg, conn, None, _diff(), _T, rid)
    rescanned = []
    monkeypatch.setattr(orchestrator, "_scan_release",
                        lambda cfg, rel, ruleset, backend, first_release=False: rescanned.append(rel) or (_diff(), _T))
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    assert [(r.package, r.version) for r in rescanned] == [("pkg", "1.0.0")]
    assert len(be.calls) == 1 and "eval(x)" in be.calls[0][0]
    assert store.get_stage(conn, "pkg", "1.0.0") == "reviewed"


def test_a_release_that_can_no_longer_be_downloaded_stays_queued_with_the_reason(tmp_path, monkeypatch):
    cfg, conn, rid, _ = _setup(tmp_path, _Backend())
    orchestrator._review_escalated(cfg, conn, None, _diff(), _T, rid)
    monkeypatch.setattr(orchestrator, "_scan_release", lambda *a, **k: None)
    be = _Backend()
    orchestrator.drain_pending(cfg, conn, reviewer.Reviewer(cfg, backend=be), auto=True)
    row = _pending(conn)["pkg"]
    assert be.calls == [] and row["pending_reason"] == "review_failed" and "download" in row["pending_detail"]


def test_pending_lists_each_queued_release(tmp_path, monkeypatch, capsys):
    cfg, conn, rid, _ = _setup(tmp_path, _Backend())
    store.update_stage(conn, rid, "triaged", 60.0, "[]")
    orchestrator._review_escalated(cfg, conn, None, _diff(), _T, rid)
    monkeypatch.setattr(cli, "load_config", lambda p: cfg)
    monkeypatch.setattr(sys, "argv", ["npmdiffwatch", "-c", "x.toml", "pending"])
    cli.main()
    out = capsys.readouterr().out
    assert "pkg==1.0.0" in out and "reviewer_disabled" in out and "60" in out
