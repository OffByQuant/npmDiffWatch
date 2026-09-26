import dataclasses
import json

from npmdiffwatch import orchestrator, reviewer, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import Diff, FileDiff, Hunk, PkgJsonChange, TriageResult

_PUB = {"provenance_now": True, "provenance_before": True, "trusted_publisher_now": None,
        "trusted_publisher_before": None, "publisher_changed": False, "maintainers_changed": False}
_TR = TriageResult(0.0, [], False)       # below the threshold: routing, not the score, decides


class _B:
    primary_model, escalation_model, last_usage = "m", None, None
    def __init__(self, short="clear", full="benign"):
        self.short, self.full, self.calls = short, full, []
    def complete(self, **kw):
        if kw["schema"] is reviewer.SHORT_SCHEMA:
            self.calls.append("short")
            if isinstance(self.short, Exception):
                raise self.short
            return json.dumps({"decision": self.short})
        self.calls.append("full")
        return json.dumps({"runs_when": "load", "chain_source": "", "chain_sink": "", "classification": self.full,
                           "confidence": 1.0, "attack_type": "none", "reasoning": "r", "cited_hunk": "",
                           "recommended_action": "dismiss", "urgent": False})


def _setup(tmp_path, backend):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "d.sqlite", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.0.1", 1, False, None, "tgz")
    return cfg, conn, rid, reviewer.Reviewer(cfg, backend=backend)


def _code(lines=("x()",)):
    return Diff("p", "1.0.1", False, [FileDiff("index.js", "modified", [Hunk((0, 1), (0, 1), list(lines), [])],
                                               "\n".join(lines))], [], [], [], "",
                {"index.js": ["load", "main"]}, {}, [], dict(_PUB))


def _docs_only():
    return Diff("p", "1.0.1", False, [FileDiff("README.md", "modified", [Hunk((0, 1), (0, 1), ["# hi"], [])],
                                               "# hi")], [], [], [PkgJsonChange("version", '"1.0.0"', '"1.0.1"')],
                "", {"README.md": ["inert", "docs"]}, {}, [], dict(_PUB))


def test_nothing_runnable_is_cleared_by_fact_without_the_model(tmp_path):
    b = _B()
    cfg, conn, rid, rvw = _setup(tmp_path, b)
    orchestrator._review_routed(cfg, conn, rvw, _docs_only(), _TR, rid)
    assert store.get_stage(conn, "p", "1.0.1") == "cleared_by_fact" and b.calls == []


def test_a_below_threshold_code_change_is_short_checked(tmp_path):
    b = _B(short="clear")
    cfg, conn, rid, rvw = _setup(tmp_path, b)
    orchestrator._review_routed(cfg, conn, rvw, _code(), _TR, rid)
    assert b.calls == ["short"] and store.get_stage(conn, "p", "1.0.1") == "reviewed"
    assert conn.execute("SELECT review_tier FROM verdicts").fetchone()[0] == "short"


def test_review_goes_to_the_full_review(tmp_path):
    b = _B(short="review", full="suspicious")
    cfg, conn, rid, rvw = _setup(tmp_path, b)
    orchestrator._review_routed(cfg, conn, rvw, _code(), _TR, rid)
    assert b.calls == ["short", "full"] and store.get_stage(conn, "p", "1.0.1") == "needs_adjudication"


def test_a_failed_short_check_goes_to_the_full_review(tmp_path):
    b = _B(short=reviewer.ReviewUnavailable("bad reply"))
    cfg, conn, rid, rvw = _setup(tmp_path, b)
    orchestrator._review_routed(cfg, conn, rvw, _code(), _TR, rid)
    assert b.calls == ["short", "full"]


def test_a_large_change_skips_the_short_check(tmp_path):
    b = _B()
    cfg, conn, rid, rvw = _setup(tmp_path, b)
    orchestrator._review_routed(cfg, conn, rvw, _code(["z" * 20_000]), _TR, rid)
    assert b.calls == ["full"]


class _Busy:
    def admit(self):
        return "model busy"


def test_the_backlog_is_parked_without_its_input_and_with_a_priority(tmp_path):
    b = _B()
    cfg, conn, rid, rvw = _setup(tmp_path, b)
    orchestrator._review_routed(cfg, conn, rvw, _code(), _TR, rid, guard=_Busy())
    row = store.pending_reviews(conn, ("not_reviewed_yet",))[0]
    assert b.calls == [] and store.review_input(row) == "" and row["priority"] == 2
