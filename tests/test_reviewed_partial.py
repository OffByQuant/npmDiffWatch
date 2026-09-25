import dataclasses
import json

from npmdiffwatch import orchestrator, reviewer, store
from npmdiffwatch.config import Config


class _Backend:
    primary_model, escalation_model, last_usage = "m", None, None
    def complete(self, **kw):
        return json.dumps({"runs_when": "unknown", "chain_source": "", "chain_sink": "", "classification": "benign",
                           "confidence": 1.0, "attack_type": "none", "reasoning": "ok", "cited_hunk": "",
                           "recommended_action": "dismiss", "urgent": False})


def _run(tmp_path, text):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "d.sqlite", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.0.1", 1, False, None, "tgz")
    rvw = reviewer.Reviewer(cfg, backend=_Backend())
    orchestrator._attempt_review(cfg, conn, rvw, rid, "p", "1.0.1", 0.0, [], text, None)
    return conn


def test_benign_on_a_partly_shown_release_stays_in_pending(tmp_path):
    text = ("untrusted_content_marker: M\n\nM\n--- file: a.js (added) ---\n+ x\n"
            f"{reviewer._NOT_SHOWN_HEADING}\n  lib/big.js (other, 5000 chars added)\nM")
    conn = _run(tmp_path, text)
    assert store.get_stage(conn, "p", "1.0.1") == "reviewed_partial"
    assert [r["package"] for r in store.pending_adjudication(conn)] == ["p"]


def test_benign_on_a_fully_shown_release_is_reviewed(tmp_path):
    conn = _run(tmp_path, "untrusted_content_marker: M\n\nM\n--- file: a.js (added) ---\n+ x\nM")
    assert store.get_stage(conn, "p", "1.0.1") == "reviewed"
