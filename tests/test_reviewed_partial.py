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


# A suspicion that rests only on what the model could not see goes to the same "couldn't see everything" queue;
# a suspicion with a chain, or one on a release the model saw whole, stays suspicious.
class _Suspicious(_Backend):
    def __init__(self, **kw): self.kw = kw
    def complete(self, **kw):
        return json.dumps({"runs_when": "load", "chain_source": "", "chain_sink": "", "classification": "suspicious",
                           "confidence": 0.5, "attack_type": "obfuscated-loader", "reasoning": "cannot read it",
                           "cited_hunk": "", "recommended_action": "monitor", "urgent": False, **self.kw})


_UNREAD = (f"untrusted_content_marker: M\n\nM\n{reviewer._UNREAD_HEADING}\n  dist/index.js (file-too-large, 5000000 bytes)\n"
           "--- file: package.json (modified) ---\n+ \"version\": \"1.0.1\"\nM")


def _run_with(tmp_path, text, backend):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "d.sqlite", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1.0.1", 1, False, None, "tgz")
    orchestrator._attempt_review(cfg, conn, reviewer.Reviewer(cfg, backend=backend), rid, "p", "1.0.1", 0.0, [],
                                 text, None)
    return store.get_stage(conn, "p", "1.0.1")


def test_a_suspicion_only_about_an_unreadable_file_is_a_partial_review(tmp_path):
    assert _run_with(tmp_path, _UNREAD, _Suspicious()) == "reviewed_partial"


def test_a_suspicion_with_a_chain_stays_suspicious(tmp_path):
    assert _run_with(tmp_path, _UNREAD, _Suspicious(chain_source="package.json postinstall")) == "needs_adjudication"


def test_a_suspicion_on_a_release_seen_whole_stays_suspicious(tmp_path):
    text = "untrusted_content_marker: M\n\nM\n--- file: a.js (added) ---\n+ x\nM"
    assert _run_with(tmp_path, text, _Suspicious()) == "needs_adjudication"


def test_a_suspicion_with_a_dependency_lead_stays_suspicious(tmp_path):
    text = _UNREAD[:-2] + f"\n{reviewer._DEPS_HEADING}\n  lodahs: named like lodash\nM"
    assert _run_with(tmp_path, text, _Suspicious()) == "needs_adjudication"


def test_a_suspicion_with_a_changed_script_stays_suspicious(tmp_path):
    text = _UNREAD[:-2] + "\n--- package.json changes ---\n  scripts: None -> {\"postinstall\": \"node x.js\"}\nM"
    assert _run_with(tmp_path, text, _Suspicious()) == "needs_adjudication"
