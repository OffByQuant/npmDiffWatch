import json

from npmdiffwatch import reviewer, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import Verdict


def _v(**kw):
    base = {"runs_when": "install", "chain_source": "setup.js:2 reads ~/.npmrc", "chain_sink": "setup.js:3 POST",
            "classification": "malicious", "confidence": 1.0, "attack_type": "credential-exfil",
            "reasoning": "r", "cited_hunk": "h", "recommended_action": "report-to-npm", "urgent": True}
    base.update(kw)
    return base


def test_a_complete_install_time_chain_stays_malicious():
    assert reviewer.apply_chain_gate(_v())["classification"] == "malicious"


def test_missing_sink_is_held_as_suspicious():
    d = reviewer.apply_chain_gate(_v(chain_sink=""))
    assert d["classification"] == "suspicious" and d["recommended_action"] == "monitor" and d["urgent"] is False
    assert d["reasoning"].startswith("Held for a person") and "sink" in d["reasoning"]


def test_command_only_code_is_held_as_suspicious():
    d = reviewer.apply_chain_gate(_v(runs_when="command"))
    assert d["classification"] == "suspicious" and "command" in d["reasoning"]


def test_benign_and_suspicious_pass_through():
    assert reviewer.apply_chain_gate(_v(classification="benign", chain_sink="")) == _v(classification="benign",
                                                                                        chain_sink="")


def test_schema_asks_for_the_chain_before_the_verdict():
    keys = list(reviewer.REVIEW_SCHEMA["properties"])
    assert keys.index("runs_when") < keys.index("classification")
    assert keys.index("chain_sink") < keys.index("classification")


class _Backend:
    primary_model, escalation_model = "m", None
    def __init__(self, reply): self.reply = reply
    def complete(self, **kw): return json.dumps(self.reply)


def test_the_parser_applies_the_gate_and_keeps_the_chain(tmp_path):
    rvw = reviewer.Reviewer(Config(), backend=_Backend(_v(chain_source="")))
    text = "untrusted_content_marker: M\n\nM\n--- file: a.js (added) ---\n+ x\nM"
    v = rvw.review_text("p", "1", 0.0, [], text)
    assert v.classification == "suspicious" and v.runs_when == "install" and v.chain_sink == "setup.js:3 POST"


def test_store_keeps_the_chain(tmp_path):
    import dataclasses
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "d.sqlite", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1", 1, False, None, "tgz")
    store.record_verdict(conn, rid, Verdict("p", "1", "suspicious", 0.0, [], False, runs_when="install",
                                            chain_source="s", chain_sink="k"))
    row = conn.execute("SELECT runs_when, chain_source, chain_sink FROM verdicts").fetchone()
    assert tuple(row) == ("install", "s", "k")
