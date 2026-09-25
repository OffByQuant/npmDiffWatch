"""recommended_action fails toward caution on a confirmed-malicious verdict.

recommended_action is informational (a human adjudicates downstream), so a
truncated/garbage value is coerced to the schema default "monitor" by
validate_verdict rather than discarding the verdict. But "monitor" on confirmed
malware reads wrong in an alert: a malicious classification must surface
"report-to-npm". Non-malicious verdicts keep whatever valid action came back.
"""
import json

from npmdiffwatch import reviewer
from npmdiffwatch.config import Config
from npmdiffwatch.models import Diff, FileDiff, Hunk, TriageResult


def _diff():
    return Diff(package="p", version="1.0.0", is_first_release=False,
                changed=[FileDiff("index.js", "modified", [Hunk((0, 1), (0, 1), ["x()"], [])])],
                added_binaries=[])


def _triage():
    return TriageResult(score=50.0, fired_rules=[], escalate=True)


class _FakeBackend:
    """Returns a pre-validated verdict JSON, as the real backend.complete would."""
    primary_model = "m"
    escalation_model = None

    def __init__(self, payload):
        # A complete, install-time chain, so the chain gate lets a malicious verdict stand.
        self._payload = {"runs_when": "install", "chain_source": "a.js:1", "chain_sink": "a.js:2", **payload}

    def complete(self, **kw):
        return json.dumps(self._payload)


def _review(payload) -> "reviewer.Verdict":
    rvw = reviewer.Reviewer(Config(), backend=_FakeBackend(payload))
    return rvw.review(_diff(), _triage())


def _base(**over):
    d = {"classification": "benign", "confidence": 0.9, "urgent": False,
         "recommended_action": "monitor", "attack_type": "none",
         "cited_hunk": "", "reasoning": "r"}
    d.update(over)
    return d


def test_malicious_with_monitor_clamps_to_report():
    v = _review(_base(classification="malicious", recommended_action="monitor"))
    assert v.classification == "malicious"
    assert v.recommended_action == "report-to-npm"


def test_malicious_with_dismiss_clamps_to_report():
    v = _review(_base(classification="malicious", recommended_action="dismiss"))
    assert v.recommended_action == "report-to-npm"


def test_non_malicious_action_unchanged():
    v = _review(_base(classification="suspicious", recommended_action="monitor"))
    assert v.recommended_action == "monitor"


def test_malicious_already_report_unchanged():
    v = _review(_base(classification="malicious", recommended_action="report-to-npm"))
    assert v.recommended_action == "report-to-npm"
