"""An LLM that sees no package content must not be able to clear a release.

Triage can fire on signals that carry no reviewable text: an oversized file the
fetcher refused to read (binary-source-too-large), a new .node binary, or a
publisher change (<ownership>). build_review_input then renders nothing between
the markers, and a model asked to judge nothing answers "benign — content is
empty". That is a pass on a package nobody looked at. Such a release must skip
the LLM and go to the human adjudication queue instead.
"""
import json

from npmdiffwatch import reviewer
from npmdiffwatch.config import Config
from npmdiffwatch.models import Diff, FileDiff, FiredRule, Hunk, PkgJsonChange, TriageResult


class _FakeBackend:
    primary_model = "m"
    escalation_model = None

    def __init__(self):
        self.calls = 0

    def complete(self, **kw):
        self.calls += 1
        return json.dumps({"classification": "benign", "confidence": 1.0, "urgent": False,
                           "recommended_action": "dismiss", "attack_type": "none",
                           "cited_hunk": "None", "reasoning": "The provided package content is empty."})


def _review(diff, triage):
    be = _FakeBackend()
    v = reviewer.Reviewer(Config(), backend=be).review(diff, triage)
    return v, be


_OVERSIZED = TriageResult(score=40.0, escalate=True, fired_rules=[
    FiredRule("binary-source-too-large", 20.0, "dist/a.js", (0, 0)),
    FiredRule("binary-source-too-large", 20.0, "dist/b.js", (0, 0))])


def test_metadata_only_signals_skip_llm_and_queue_for_human():
    diff = Diff(package="p", version="1.0.1", is_first_release=False, changed=[], added_binaries=[])
    v, be = _review(diff, _OVERSIZED)
    assert be.calls == 0
    assert v.classification == "suspicious"          # routes to needs_adjudication
    assert v.confidence == 0.0
    assert "binary-source-too-large" in v.reasoning


def test_ownership_only_signal_skips_llm():
    tr = TriageResult(score=50.0, escalate=True, fired_rules=[
        FiredRule("publisher-change", 25.0, "<ownership>", (0, 0)),
        FiredRule("low-footprint-publisher", 25.0, "<ownership>", (0, 0))])
    diff = Diff(package="p", version="1.0.1", is_first_release=False, changed=[], added_binaries=[])
    v, be = _review(diff, tr)
    assert be.calls == 0
    assert v.classification == "suspicious"


def test_top_file_over_input_cap_raises_input_too_large():
    """A minified bundle larger than max_input_chars used to leave the model with no code at all
    (genesys, nexior). It must be parked for a larger-context model, not sent empty or partial."""
    huge = FileDiff("dist/huge.js", "modified", [Hunk((0, 1), (0, 1), ["x" * 300_000], [])])
    tr = TriageResult(score=40.0, escalate=True, fired_rules=[FiredRule("js-eval", 40.0, "dist/huge.js", (1, 1))])
    diff = Diff(package="p", version="1.0.1", is_first_release=False, changed=[huge], added_binaries=[])
    be = _FakeBackend()
    try:
        reviewer.Reviewer(Config(), backend=be).review(diff, tr)
        raise AssertionError("expected InputTooLarge")
    except reviewer.InputTooLarge as e:
        assert e.cap == Config().reviewer.max_input_chars and e.needed > 300_000
        assert "x" * 300_000 in e.text
    assert be.calls == 0


def test_rendered_code_still_goes_to_llm():
    fd = FileDiff("index.js", "modified", [Hunk((0, 1), (0, 1), ["eval(x)"], [])])
    diff = Diff(package="p", version="1.0.1", is_first_release=False, changed=[fd], added_binaries=[])
    v, be = _review(diff, _OVERSIZED)
    assert be.calls == 1
    assert v.classification == "benign"


def test_package_json_change_alone_is_reviewable():
    diff = Diff(package="p", version="1.0.1", is_first_release=False, changed=[], added_binaries=[],
                package_json_changes=[PkgJsonChange("scripts.postinstall", None, "node x.js")])
    v, be = _review(diff, _OVERSIZED)
    assert be.calls == 1
