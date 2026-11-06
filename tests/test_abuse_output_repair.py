from contextlib import nullcontext
import json

import pytest

from npmdiffwatch import abuse_workflow as flow
from npmdiffwatch.backends import InvalidModelOutput, ReviewUnavailable, validate_verdict
from npmdiffwatch.review_budget import BudgetExceeded, ReviewBudget, ReviewLimits
from tests.test_abuse_workflow import answer, packet


def budget(calls=2):
    return ReviewBudget(ReviewLimits(128000, 128000 * calls, 4096 * calls,
        output_tokens_per_call=4096, max_model_calls=calls))


class Backend:
    primary_model = "openai/test"
    last_usage = None

    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = []

    def complete(self, **kwargs):
        self.calls.append(kwargs)
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        return reply


@pytest.mark.parametrize("failure", [
    InvalidModelOutput("missing required field", raw_response='{}'),
    '{"classification":',
])
def test_completed_invalid_output_gets_one_same_budget_repair(failure):
    p = packet()
    backend = Backend([failure, json.dumps(answer(p))])
    trace, admissions = [], []
    allowance = budget()
    result = flow.adjudicate(backend, p, allowance, lambda: admissions.append(1), nullcontext, trace)
    assert result["status"] == "no_abuse_found"
    assert len(backend.calls) == len(admissions) == allowance.model_calls == len(trace) == 2
    assert trace[0]["raw"] and trace[0]["error"] and trace[0]["validation_error"]
    brief = json.loads(backend.calls[1]["user_text"].splitlines()[2])
    assert "Return one valid JSON object" in brief["validation_error"]
    assert "expected" not in brief


@pytest.mark.parametrize("failure", [ReviewUnavailable("authentication failed"),
    ReviewUnavailable("quota exhausted"), ReviewUnavailable("provider unavailable"),
    ReviewUnavailable("opencode attempted a native tool"), TimeoutError("transport timeout")])
def test_provider_or_transport_failures_are_not_schema_repaired_or_promoted(failure):
    p = packet()
    backend = Backend([failure])
    trace = []
    allowance = budget()
    with pytest.raises(type(failure), match=str(failure)):
        flow.adjudicate(backend, p, allowance, lambda: None, nullcontext, trace)
    assert len(backend.calls) == allowance.model_calls == 1
    assert "validation_error" not in trace[0]


def test_repeated_invalid_output_stops_after_one_repair():
    p = packet()
    backend = Backend([InvalidModelOutput("bad action"), InvalidModelOutput("still bad")])
    with pytest.raises(InvalidModelOutput, match="still bad"):
        flow.adjudicate(backend, p, budget(), lambda: None, nullcontext, [])
    assert len(backend.calls) == 2


def test_repair_does_not_refresh_an_exhausted_dispatch_budget():
    p = packet()
    backend = Backend([InvalidModelOutput("bad action")])
    trace = []
    with pytest.raises(BudgetExceeded):
        flow.adjudicate(backend, p, budget(1), lambda: None, nullcontext, trace)
    assert len(backend.calls) == len(trace) == 1


def test_verdict_contract_errors_are_typed_provider_errors_are_not():
    with pytest.raises(InvalidModelOutput):
        validate_verdict({"action": "changes"}, {"type": "object", "properties": {
            "action": {"enum": ["continue", "finish"]}}, "required": ["action"]})
    assert issubclass(InvalidModelOutput, ReviewUnavailable)
    assert not isinstance(ReviewUnavailable("HTTP 429"), InvalidModelOutput)
