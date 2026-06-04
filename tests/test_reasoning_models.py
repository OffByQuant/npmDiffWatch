"""Reasoning/thinking-model support (DeepSeek and the like).

Reasoning models spend output-token budget on internal thinking, so the JSON
verdict is often truncated. Rather than hard-fail (which floods the queue with
heuristic fallbacks), validate_verdict fills non-critical fields from their
schema defaults and keeps only `classification` mandatory — that field gates
alerting and is emitted first, so it survives truncation. Corrections must reach
the caller, so complete() returns the re-serialized validated dict.
"""
import json

import pytest

from npmdiffwatch.backends import validate_verdict, OpenAICompatibleBackend, ReviewUnavailable
from npmdiffwatch.reviewer import REVIEW_SCHEMA


# --- validate_verdict: soft defaults, hard classification --------------------

def test_fills_defaults_for_truncated_verdict():
    out = validate_verdict({"classification": "malicious", "confidence": 0.9}, REVIEW_SCHEMA)
    assert out["classification"] == "malicious"      # critical field preserved
    assert out["attack_type"] == "none"              # soft default
    assert out["reasoning"] == ""
    assert out["cited_hunk"] == ""
    assert out["recommended_action"] == "monitor"    # never "dismiss" on a security tool
    assert out["urgent"] is False
    assert out["confidence"] == 0.9


def test_hard_fails_without_classification():
    with pytest.raises(ReviewUnavailable):
        validate_verdict({"confidence": 0.5, "reasoning": "x"}, REVIEW_SCHEMA)


def test_out_of_enum_soft_field_coerces_to_default():
    out = validate_verdict(
        {"classification": "suspicious", "attack_type": "supply-chain-novel"}, REVIEW_SCHEMA)
    assert out["attack_type"] == "none"


def test_out_of_enum_classification_hard_fails():
    # fail-safe: a garbage classification must not pass as benign
    with pytest.raises(ReviewUnavailable):
        validate_verdict({"classification": "totally-bogus"}, REVIEW_SCHEMA)


# --- complete() returns corrected JSON + honors extra_body -------------------

def _backend(content, **kw):
    captured = {}

    def fake_post(url, payload, timeout, headers=None):
        captured["payload"] = payload
        captured["url"] = url
        return {"choices": [{"message": {"content": content}}]}

    b = OpenAICompatibleBackend("http://x/v1", "m", post=fake_post, **kw)
    return b, captured


def test_complete_propagates_defaults_to_caller():
    # model truncated everything after classification+confidence
    b, _ = _backend('{"classification":"malicious","confidence":0.9}')
    out = b.complete(model="m", system="s", user_text="u", schema=REVIEW_SCHEMA, max_tokens=8)
    d = json.loads(out)
    assert d["classification"] == "malicious"
    assert d["recommended_action"] == "monitor"   # default reached the caller, not lost
    assert set(REVIEW_SCHEMA["properties"]) <= set(d)


def test_extra_body_merged_into_payload():
    b, captured = _backend('{"classification":"benign"}',
                           extra_body={"reasoning": {"enabled": False}})
    b.complete(model="m", system="s", user_text="u", schema=REVIEW_SCHEMA, max_tokens=8)
    assert captured["payload"]["reasoning"] == {"enabled": False}


def test_no_extra_body_leaves_payload_clean():
    b, captured = _backend('{"classification":"benign"}')
    b.complete(model="m", system="s", user_text="u", schema=REVIEW_SCHEMA, max_tokens=8)
    assert "reasoning" not in captured["payload"]
