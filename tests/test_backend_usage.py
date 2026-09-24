# tests/test_backend_usage.py
"""Backends report the token counts the server returned, so the guard can measure endpoint speed."""
import pytest

from npmdiffwatch.backends import OpenAICompatibleBackend, ReviewUnavailable
from npmdiffwatch.reviewer import REVIEW_SCHEMA

_VERDICT = ('{"classification":"benign","confidence":0.9,"urgent":false,"recommended_action":"monitor",'
            '"attack_type":"none","cited_hunk":"","reasoning":"r"}')


def _post_returning(resp, seen=None):
    def post(url, payload, timeout, headers):
        if seen is not None:
            seen.append((url, payload, timeout))
        return resp
    return post


def test_complete_records_usage():
    b = OpenAICompatibleBackend("http://h:1/v1", "m", post=_post_returning(
        {"choices": [{"message": {"content": _VERDICT}}], "usage": {"prompt_tokens": 5000, "completion_tokens": 200}}))
    b.complete(model="m", system="s", user_text="u", schema=REVIEW_SCHEMA, max_tokens=10)
    assert b.last_usage == {"prompt_tokens": 5000, "completion_tokens": 200}


def test_complete_records_llamacpp_prompt_speed():
    b = OpenAICompatibleBackend("http://h:1/v1", "m", post=_post_returning(
        {"choices": [{"message": {"content": _VERDICT}}], "usage": {"prompt_tokens": 5000, "completion_tokens": 9},
         "timings": {"prompt_per_second": 1234.5}}))
    b.complete(model="m", system="s", user_text="u", schema=REVIEW_SCHEMA, max_tokens=10)
    assert b.last_usage["prompt_per_second"] == 1234.5


def test_missing_usage_is_none():
    b = OpenAICompatibleBackend("http://h:1/v1", "m", post=_post_returning({"choices": [{"message": {"content": _VERDICT}}]}))
    b.complete(model="m", system="s", user_text="u", schema=REVIEW_SCHEMA, max_tokens=10)
    assert b.last_usage is None


def test_ping_is_one_token_no_schema_and_returns_usage():
    seen = []
    b = OpenAICompatibleBackend("http://h:1/v1", "m", extra_body={"chat_template_kwargs": {"enable_thinking": False}},
                                post=_post_returning({"choices": [{"message": {"content": "OK"}}],
                                                      "usage": {"prompt_tokens": 7, "completion_tokens": 1}}, seen))
    assert b.ping("Reply with OK.", timeout=60.0) == {"prompt_tokens": 7, "completion_tokens": 1}
    url, payload, timeout = seen[0]
    assert url.endswith("/chat/completions") and timeout == 60.0
    assert payload["max_tokens"] == 1 and "response_format" not in payload
    assert payload["chat_template_kwargs"] == {"enable_thinking": False}


def test_ping_failure_raises_review_unavailable():
    def post(*a):
        raise TimeoutError("timed out")
    with pytest.raises(ReviewUnavailable):
        OpenAICompatibleBackend("http://h:1/v1", "m", post=post).ping("x", timeout=1.0)


def test_context_length_from_models_listing():
    def get(url, timeout, headers):
        assert url == "http://h:1/v1/models"
        return {"data": [{"id": "other", "context_length": 1}, {"id": "m", "context_length": 262144}]}
    assert OpenAICompatibleBackend("http://h:1/v1", "m", get=get).context_length() == 262144


def test_context_length_from_llamacpp_props_then_none():
    def get(url, timeout, headers):
        if url.endswith("/v1/models"):
            return {"data": [{"id": "m"}]}
        assert url == "http://h:1/props"
        return {"default_generation_settings": {"n_ctx": 32768}}
    assert OpenAICompatibleBackend("http://h:1/v1", "m", get=get).context_length() == 32768

    def boom(url, timeout, headers):
        raise OSError("no")
    assert OpenAICompatibleBackend("http://h:1/v1", "m", get=boom).context_length() is None


def test_usage_keeps_how_many_prompt_tokens_the_server_timed():
    b = OpenAICompatibleBackend("http://h:1/v1", "m", post=_post_returning(
        {"choices": [{"message": {"content": _VERDICT}}], "usage": {"prompt_tokens": 5000, "completion_tokens": 9},
         "timings": {"prompt_per_second": 1234.5, "prompt_n": 812}}))
    b.complete(model="m", system="s", user_text="u", schema=REVIEW_SCHEMA, max_tokens=10)
    assert b.last_usage["prompt_n"] == 812
