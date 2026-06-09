"""Anthropic backend contract.

The call shape (adaptive thinking + output_config json_schema) is valid on the
installed anthropic SDK; these tests lock that contract and the response/error
handling so a future "fix" can't silently revert to an invalid shape or break
the heuristic-fallback path.
"""
import json

import pytest

# The Anthropic SDK is an optional extra ([claude]); skip this whole module cleanly
# when it isn't installed instead of failing collection for contributors on `[dev]` only.
anthropic = pytest.importorskip("anthropic")
httpx = pytest.importorskip("httpx")

from npmdiffwatch.backends import AnthropicBackend, ReviewUnavailable

SCHEMA = {
    "required": ["classification"],
    "properties": {"classification": {"enum": ["benign", "suspicious", "malicious"]}},
}


class _Block:
    def __init__(self, text, type="text"):
        self.type = type
        self.text = text


class _Resp:
    def __init__(self, blocks):
        self.content = blocks


class _FakeClient:
    def __init__(self, *, response=None, raise_exc=None):
        self.response = response
        self.raise_exc = raise_exc
        self.kwargs = None
        outer = self

        class _Messages:
            def create(self, **kwargs):
                outer.kwargs = kwargs
                if outer.raise_exc:
                    raise outer.raise_exc
                return outer.response

        self.messages = _Messages()


def _complete(client):
    backend = AnthropicBackend("claude-test", client=client)
    return backend.complete(model="claude-test", system="sys", user_text="data",
                            schema=SCHEMA, max_tokens=1024)


def test_passes_verified_call_shape():
    client = _FakeClient(response=_Resp([_Block('{"classification":"benign"}')]))
    _complete(client)
    assert client.kwargs["thinking"] == {"type": "adaptive"}
    fmt = client.kwargs["output_config"]["format"]
    assert fmt["type"] == "json_schema"
    assert fmt["schema"] == SCHEMA


def test_parses_text_block_to_validated_json():
    client = _FakeClient(response=_Resp([_Block('{"classification":"malicious"}')]))
    out = _complete(client)
    assert json.loads(out)["classification"] == "malicious"


def test_ignores_thinking_block_and_reads_text_block():
    client = _FakeClient(response=_Resp([
        _Block("internal reasoning...", type="thinking"),
        _Block('{"classification":"benign"}'),
    ]))
    assert json.loads(_complete(client))["classification"] == "benign"


def test_api_error_maps_to_review_unavailable():
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    client = _FakeClient(raise_exc=anthropic.APIError("down", request=req, body=None))
    with pytest.raises(ReviewUnavailable):
        _complete(client)


def test_non_json_text_maps_to_review_unavailable():
    client = _FakeClient(response=_Resp([_Block("not json at all")]))
    with pytest.raises(ReviewUnavailable):
        _complete(client)


def test_enum_violation_maps_to_review_unavailable():
    client = _FakeClient(response=_Resp([_Block('{"classification":"totally-bogus"}')]))
    with pytest.raises(ReviewUnavailable):
        _complete(client)
