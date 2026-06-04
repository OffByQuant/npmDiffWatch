"""OpenAI-compatible backend HTTP behavior.

Paid OpenAI-compatible APIs (DeepSeek, etc.) sit behind Cloudflare, which blocks
the default `Python-urllib/x.y` User-Agent. The request must carry an explicit
UA like every other outbound call in the codebase, or the review silently fails
for anyone not on a local model.
"""
from npmdiffwatch import backends


class _FakeResp:
    def __init__(self, body): self._body = body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self): return self._body


def test_post_json_sets_explicit_user_agent(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["req"] = req
        return _FakeResp(b'{"ok": true}')

    monkeypatch.setattr(backends.urllib.request, "urlopen", fake_urlopen)
    out = backends._urllib_post_json(
        "https://api.deepseek.com/v1/chat/completions",
        {"model": "deepseek-chat"}, 10.0, {"Authorization": "Bearer k"})

    assert out == {"ok": True}
    req = captured["req"]
    # urllib stores header keys capitalize()'d: "User-agent", "Content-type".
    assert req.get_header("User-agent") == "npmdiffwatch/0.1"
    # auth + content-type still flow through untouched
    assert req.get_header("Authorization") == "Bearer k"
    assert req.get_header("Content-type") == "application/json"


def test_post_json_default_ua_is_suppressed(monkeypatch):
    # Proves the explicit UA actually replaces urllib's default rather than
    # sitting alongside it: has_header("User-agent") must already be true so
    # AbstractHTTPHandler never injects "Python-urllib/x.y".
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["req"] = req
        return _FakeResp(b"{}")

    monkeypatch.setattr(backends.urllib.request, "urlopen", fake_urlopen)
    backends._urllib_post_json("https://api.deepseek.com/v1/x", {}, 10.0)
    assert captured["req"].has_header("User-agent")
    assert "Python-urllib" not in captured["req"].get_header("User-agent")
