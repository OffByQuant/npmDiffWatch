"""Webhook POST must carry an explicit User-Agent.

Same rationale as the LLM backend: a webhook behind Cloudflare/a WAF blocks the
default "Python-urllib/x.y". The notifier swallows all webhook errors, so a block
here vanishes silently — the alert is printed but never delivered.
"""
from npmdiffwatch import notifier
from npmdiffwatch.models import Verdict
from npmdiffwatch.config import Config


class _FakeResp:
    def __enter__(self): return self
    def __exit__(self, *a): return False


def test_webhook_sets_user_agent(monkeypatch):
    captured = {}
    monkeypatch.setattr(notifier.store, "record_alert", lambda *a, **k: True)

    def fake_urlopen(req, timeout=None):
        captured["req"] = req
        return _FakeResp()

    monkeypatch.setattr(notifier.urllib.request, "urlopen", fake_urlopen)
    cfg = Config(webhook_url="https://hooks.example.com/x")
    v = Verdict("p", "1.0.0", "malicious", 50.0, [], False)
    notifier.emit(cfg, None, v, 1)

    req = captured["req"]
    assert req.get_header("User-agent") == "npmdiffwatch/0.1"
    assert req.get_header("Content-type") == "application/json"
