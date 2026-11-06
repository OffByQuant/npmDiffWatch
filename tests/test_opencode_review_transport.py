from dataclasses import replace
import json

import pytest

from npmdiffwatch import backends, reviewer
from npmdiffwatch.config import Config
from npmdiffwatch.opencode_backend import OpencodeBackend


def process(monkeypatch, tmp_path, events, returncode=0):
    import os.path
    sent = {}
    monkeypatch.setattr(os.path, "expanduser", lambda path: str(tmp_path / "agents"))

    class Process:
        def __init__(self, command, **kwargs):
            self.returncode = returncode
            sent.update(command=command, **kwargs)
            name = command[command.index("--agent") + 1]
            sent["agent_path"] = tmp_path / "agents" / (name + ".md")
            sent["agent_content"] = sent["agent_path"].read_text()

        def communicate(self, input=None, timeout=None):
            sent.update(input=input, timeout=timeout)
            return "\n".join(json.dumps(event) for event in events), ""

    monkeypatch.setattr("subprocess.Popen", Process)
    return sent


def test_public_initial_reviewer_can_use_no_tools_opencode_transport(monkeypatch, tmp_path):
    sent = process(monkeypatch, tmp_path, [
        {"type": "text", "part": {"text": "not a verdict", "metadata": {"openai": {"phase": "commentary"}}}},
        {"type": "text", "part": {"text": '{"decision":"review"}', "metadata": {"openai": {"phase": "final_answer"}}}},
    ])
    cfg = replace(Config(), reviewer=replace(Config().reviewer, provider="opencode", model="openai/test"))
    backend = backends.make_backend(cfg)
    assert isinstance(backend, OpencodeBackend)
    result = backend.complete(model=backend.primary_model, system="trusted policy", user_text="untrusted-package-body",
        schema=reviewer.SHORT_SCHEMA, max_tokens=32, timeout=17)
    assert json.loads(result) == {"decision": "review"}
    assert sent["input"] == "untrusted-package-body" and "untrusted-package-body" not in sent["command"]
    assert "untrusted-package-body" not in sent["agent_content"]
    assert 'effect: deny' in sent["agent_content"]
    assert sent["start_new_session"] is True and sent["timeout"] == 17
    assert not sent["agent_path"].exists()


def test_provider_failure_is_not_an_invalid_model_answer(monkeypatch, tmp_path):
    process(monkeypatch, tmp_path, [{"type": "error", "error": {"type": "provider.rate-limit", "status": 429,
        "retryAfterMs": 120000, "message": "rate limited"}}], returncode=1)
    with pytest.raises(backends.ReviewUnavailable) as error:
        OpencodeBackend("openai/test").ping("OK", timeout=1)
    assert not isinstance(error.value, backends.InvalidModelOutput)
    assert error.value.status_code == 429 and error.value.retry_after_s == 120


def test_invalid_completed_answer_is_typed_and_retained(monkeypatch, tmp_path):
    process(monkeypatch, tmp_path, [{"type": "text", "part": {"text": '{"decision":"unknown"}'}}])
    backend = OpencodeBackend("openai/test")
    with pytest.raises(backends.InvalidModelOutput) as error:
        backend.complete(model=backend.primary_model, system="s", user_text="u", schema=reviewer.SHORT_SCHEMA, max_tokens=32)
    assert json.loads(error.value.raw_response) == {"decision": "unknown"}
