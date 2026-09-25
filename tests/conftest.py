import pytest

from npmdiffwatch import sandbox


@pytest.fixture(autouse=True)
def _scan_in_process(request, monkeypatch):
    """Most tests stub the fetcher in this process, which a sandboxed worker would not see. test_sandbox.py
    exercises the real sandbox."""
    monkeypatch.setattr(sandbox, "_backend", "off")
    if request.module.__name__.split(".")[-1] != "test_sandbox":
        monkeypatch.setattr(sandbox, "choose", lambda cfg, **k: "off")
