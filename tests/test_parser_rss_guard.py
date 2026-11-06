"""Platform-independent regressions for the sampled macOS parser budget."""
from dataclasses import replace
import errno
import subprocess
import threading

import pytest

from npmdiffwatch import hostmem, sandbox
from npmdiffwatch.config import Config


@pytest.mark.parametrize("mode", ["within", "over", "unreadable", "timeout", "exited", "missing_live"])
def test_parser_rss_guard_distinguishes_child_exit_from_unenforceable_budget(monkeypatch, mode):
    cfg = replace(Config(), parse_rss_max_bytes=1000)
    sampled = threading.Event()

    class Process:
        pid = 12345
        returncode = None
        killed = False

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9
            sampled.set()

        def wait(self, timeout):
            if mode == "missing_live":
                raise subprocess.TimeoutExpired("worker", timeout)
            self.returncode = 0
            sampled.set()
            return 0

        def communicate(self, input=None, timeout=None):
            if mode == "timeout" and timeout is not None:
                raise subprocess.TimeoutExpired("worker", timeout)
            assert sampled.wait(2)
            self.returncode = self.returncode or 0
            return b"{}", b""

    process = Process()
    monkeypatch.setattr(sandbox.subprocess, "Popen", lambda *args, **kwargs: process)

    def rss(pid):
        if mode == "unreadable":
            raise OSError("RSS unavailable")
        if pid == process.pid:
            if mode in ("exited", "missing_live"):
                raise OSError(errno.ESRCH, "child no longer available")
            sampled.set()
        return 600 if mode == "over" else 100

    monkeypatch.setattr(hostmem, "rss_bytes", rss)
    if mode in ("within", "exited"):
        assert sandbox._run(cfg, "seatbelt", b"{}\n") == b"{}"
        assert not process.killed
    else:
        with pytest.raises(sandbox.SandboxError):
            sandbox._run(cfg, "seatbelt", b"{}\n")
        assert process.killed
