"""The sandboxed side of npmdiffwatch.sandbox. Reads one request on stdin, writes one JSON reply on stdout.

A scan request is a JSON line followed by the raw tarballs; the reply is the diff and the rules that fired. A
probe request asks the worker to try what the sandbox should stop, and reports what happened."""
import hashlib
import json
import os
import socket
import subprocess
import sys


def _attempt(fn) -> str:
    try:
        fn()
    except OSError:
        return "blocked"
    return "open"


def _probe(head) -> dict:
    def net():
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()

    def write():
        with open(head["write_target"], "w") as f:
            f.write("x")

    def read():
        with open(head["home_file"], "rb") as f:
            f.read(1)
    def read_db():
        with open(head["db_file"], "rb") as f:
            f.read(1)

    def run_program():
        subprocess.run(["/usr/bin/true"], capture_output=True, timeout=5)

    seen = {hashlib.sha256(v.encode()).hexdigest() for v in os.environ.values()}
    return {"network": _attempt(net), "write": _attempt(write),
            "home_read": _attempt(read) if head.get("home_file") else "unknown",
            "db_read": _attempt(read_db), "exec": _attempt(run_program), "services": _services(),
            "env": "leaked" if seen & set(head.get("env_hashes", [])) else "clean"}


def _services() -> str:
    """macOS: can the worker reach LaunchServices, which opens URLs and apps outside the sandbox?"""
    if sys.platform != "darwin":
        return "n/a"
    import ctypes
    import ctypes.util
    libc = ctypes.CDLL(ctypes.util.find_library("System"))
    port = ctypes.c_uint32(0)
    kr = libc.bootstrap_look_up(ctypes.c_uint32.in_dll(libc, "bootstrap_port"),
                                b"com.apple.coreservices.launchservicesd", ctypes.byref(port))
    return "open" if kr == 0 else "blocked"


def main() -> None:
    stdin = sys.stdin.buffer
    head = json.loads(stdin.readline())
    sys.path[:0] = [p for p in head.get("sys_path", []) if p not in sys.path]
    if head.get("probe"):
        out = _probe(head)
    else:
        from . import fetcher, rules, sandbox
        try:
            cfg, dl, mc = sandbox._decode_input(head, stdin)
            out = sandbox._encode_output(*sandbox.compute(cfg, dl, mc, rules.load_rules(cfg.rules_dir)))
        except fetcher.RefusedToExtract as e:
            out = {"error_type": "RefusedToExtract", "error": str(e)}
        except Exception as e:                  # the parent turns this into a retryable scan failure
            out = {"error": f"{type(e).__name__}: {e}"}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
