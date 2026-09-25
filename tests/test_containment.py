"""NO-EXECUTION containment guards.

The whole safety claim of npmdiffwatch is that analyzed packages are *data*,
never run, and never written to disk. These AST guards enforce that invariant
mechanically so it cannot rot silently:

  - no dynamic code execution anywhere (eval/exec/compile/__import__)
  - no shelling out (subprocess / os.system / os.popen), except sandbox.py starting
    its own parse worker under sandbox-exec or systemd-run, never through a shell
  - fetcher never uses tarfile.extractall and only opens archives in the
    streaming, non-seeking "r|" mode, and never writes files to disk
  - the rules matcher stays pure data (no eval of rule expressions)
"""
import ast
import pathlib

import pytest

PKG_DIR = pathlib.Path(__file__).resolve().parents[1] / "npmdiffwatch"
SOURCES = sorted(p for p in PKG_DIR.rglob("*.py"))


def _parse(path):
    return ast.parse(path.read_text(), filename=str(path))


def _bare_name_calls(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            yield node.func.id


def _attr_chain(node):
    """Render an Attribute access like os.system / subprocess.run as a string."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def test_no_dynamic_code_execution():
    forbidden = {"eval", "exec", "__import__"}  # `compile` excluded: re.compile is legit
    offenders = []
    for path in SOURCES:
        for name in _bare_name_calls(_parse(path)):
            if name in forbidden:
                offenders.append((path.name, name))
        # bare builtin compile() (not re.compile) is also execution machinery
        tree = _parse(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "compile":
                offenders.append((path.name, "compile"))
    assert offenders == [], f"dynamic execution primitives found: {offenders}"


def test_no_subprocess_or_shell_out():
    offenders = []
    for path in SOURCES:
        tree = _parse(path)
        if path.name == "sandbox.py":       # its one process launch is pinned by the test below
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] in {"subprocess", "pty", "commands"}:
                        offenders.append((path.name, f"import {a.name}"))
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] in {"subprocess", "pty", "commands"}:
                    offenders.append((path.name, f"from {node.module}"))
            elif isinstance(node, ast.Attribute):
                chain = _attr_chain(node)
                if chain in {"os.system", "os.popen", "os.spawnv", "os.spawnl", "os.execv"}:
                    offenders.append((path.name, chain))
    assert offenders == [], f"shell-out machinery found: {offenders}"


def test_sandbox_only_launches_its_worker_without_a_shell():
    tree = _parse(PKG_DIR / "sandbox.py")
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _attr_chain(n.func).startswith("subprocess.")]
    assert [_attr_chain(c.func) for c in calls] == ["subprocess.run"]
    assert all(kw.arg != "shell" for kw in calls[0].keywords)
    launchers = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and n.value in
                 {"sandbox-exec", "systemd-run"}}
    assert launchers == {"sandbox-exec", "systemd-run"}
    for chain in ("os.system", "os.popen", "os.spawnv", "os.spawnl", "os.execv"):
        assert chain not in {_attr_chain(n) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}


def test_fetcher_never_uses_extractall():
    tree = _parse(PKG_DIR / "fetcher.py")
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "extractall" not in attrs


def test_fetcher_only_opens_archives_streaming():
    """Every tarfile.open must use a streaming 'r|' mode (no seeking, no temp
    files). A seekable mode ('r:', 'r:gz') would let tarfile buffer to disk."""
    tree = _parse(PKG_DIR / "fetcher.py")
    found = 0
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "open"
                and _attr_chain(node.func).endswith("tarfile.open")):
            found += 1
            mode = None
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = kw.value.value
            if mode is None and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            assert mode is not None and mode.startswith("r|"), f"non-streaming tarfile mode: {mode!r}"
    assert found >= 1, "expected at least one tarfile.open in fetcher"


def test_fetcher_never_writes_files_to_disk():
    """fetcher extracts package contents into memory only: no builtin open() for
    writing, no Path.write_*/os.makedirs of extracted data."""
    tree = _parse(PKG_DIR / "fetcher.py")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            pytest.fail("fetcher must not call builtin open() (would touch disk)")
        if isinstance(node, ast.Attribute) and node.attr in {"write_bytes", "write_text", "makedirs"}:
            pytest.fail(f"fetcher must not call {node.attr} (would touch disk)")


def test_rules_matcher_has_no_eval_of_rule_expressions():
    """Rules are pure data walked by a matcher; the engine must never turn rule
    strings into code."""
    tree = _parse(PKG_DIR / "rules.py")
    for name in _bare_name_calls(tree):
        assert name not in {"eval", "exec", "compile"}
