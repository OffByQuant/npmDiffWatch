"""Everyday library code must not look like an attack: RegExp#exec is not a shell, a timer with a callback is
not eval, and a package's entry file is not an install script."""
from npmdiffwatch import differ, engine, facts
from npmdiffwatch.config import Config
from npmdiffwatch.models import ArtifactSet
from npmdiffwatch.rules import load_rules


def _cats(src: bytes, path="lib/util.js"):
    d = differ.build_diff(ArtifactSet("p", "1.0.0", None, "tgz", {path: src}, {}, {}))
    return next(f for f in facts.build_facts(d).files if f.path == path).bound_categories


def test_regexp_exec_is_not_a_shell_command():
    assert "process" not in _cats(b"const m = /v(\\d+)/.exec(s);\n")


def test_child_process_exec_is_still_a_shell_command():
    assert "process" in _cats(b"const { exec } = require('child_process');\nexec(cmd);\n")
    assert "process" in _cats(b"import cp from 'node:child_process';\ncp.exec(cmd);\n")


def test_timer_with_a_callback_is_not_eval():
    for src in (b"setTimeout(() => done(), 10);\n", b"setTimeout(function () { done(); }, 10);\n",
                b"setInterval(tick, 1000);\n", b"setTimeout(this.flush, 0);\n"):
        assert "exec" not in _cats(src), src


def test_timer_with_a_string_is_eval():
    for src in (b"setTimeout('run()', 10);\n", b"setTimeout(atob(p), 10);\n", b"setInterval('a' + b, 5);\n",
                b"setTimeout(`${code}`, 1);\n"):
        assert "exec" in _cats(src), src


def test_entry_files_are_weighted_below_install_scripts():
    for name in ("index.js", "main.js", "cli.js", "lib/index.js"):
        assert 1.0 < facts.classify_location(name) < 3.0
    assert facts.classify_location("postinstall.js") == 3.0


def test_bin_files_are_weighted_like_entry_files_wherever_they_are():
    assert facts.classify_location("bin/cli.mjs") == facts.classify_location("packages/tool/bin/run.js") == 2.0


def test_a_cli_spawning_a_process_is_not_called_an_install_hook():
    src = b"const { spawnSync } = require('child_process');\nspawnSync('git', ['status']);\n"
    d = differ.build_diff(ArtifactSet("p", "1.0.1", "1.0.0", "tgz", {"bin/cli.js": src}, {"bin/cli.js": b""}, {}))
    fired = {r.rule for r in engine.triage(d, Config(), load_rules("rules/community")).fired_rules}
    assert "js-child-process" in fired and "js-install-script" not in fired


def test_a_timer_and_a_buffer_in_index_js_do_not_escalate():
    src = b"const buf = Buffer.from(chunk);\nsetTimeout(() => flush(buf), 10);\n"
    d = differ.build_diff(ArtifactSet("p", "1.0.1", "1.0.0", "tgz", {"index.js": src}, {"index.js": b""}, {}))
    tr = engine.triage(d, Config(), load_rules("rules/community"))
    assert not tr.escalate, tr.fired_rules
