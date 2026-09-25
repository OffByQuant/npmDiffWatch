"""Decoding something and handing it to a shell in the same file is the plain form of a hidden-command
loader. Either half alone is ordinary code."""
from npmdiffwatch import differ, engine
from npmdiffwatch.config import Config
from npmdiffwatch.models import ArtifactSet
from npmdiffwatch.rules import load_rules


def _fired(src: bytes, path="lib/util.js"):
    d = differ.build_diff(ArtifactSet("p", "1.0.1", "1.0.0", "tgz", {path: src}, {path: b""}, {}))
    return engine.triage(d, Config(), load_rules("rules/community"))


def test_decoded_command_run_through_child_process_escalates():
    tr = _fired(b"require('child_process').execSync(Buffer.from(p, 'base64').toString());\n")
    assert "js-decode-run" in {r.rule for r in tr.fired_rules} and tr.escalate


def test_decoding_alone_or_running_alone_does_not_fire_it():
    for src in (b"const s = Buffer.from(p, 'base64').toString();\n",
                b"const { spawnSync } = require('child_process');\nspawnSync('git', ['status']);\n"):
        assert "js-decode-run" not in {r.rule for r in _fired(src).fired_rules}, src
