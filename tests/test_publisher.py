"""Per-version publisher-change signal (account-takeover).

Uses the packument's per-version `_npmUser`, so it fires on first sight of a
package without needing our own stored history — unlike maintainer-set-change,
which compares against a prior release we already recorded.
"""
from npmdiffwatch import fetcher, differ, facts, engine
from npmdiffwatch.models import ArtifactSet
from npmdiffwatch.rules import Rule
from npmdiffwatch.config import Config


def _versions(pubs):
    return {v: {"_npmUser": {"name": n}} for v, n in pubs.items()}


# --- fetcher._publisher_changed helper -------------------------------------

def test_publisher_changed_true_when_account_differs():
    versions = _versions({"1.0.0": "alice", "1.1.0": "mallory"})
    assert fetcher._publisher_changed(versions, "1.1.0", "1.0.0") is True


def test_publisher_changed_false_when_same_account():
    versions = _versions({"1.0.0": "alice", "1.1.0": "alice"})
    assert fetcher._publisher_changed(versions, "1.1.0", "1.0.0") is False


def test_publisher_changed_false_without_predecessor():
    versions = _versions({"1.0.0": "alice"})
    assert fetcher._publisher_changed(versions, "1.0.0", None) is False


def test_publisher_changed_false_when_npmuser_absent():
    # prior version lacks _npmUser -> cannot conclude, must not false-positive
    versions = {"1.0.0": {}, "1.1.0": {"_npmUser": {"name": "mallory"}}}
    assert fetcher._publisher_changed(versions, "1.1.0", "1.0.0") is False


# --- facts surfaces it ------------------------------------------------------

def _facts(ctx):
    a = ArtifactSet("p", "1.1.0", "1.0.0", "tgz", {"index.js": b"x=1;\n"}, {}, {})
    return facts.build_facts(differ.build_diff(a), ctx)


def test_facts_surfaces_publisher_changed():
    assert _facts({"current": {"publisher_changed": True}, "prior": None}).publisher_changed is True
    assert _facts({"current": {"publisher_changed": False}, "prior": None}).publisher_changed is False
    assert _facts(None).publisher_changed is False


# --- engine wiring ----------------------------------------------------------

_PUB_RULE = Rule(id="publisher-change", applies_to="maintainer", weight=25,
                 match={"publisher_changed": True}, attack_type="account-takeover")
_SET_RULE = Rule(id="maintainer-set-change", applies_to="maintainer", weight=20,
                 match={"maintainer_changed": True}, attack_type="account-takeover")


def _triage(ctx, ruleset):
    a = ArtifactSet("p", "1.1.0", "1.0.0", "tgz", {"index.js": b"x=1;\n"}, {}, {})
    return engine.triage(differ.build_diff(a), Config(), ruleset, ctx)


def test_engine_fires_publisher_rule():
    tr = _triage({"current": {"publisher_changed": True, "maintainers": ["alice"]}, "prior": None},
                 [_PUB_RULE])
    assert any(f.rule == "publisher-change" for f in tr.fired_rules)


def test_engine_maintainer_set_rule_still_fires_with_dict_ctx():
    tr = _triage({"current": {"maintainers": ["alice", "mallory"]},
                  "prior": {"maintainers": ["alice"]}}, [_SET_RULE])
    assert any(f.rule == "maintainer-set-change" for f in tr.fired_rules)


def test_shipped_publisher_rule_is_loaded():
    from npmdiffwatch import rules
    loaded = {r.id for r in rules.load_rules("rules/community")}
    assert "publisher-change" in loaded
