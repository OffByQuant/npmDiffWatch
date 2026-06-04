"""Low-footprint-publisher signal (account-takeover amplifier).

npm exposes no account-creation date, so "new account" is proxied by the new
publisher's footprint: the count of packages they maintain, via the registry
search API (maintainer:<name>). A publisher change *to* a low-footprint account
is the fresh-account-takeover shape; it stacks with publisher-change so that a
change to a throwaway account escalates on its own.
"""
from npmdiffwatch import fetcher, differ, facts, engine
from npmdiffwatch.models import ArtifactSet
from npmdiffwatch.rules import Rule
from npmdiffwatch.config import Config


def _versions(pubs):
    return {v: {"_npmUser": {"name": n}} for v, n in pubs.items()}


# --- _publisher_footprint: parses search total, fails closed -----------------

def test_footprint_reads_search_total():
    seen = {}
    def fake(url, cfg):
        seen["url"] = url
        return {"total": 1061, "objects": []}
    n = fetcher._publisher_footprint("sindresorhus", Config(), fake)
    assert n == 1061
    assert "maintainer:sindresorhus" in seen["url"]


def test_footprint_none_on_bad_payload():
    assert fetcher._publisher_footprint("x", Config(), lambda url, cfg: {}) is None
    assert fetcher._publisher_footprint("x", Config(), lambda url, cfg: None) is None


# --- _low_footprint_publisher: gate on cap, fail closed ----------------------

def test_low_footprint_true_under_cap():
    vd = {"_npmUser": {"name": "mallory"}}
    assert fetcher._low_footprint_publisher(vd, Config(), lambda url, cfg: {"total": 1}) is True


def test_low_footprint_false_over_cap():
    vd = {"_npmUser": {"name": "sindresorhus"}}
    assert fetcher._low_footprint_publisher(vd, Config(), lambda url, cfg: {"total": 1061}) is False


def test_low_footprint_false_when_lookup_fails():
    vd = {"_npmUser": {"name": "mallory"}}
    assert fetcher._low_footprint_publisher(vd, Config(), lambda url, cfg: {}) is False


def test_low_footprint_false_without_publisher_name():
    assert fetcher._low_footprint_publisher({}, Config(), lambda url, cfg: {"total": 0}) is False


# --- facts surfaces it -------------------------------------------------------

def _facts(ctx):
    a = ArtifactSet("p", "1.1.0", "1.0.0", "tgz", {"index.js": b"x=1;\n"}, {}, {})
    return facts.build_facts(differ.build_diff(a), ctx)


def test_facts_surfaces_low_footprint_publisher():
    assert _facts({"current": {"low_footprint_publisher": True}, "prior": None}).low_footprint_publisher is True
    assert _facts({"current": {"low_footprint_publisher": False}, "prior": None}).low_footprint_publisher is False
    assert _facts(None).low_footprint_publisher is False


# --- engine wiring + conjunction escalation ---------------------------------

_PUB_RULE = Rule(id="publisher-change", applies_to="maintainer", weight=25,
                 match={"publisher_changed": True}, attack_type="account-takeover")
_FP_RULE = Rule(id="low-footprint-publisher", applies_to="maintainer", weight=25,
                match={"low_footprint_publisher": True}, attack_type="account-takeover")


def _triage(ctx, ruleset):
    a = ArtifactSet("p", "1.1.0", "1.0.0", "tgz", {"index.js": b"x=1;\n"}, {}, {})
    return engine.triage(differ.build_diff(a), Config(), ruleset, ctx)


def test_engine_fires_low_footprint_rule():
    tr = _triage({"current": {"low_footprint_publisher": True}, "prior": None}, [_FP_RULE])
    assert any(f.rule == "low-footprint-publisher" for f in tr.fired_rules)


def test_fresh_account_takeover_escalates_alone():
    # publisher-change (25) + low-footprint-publisher (25) = 50 >= threshold_t (40)
    tr = _triage({"current": {"publisher_changed": True, "low_footprint_publisher": True},
                  "prior": None}, [_PUB_RULE, _FP_RULE])
    assert tr.escalate is True


def test_established_account_change_does_not_escalate_alone():
    # publisher-change (25) only, established account -> 25 < 40
    tr = _triage({"current": {"publisher_changed": True, "low_footprint_publisher": False},
                  "prior": None}, [_PUB_RULE, _FP_RULE])
    assert tr.escalate is False


def test_shipped_low_footprint_rule_is_loaded():
    from npmdiffwatch import rules
    loaded = {r.id for r in rules.load_rules("rules/community")}
    assert "low-footprint-publisher" in loaded
