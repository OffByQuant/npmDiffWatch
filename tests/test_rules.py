"""Rule loader: fail-closed validator and the pure-data matcher.

Community rules are untrusted input, so anything malformed, out-of-scope, or
using an unknown predicate must be rejected — never loaded and never eval'd.
"""
from types import SimpleNamespace

from npmdiffwatch import rules


def _valid_code_rule(**over):
    base = {"id": "r1", "applies_to": "code", "weight": 5.0,
            "match": {"bound_call": {"category": "process"}}}
    base.update(over)
    return base


def test_valid_rule_accepted():
    r = rules.validate_rule(_valid_code_rule())
    assert r is not None and r.id == "r1" and r.applies_to == "code"


def test_missing_required_field_rejected():
    raw = _valid_code_rule()
    del raw["weight"]
    assert rules.validate_rule(raw) is None


def test_unknown_scope_rejected():
    assert rules.validate_rule(_valid_code_rule(applies_to="not-a-scope")) is None


def test_predicate_out_of_scope_rejected():
    # binary_reason only valid in `binary` scope, not `code`
    raw = _valid_code_rule(match={"binary_reason": "new-binary"})
    assert rules.validate_rule(raw) is None


def test_unknown_predicate_rejected():
    raw = _valid_code_rule(match={"definitely_not_a_predicate": True})
    assert rules.validate_rule(raw) is None


def test_regex_predicate_rejects_overlong_pattern():
    raw = _valid_code_rule(match={"regex": {"pattern": "a" * (rules.MAX_REGEX_LEN + 1)}})
    assert rules.validate_rule(raw) is None


def test_bad_category_in_bound_call_rejected():
    raw = _valid_code_rule(match={"bound_call": {"category": "not-a-category"}})
    assert rules.validate_rule(raw) is None


def test_publisher_changed_valid_in_maintainer_scope():
    raw = {"id": "pc", "applies_to": "maintainer", "weight": 25,
           "match": {"publisher_changed": True}}
    assert rules.validate_rule(raw) is not None


def test_publisher_changed_rejected_outside_maintainer_scope():
    raw = {"id": "pc", "applies_to": "code", "weight": 25,
           "match": {"publisher_changed": True}}
    assert rules.validate_rule(raw) is None


def test_load_rules_dedupes_ids(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "- {id: dup, applies_to: code, weight: 1, match: {blob_present: true}}\n")
    (tmp_path / "b.yaml").write_text(
        "- {id: dup, applies_to: code, weight: 9, match: {blob_present: true}}\n")
    loaded = rules.load_rules(tmp_path)
    assert [r.id for r in loaded] == ["dup"]  # second dup dropped
    assert loaded[0].weight == 1.0            # first wins


def test_evaluate_boolean_tree():
    ctx = SimpleNamespace(bound_categories={"process"}, bound_names=set())
    node = {"all": [{"bound_call": {"category": "process"}},
                    {"not": {"bound_call": {"category": "network"}}}]}
    assert rules.evaluate(node, ctx) is True


def test_import_present_is_rejected_since_nothing_can_match_it():
    assert rules.validate_rule(_valid_code_rule(match={"import_present": {"module": "child_process"}})) is None
