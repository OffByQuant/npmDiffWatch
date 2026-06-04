"""Dependency reputation gate: name normalization, typosquat distance, and the
screening state machine (typosquat / nonexistent / brand-new / cap)."""
from datetime import datetime, timedelta, timezone

from npmdiffwatch import deps


def test_normalize_name_collapses_separators_and_case():
    assert deps.normalize_name("Foo_Bar.Baz") == "foo-bar-baz"


def test_edit_distance_basic():
    assert deps.edit_distance("lodash", "lodash") == 0
    assert deps.edit_distance("lodash", "lodahs") == 2


def test_nearest_corpus_flags_close_name_but_not_exact_or_short():
    corpus = {"express", "lodash", "react"}
    assert deps.nearest_corpus("expres", corpus) == "express"   # 1 edit away
    assert deps.nearest_corpus("react", corpus) is None         # exact match
    assert deps.nearest_corpus("abc", corpus) is None           # too short


def test_screen_typosquat_takes_priority_over_lookup():
    findings = deps.screen_added_deps({"expres"}, {"express", "react"},
                                      fetch_json=lambda n: pytest_fail_if_called())
    assert findings == [{"name": "expres", "reason": "typosquat", "target": "express"}]


def pytest_fail_if_called():
    raise AssertionError("fetch_json should not be called for a typosquat")


def test_screen_nonexistent_dep():
    findings = deps.screen_added_deps({"totally-unknown-xyz"}, {"react"},
                                      fetch_json=lambda n: None)
    assert findings == [{"name": "totally-unknown-xyz", "reason": "nonexistent"}]


def test_screen_brand_new_dep():
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    meta = {"time": {"created": recent, "1.0.0": recent}}
    findings = deps.screen_added_deps({"freshly-made-pkg"}, {"react"},
                                      fetch_json=lambda n: meta, brandnew_days=30)
    assert findings == [{"name": "freshly-made-pkg", "reason": "brand-new"}]


def test_screen_old_dep_is_clean():
    old = (datetime.now(timezone.utc) - timedelta(days=900)).isoformat()
    meta = {"time": {"created": old, "1.0.0": old}}
    findings = deps.screen_added_deps({"venerable-pkg-name"}, {"react"},
                                      fetch_json=lambda n: meta, brandnew_days=30)
    assert findings == []


def test_screen_respects_lookup_cap():
    names = {f"unknown-pkg-{i}" for i in range(5)}
    findings = deps.screen_added_deps(names, {"react"}, fetch_json=lambda n: None, cap=2)
    capped = [f for f in findings if f["reason"] == "not-screened-cap"]
    assert len(capped) == 3  # 5 names, only 2 lookups allowed
