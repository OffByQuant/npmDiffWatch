import logging
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

CATEGORIES = {"decode", "exec", "process", "network", "credential", "file", "proto", "dynamic_require"}
BINARY_REASONS = {"source-too-large", "foreign-language-source", "new-binary"}
DEP_REASONS = {"typosquat", "nonexistent", "brand-new", "not-screened-cap"}
SCOPES = {"code", "binary", "dep", "package_json", "lockfile", "maintainer"}
_BOOL = {"all", "any", "not"}
MAX_REGEX_LEN = 1000
MAX_SUBSTRINGS, MAX_SUBSTRING_LEN = 100, 200
_PRED_SCOPE = {
    "bound_call": {"code"}, "regex": {"code"},
    "blob_present": {"code"}, "syntax_error": {"code"}, "location_at_least": {"code"},
    "binary_reason": {"binary"}, "dep_reason": {"dep"},
    "pkg_field_changed": {"package_json"}, "pkg_script_added": {"package_json"},
    "install_script_contains": {"package_json"},
    "lock_new_package": {"lockfile"}, "lock_integrity_change": {"lockfile"},
    "maintainer_changed": {"maintainer"}, "publisher_changed": {"maintainer"},
    "low_footprint_publisher": {"maintainer"},
}


@dataclass(frozen=True)
class Rule:
    id: str
    applies_to: str
    weight: float
    match: dict
    attack_type: str = ""
    location_scaled: bool = False
    description: str = ""


def _valid_pred_args(name, args, scope) -> bool:
    if scope not in _PRED_SCOPE.get(name, set()):
        return False
    if name == "bound_call":
        if not isinstance(args, dict) or not args or set(args) - {"category", "name"}:
            return False
        if "category" in args:
            cats = args["category"]
            cats = cats if isinstance(cats, list) else [cats]
            if not cats or not all(c in CATEGORIES for c in cats):
                return False
        if "name" in args and not isinstance(args["name"], str):
            return False
        return True
    if name == "regex":
        if not (isinstance(args, dict) and isinstance(args.get("pattern"), str)):
            return False
        if len(args["pattern"]) > MAX_REGEX_LEN:
            return False
        try:
            re.compile(args["pattern"])
        except re.error:
            return False
        return True
    if name in ("blob_present", "syntax_error", "maintainer_changed",
                "publisher_changed", "low_footprint_publisher"):
        return args is True
    if name == "location_at_least":
        return isinstance(args, (int, float)) and not isinstance(args, bool)
    if name == "binary_reason":
        return isinstance(args, str) and args in BINARY_REASONS
    if name == "dep_reason":
        return isinstance(args, str) and args in DEP_REASONS
    if name in ("pkg_field_changed", "pkg_script_added"):
        return isinstance(args, str)
    if name in ("lock_new_package", "lock_integrity_change"):
        return args is True
    if name == "install_script_contains":      # plain substrings, never regex: linear time, nothing to blow up
        return (isinstance(args, list) and 0 < len(args) <= MAX_SUBSTRINGS
                and all(isinstance(s, str) and 0 < len(s) <= MAX_SUBSTRING_LEN for s in args))
    return False


def _valid_match(node, scope) -> bool:
    if not isinstance(node, dict) or len(node) != 1:
        return False
    (key, val), = node.items()
    if key in _BOOL:
        if key == "not":
            return _valid_match(val, scope)
        return isinstance(val, list) and len(val) >= 1 and all(_valid_match(n, scope) for n in val)
    if key in _PRED_SCOPE:
        return _valid_pred_args(key, val, scope)
    return False


def validate_rule(raw):
    if not isinstance(raw, dict):
        logger.warning("rule rejected (not a mapping): %r", raw)
        return None
    try:
        rid = raw["id"]
        scope = raw["applies_to"]
        weight = float(raw["weight"])
        match = raw["match"]
    except (KeyError, TypeError, ValueError):
        logger.warning("rule rejected (missing/invalid required field): %r", raw)
        return None
    try:
        ok = scope in SCOPES and _valid_match(match, scope)
    except Exception as e:
        logger.warning("rule %r rejected: validation error: %s", raw.get("id"), e)
        return None
    if not ok:
        logger.warning("rule %r rejected: bad scope or match tree", raw.get("id"))
        return None
    return Rule(id=str(rid), applies_to=scope, weight=weight, match=match,
                attack_type=str(raw.get("attack_type", "")),
                location_scaled=bool(raw.get("location_scaled", False)),
                description=str(raw.get("description", "")))


def load_rules(rules_dir) -> list:
    rules, seen = [], set()
    for path in sorted(Path(rules_dir).glob("*.yaml")):
        try:
            docs = yaml.safe_load(path.read_text()) or []
        except yaml.YAMLError as e:
            logger.warning("skipping unparseable rule file %s: %s", path, e)
            continue
        for raw in (docs if isinstance(docs, list) else [docs]):
            r = validate_rule(raw)
            if r is None:
                continue
            if r.id in seen:
                logger.warning("duplicate rule id %r in %s, skipping", r.id, path)
                continue
            seen.add(r.id)
            rules.append(r)
    return rules


def _pred(name, args, ctx) -> bool:
    if name == "bound_call":
        if "category" in args:
            cats = args["category"]
            cats = cats if isinstance(cats, list) else [cats]
            if any(c in ctx.bound_categories for c in cats):
                return True
        if "name" in args and args["name"] in ctx.bound_names:
            return True
        return False
    if name == "regex":
        return any(re.search(args["pattern"], s) for s in ctx.added_strs)
    if name == "blob_present":
        return ctx.blob_present
    if name == "syntax_error":
        return ctx.syntax_error
    if name == "location_at_least":
        return ctx.location_weight >= args
    if name == "binary_reason":
        return ctx.get("reason") == args
    if name == "dep_reason":
        return ctx.get("reason") == args
    if name == "pkg_field_changed":
        return args in ctx.get("changed_fields", set())
    if name == "pkg_script_added":
        return args in ctx.get("changed_scripts", set())
    if name == "install_script_contains":
        text = ctx.get("changed_script_text", "").lower()
        return any(s.lower() in text for s in args)
    if name == "lock_new_package":
        return ctx.get("has_new_packages", False) is True
    if name == "lock_integrity_change":
        return ctx.get("has_integrity_changes", False) is True
    if name == "maintainer_changed":
        return ctx.get("maintainer_changed") is True
    if name == "publisher_changed":
        return ctx.get("publisher_changed") is True
    if name == "low_footprint_publisher":
        return ctx.get("low_footprint_publisher") is True
    return False


def evaluate(node, ctx) -> bool:
    (key, val), = node.items()
    if key == "all":
        return all(evaluate(n, ctx) for n in val)
    if key == "any":
        return any(evaluate(n, ctx) for n in val)
    if key == "not":
        return not evaluate(val, ctx)
    return _pred(key, val, ctx)
