import json

from npmdiffwatch import routing
from npmdiffwatch.models import Diff, FileDiff, Hunk, PkgJsonChange

_PUB = {"provenance_now": True, "provenance_before": True, "trusted_publisher_now": "github",
        "trusted_publisher_before": "github", "publisher_changed": False, "maintainers_changed": False}


def _fd(path, text="x", kind="modified"):
    return FileDiff(path, kind, [Hunk((0, 1), (0, 1), [text], ["y"])], text)


def _d(changed=(), classes=None, pkg=(), pub=_PUB, first=False, bins=(), deps=()):
    return Diff("p", "1.0.1", first, list(changed), list(bins), list(deps), list(pkg), "",
                classes or {}, {}, [], dict(pub))


def test_docs_and_version_only_is_cleared_by_fact():
    r = routing.route(_d([_fd("README.md", "# words")], {"README.md": ["inert", "docs"]},
                         [PkgJsonChange("version", '"1.0.0"', '"1.0.1"')]))
    assert r.tier == "fact" and r.why == ()


def test_existing_dependency_bumps_and_dev_dependencies_are_cleared():
    r = routing.route(_d(pkg=[PkgJsonChange("dependencies", json.dumps({"a": "^1"}), json.dumps({"a": "^2"})),
                              PkgJsonChange("devDependencies", None, json.dumps({"b": "1"}))]))
    assert r.tier == "fact"


def test_a_new_dependency_goes_to_the_model():
    r = routing.route(_d(pkg=[PkgJsonChange("dependencies", json.dumps({"a": "^1"}),
                                            json.dumps({"a": "^1", "b": "1"}))]))
    assert r.tier == "model" and r.priority == 1


def test_a_runnable_change_goes_to_the_model():
    r = routing.route(_d([_fd("index.js")], {"index.js": ["load", "main"]}))
    assert r.tier == "model" and r.priority == 2
    r = routing.route(_d([_fd("setup.js")], {"setup.js": ["install", "hook"]}))
    assert r.priority == 3


def test_doc_named_code_is_not_cleared():
    # the parent relabels a mismatched doc as data (Task 1); route re-checks content itself too
    r = routing.route(_d([_fd("README.md", "const h = require('https');\neval(process.env.X);")],
                         {"README.md": ["inert", "docs"]}))
    assert r.tier == "model"


def test_code_under_test_paths_is_not_cleared():
    r = routing.route(_d([_fd("test/a.test.js", "x()")], {"test/a.test.js": ["not-shipped", "test path"]}))
    assert r.tier == "model"


def test_removed_code_is_not_a_runnable_change():
    r = routing.route(_d([_fd("lib/old.js", kind="removed")], {"lib/old.js": ["not-shipped", "removed"]}))
    assert r.tier == "fact"


def test_publishing_changes_and_first_releases_go_to_the_model():
    assert routing.route(_d(pub={**_PUB, "publisher_changed": True})).tier == "model"
    assert routing.route(_d(pub={**_PUB, "provenance_now": False})).tier == "model"
    assert routing.route(_d(pub={**_PUB, "trusted_publisher_now": None})).tier == "model"
    assert routing.route(_d(pub={})).tier == "model"
    assert routing.route(_d(first=True)).tier == "model"


def test_binaries_and_dependency_findings_go_to_the_model():
    assert routing.route(_d(bins=[{"path": "a.node", "sha256": "0", "size": 1}])).tier == "model"
    assert routing.route(_d(deps=[{"name": "x", "reason": "typosquat"}])).tier == "model"


def test_install_script_change_is_highest_priority():
    r = routing.route(_d(pkg=[PkgJsonChange("scripts", None, json.dumps({"postinstall": "node x.js"}))]))
    assert r.tier == "model" and r.priority == 3
