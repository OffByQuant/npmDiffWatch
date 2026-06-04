"""Version-to-version diffing.

Regression guard: build_diff attaches lock/scripts side-channel metadata to the
(frozen) Diff. A naive attribute assignment raises FrozenInstanceError, which
the orchestrator swallows as a generic failure -> every release silently stalls
at the diff stage.
"""
from npmdiffwatch.models import ArtifactSet
from npmdiffwatch import differ


def _artifacts(new_files, prior_files, prior_version="0.9.0"):
    return ArtifactSet("p", "1.0.0", prior_version, "tgz", new_files, prior_files, {})


def test_build_diff_does_not_crash_on_frozen_diff():
    a = _artifacts({"index.js": b"const x=1;\nrequire(mod);\n"},
                   {"index.js": b"const x=1;\n"})
    d = differ.build_diff(a)  # must not raise FrozenInstanceError
    assert d.package == "p"


def test_modified_js_file_produces_filediff_with_added_line():
    a = _artifacts({"index.js": b"const x=1;\nrequire(mod);\n"},
                   {"index.js": b"const x=1;\n"})
    d = differ.build_diff(a)
    fd = next(f for f in d.changed if f.path == "index.js")
    assert fd.change_kind == "modified"
    added = [ln for h in fd.hunks for ln in h.added]
    assert any("require(mod)" in ln for ln in added)


def test_package_json_script_change_is_captured():
    a = _artifacts(
        {"package.json": b'{"name":"p","scripts":{"postinstall":"node evil.js"}}'},
        {"package.json": b'{"name":"p"}'},
    )
    d = differ.build_diff(a)
    fields = {c.field for c in d.package_json_changes}
    assert "scripts" in fields
    assert d._changed_scripts == frozenset({"postinstall"})


def test_lockfile_new_package_detected():
    a = _artifacts(
        {"package-lock.json": b'{"packages":{"node_modules/evil":{"integrity":"sha512-aaa"}}}'},
        {"package-lock.json": b'{"packages":{}}'},
    )
    d = differ.build_diff(a)
    assert d._lock_meta == {"has_new_packages": True, "has_integrity_changes": False}


def test_unchanged_file_not_reported():
    a = _artifacts({"index.js": b"same\n"}, {"index.js": b"same\n"})
    d = differ.build_diff(a)
    assert all(f.path != "index.js" for f in d.changed)
