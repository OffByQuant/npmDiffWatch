"""package.json is author-controlled. A byte-order mark, broken JSON or a wrongly-typed field must never make
build_diff raise: a release that fails to process is retried every tick and holds the cursor, so one such
package would stall the whole scan."""
import pytest

from npmdiffwatch import differ
from npmdiffwatch.models import ArtifactSet

BOM = b"\xef\xbb\xbf"


def _diff(new_pkg, old_pkg=b'{"name": "p", "version": "1.0.0"}', extra_new=None, extra_old=None):
    new = {"package.json": new_pkg, **(extra_new or {})}
    old = {"package.json": old_pkg, **(extra_old or {})}
    return differ.build_diff(ArtifactSet("p", "1.0.1", "1.0.0", "tgz", new, old, {}))


def test_a_byte_order_mark_is_read_like_any_package_json():
    d = _diff(BOM + b'{"name": "p", "version": "1.0.1", "scripts": {"postinstall": "node x.js"}}',
              old_pkg=BOM + b'{"name": "p", "version": "1.0.0"}')
    assert d._changed_scripts == frozenset({"postinstall"})
    assert "scripts" in {c.field for c in d.package_json_changes}


@pytest.mark.parametrize("bad", [b"{not json", b"[]", b'"a string"', b"null", b"",
                                 b'{"scripts": "rm -rf /"}', b'{"scripts": ["a"]}', b"\xff\xfe\x00"])
def test_a_broken_package_json_never_raises(bad):
    _diff(bad)
    _diff(b'{"name": "p"}', old_pkg=bad)


def test_a_lockfile_with_a_byte_order_mark_is_still_compared():
    lock = BOM + b'{"packages": {"node_modules/a": {"integrity": "sha512-new"}}}'
    old_lock = b'{"packages": {"node_modules/a": {"integrity": "sha512-old"}}}'
    d = _diff(b'{"name": "p"}', old_pkg=b'{"name": "p"}',
              extra_new={"package-lock.json": lock}, extra_old={"package-lock.json": old_lock})
    assert d._lock_meta["has_integrity_changes"] is True
