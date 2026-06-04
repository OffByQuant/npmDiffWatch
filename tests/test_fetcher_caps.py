"""Extraction caps and path safety in fetcher.extract_tgz.

Archives are attacker-controlled. Extraction is in-memory, streaming, and
bounded; oversize/zip-bomb/too-many-member/traversal inputs must be refused or
skipped, never extracted to disk.
"""
import dataclasses
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


def test_oversize_member_refused():
    blob = _tgz([("package/big.js", b"x" * 100)])
    with pytest.raises(fetcher.RefusedToExtract):
        fetcher.extract_tgz(blob, _cfg(max_member_bytes=10))


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
