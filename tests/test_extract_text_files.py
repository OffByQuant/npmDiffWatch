"""Extraction keeps any text file, whatever its name: a shell script an install hook runs, a command file with
no extension, a data file shipped code reads. Binary content stays out of `files`."""
import io
import tarfile

from npmdiffwatch import fetcher
from npmdiffwatch.config import Config


def _tgz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in members.items():
            ti = tarfile.TarInfo(f"package/{name}"); ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_text_files_are_kept_whatever_their_extension():
    files, *_ = fetcher.extract_tgz(_tgz({
        "index.js": b"module.exports = 1;\n",
        "scripts/setup.sh": b"echo hi\n",
        "bin/tool": b"#!/usr/bin/env node\nconsole.log(1)\n",
        "config/data.json": b'{"a": 1}\n',
        "notes.txt": b"hello\n",
    }), Config())
    assert set(files) == {"index.js", "scripts/setup.sh", "bin/tool", "config/data.json", "notes.txt"}


def test_binary_content_is_not_kept_as_text():
    files, *_ = fetcher.extract_tgz(_tgz({"img/logo.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"}), Config())
    assert "img/logo.png" not in files


def test_is_text():
    assert fetcher._is_text(b"plain text\n")
    assert not fetcher._is_text(b"a\x00b")
    assert not fetcher._is_text(b"\xff\xfe\xfd")
