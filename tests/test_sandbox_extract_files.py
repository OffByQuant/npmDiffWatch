import gzip
import io
import json
import tarfile
import zlib

import pytest

from npmdiffwatch import sandbox
from npmdiffwatch.config import Config


def _tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for n, b in files.items():
            ti = tarfile.TarInfo(f"package/{n}"); ti.size = len(b); t.addfile(ti, io.BytesIO(b))
    return buf.getvalue()


def test_extract_files_returns_text_and_lists_binaries():
    files, bins = sandbox.extract_files(Config(), _tgz({"a.js": b"x()", "img.png": b"\x89PNG\x00\x00"}), "off")
    assert files == {"a.js": b"x()"} and bins[0]["path"] == "img.png"


def test_extract_output_is_validated():
    ok = {"files": {"a.js": "x"}, "binaries": [{"path": "b", "size": 1, "sha256": "0" * 64}]}
    assert sandbox._decode_files(json.dumps(ok).encode(), Config())[0] == {"a.js": b"x"}
    for bad in ({"files": {"a.js": 5}, "binaries": []}, {"files": {}, "binaries": [{"path": 5}]},
                {"files": {"../x": "y"}, "binaries": []}):
        with pytest.raises(sandbox.SandboxError):
            sandbox._decode_files(json.dumps(bad).encode(), Config())


def test_inflate_is_capped():
    bomb = gzip.compress(b"a" * 5_000_000)
    assert len(sandbox.inflate(Config(), bomb, "gzip", 1000, "off")) == 1000
    assert sandbox.inflate(Config(), zlib.compress(b"hello"), "zlib", 1000, "off") == b"hello"


def test_inflate_rejects_garbage():
    with pytest.raises(sandbox.SandboxError):
        sandbox.inflate(Config(), b"not gzip", "gzip", 1000, "off")
