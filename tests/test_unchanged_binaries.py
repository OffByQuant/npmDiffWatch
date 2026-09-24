"""Oversized sources, binaries and foreign-language files are signals only when this release adds or changes
them. A package whose CI republishes the same large bundle every half hour must not escalate each release to a
human."""
import dataclasses
import io
import tarfile

from npmdiffwatch import fetcher
from npmdiffwatch.config import Config
from npmdiffwatch.models import NewRelease

_BIG = b"// bundle\n" + b"x" * 1_100_000        # over max_source_file_bytes (1 MB)


def _tgz(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members:
            ti = tarfile.TarInfo(name=f"package/{name}"); ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _fetch(monkeypatch, old, new, prior_fails=False):
    meta = {"versions": {v: {"dist": {"tarball": f"https://registry.npmjs.org/p/-/p-{v}.tgz"}, "_npmUser": {"name": "a"}}
                         for v in ("1.0.0", "1.0.1")},
            "time": {"1.0.0": "2026-09-24T05:20:00.000Z", "1.0.1": "2026-09-24T05:49:00.000Z"},
            "maintainers": [{"name": "a"}]}
    blobs = {"1.0.0": _tgz(old), "1.0.1": _tgz(new)}

    def fetch_url(url, cfg):
        v = url.rsplit("-", 1)[1][:-4]
        if prior_fails and v == "1.0.0":
            raise TimeoutError("download took longer than 120s")
        return blobs[v]
    monkeypatch.setattr(fetcher, "_packument", lambda *a: meta)
    monkeypatch.setattr(fetcher, "_fetch_url", fetch_url)
    art = fetcher.fetch_artifacts(dataclasses.replace(Config()), NewRelease("p", "1.0.1", 2))
    return sorted(b["path"] for b in art.added_binaries)


def test_unchanged_oversized_bundle_is_not_reported(monkeypatch):
    assert _fetch(monkeypatch, [("dist/big.js", _BIG), ("a.md", b"1")], [("dist/big.js", _BIG), ("a.md", b"2")]) == []


def test_changed_oversized_bundle_is_still_reported(monkeypatch):
    assert _fetch(monkeypatch, [("dist/big.js", _BIG)], [("dist/big.js", _BIG + b";evil()")]) == ["dist/big.js"]


def test_new_oversized_bundle_is_still_reported(monkeypatch):
    assert _fetch(monkeypatch, [("a.js", b"1")], [("a.js", b"1"), ("dist/big.js", _BIG)]) == ["dist/big.js"]


def test_unchanged_binary_and_foreign_file_are_not_reported(monkeypatch):
    files = [("bin/addon.node", b"\x7fELF" + b"\0" * 64), ("tool.py", b"print(1)\n")]
    assert _fetch(monkeypatch, files, files) == []


def test_everything_is_reported_when_the_prior_version_cannot_be_read(monkeypatch):
    assert _fetch(monkeypatch, [("dist/big.js", _BIG)], [("dist/big.js", _BIG)], prior_fails=True) == ["dist/big.js"]
