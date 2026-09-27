"""A file the model cannot read is never dropped silently: every member not kept as text is fingerprinted, so a
release that changes only such a file reaches the model with the lines that read it."""
import dataclasses
import io
import tarfile

from npmdiffwatch import differ, fetcher, reviewer, routing
from npmdiffwatch.config import Config
from npmdiffwatch.models import Download, TriageResult

_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
_PUB = {"provenance_now": False, "provenance_before": False, "trusted_publisher_now": None,
        "trusted_publisher_before": None, "publisher_changed": False, "maintainers_changed": False}


def _tgz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in members.items():
            ti = tarfile.TarInfo(f"package/{name}"); ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _bins(members, cfg=None):
    _, bins, *_ = fetcher.extract_tgz(_tgz(members), cfg or Config())
    return {b["path"]: b for b in bins}


def test_a_small_non_text_member_is_fingerprinted():
    b = _bins({"img/logo.png": _PNG})["img/logo.png"]
    assert b["sha256"] and b["size"] == len(_PNG) and b["reason"] == "unreadable"


def test_a_member_between_the_source_cap_and_the_member_cap_is_fingerprinted():
    cfg = dataclasses.replace(Config(), max_source_file_bytes=100, max_member_bytes=10_000)
    b = _bins({"assets/blob.dat": b"a" * 500}, cfg)["assets/blob.dat"]
    assert b["sha256"] and b["reason"] == "file-too-large"


PJ = b'{"name":"p","version":"%s","main":"index.js"}'
LOADER = b"const d = require('fs').readFileSync(__dirname + '/img/logo.png');\nmodule.exports = d;\n"


def _diff(prior_png, new_png):
    dl = Download("p", "1.0.1", "1.0.0", False,
                  _tgz({"package.json": PJ % b"1.0.1", "index.js": LOADER, "img/logo.png": new_png}),
                  _tgz({"package.json": PJ % b"1.0.0", "index.js": LOADER, "img/logo.png": prior_png}))
    d = differ.build_diff(fetcher.extract_download(Config(), dl))
    object.__setattr__(d, "publishing", dict(_PUB))
    return d


def test_a_release_that_changes_only_an_unreadable_file_goes_to_the_model():
    d = _diff(_PNG, _PNG + b"\x00payload")
    assert routing.route(d).tier == "model"


def test_an_unchanged_unreadable_file_does_not_route():
    assert routing.route(_diff(_PNG, _PNG)).tier == "fact"


def test_the_model_is_told_which_unreadable_file_changed_and_what_reads_it():
    d = _diff(_PNG, _PNG + b"\x00payload")
    text = reviewer.build_review_input(d, TriageResult(0.0, [], False), max_chars=60_000)
    assert "img/logo.png" in text and "cannot be read as text" in text
    assert "index.js:1:" in text        # the loader line
