import dataclasses
import hashlib

import pytest

from npmdiffwatch.evidence import AnalysisInput, EvidenceLedger, fingerprint


def identity(**kw):
    fields = dict(registry="https://registry.npmjs.org", package="p", version="2", artifact_sha256="a" * 64,
                  prior_version="1", prior_sha256="b" * 64, scope="release-change",
                  profile_sha256="c" * 64, engine_version="1", rules_version="1", policy_sha256="d" * 64,
                  prompt_sha256="e" * 64, gate_version="1", provider="openai", model="test")
    return AnalysisInput(**(fields | kw))


def test_input_identity_is_canonical_and_revision_bound():
    a = identity()
    assert a.id == identity().id
    assert fingerprint({"a": 1, "b": 2}) == fingerprint({"b": 2, "a": 1})
    for key, value in [("model", "other"), ("scope", "existing-behavior"), ("artifact_sha256", "f" * 64),
                       ("policy_sha256", "f" * 64), ("prior_sha256", "f" * 64)]:
        assert dataclasses.replace(a, **{key: value}).id != a.id
    with pytest.raises(ValueError):
        identity(prior_sha256=None)
    with pytest.raises(ValueError):
        identity(artifact_sha256="not a digest")


def test_only_exact_issued_spans_count_not_matching_text_elsewhere():
    a = identity()
    ledger = EvidenceLedger(a)
    data = b"first();\nsecond();\nthird();\n"
    assert ledger.admit_file(a.artifact_sha256, "x.js", data) == hashlib.sha256(data).hexdigest()
    span, quote = ledger.show(a.artifact_sha256, "x.js", 9, 18, request_id="r1")
    assert quote == b"second();"
    assert ledger.validate(span, quote).ok
    assert not ledger.validate(span, b"first();").ok
    assert not ledger.validate(dataclasses.replace(span, start=0), b"second();").ok
    assert not ledger.validate(dataclasses.replace(span, request_id="not sent"), quote).ok
    assert not EvidenceLedger(a).validate(span, quote).ok
    assert not ledger.validate(span, "second();").ok


def test_original_byte_coordinates_preserve_multibyte_encoding():
    a = identity()
    ledger = EvidenceLedger(a)
    data = "é\ncall();".encode()
    ledger.admit_file(a.artifact_sha256, "utf8.js", data)
    span, quote = ledger.show(a.artifact_sha256, "utf8.js", 3, len(data), request_id="r")
    assert quote == b"call();" and span.start == 3
    assert ledger.validate(span, quote).ok


def test_artifact_and_resource_limits_are_not_renewed_by_pagination():
    a = identity()
    ledger = EvidenceLedger(a, max_bytes=10, max_spans=1)
    ledger.admit_file(a.artifact_sha256, "x", b"0123456789")
    ledger.admit_file(a.artifact_sha256, "x", b"0123456789")  # idempotent, no extra memory
    with pytest.raises(ValueError, match="changed"):
        ledger.admit_file(a.artifact_sha256, "x", b"different")
    with pytest.raises(ValueError, match="byte budget"):
        ledger.admit_file(a.prior_sha256, "x", b"a")
    with pytest.raises(ValueError, match="outside"):
        ledger.admit_file("f" * 64, "x", b"a")
    with pytest.raises(ValueError, match="read byte"):
        ledger.show(a.artifact_sha256, "x", 0, 10, request_id="r", max_read_bytes=5)
    span, quote = ledger.show(a.artifact_sha256, "x", 0, 5, request_id="r")
    assert ledger.validate(span, quote).ok
    with pytest.raises(ValueError, match="span budget"):
        ledger.show(a.artifact_sha256, "x", 5, 10, request_id="r2")


@pytest.mark.parametrize("start,end", [(True, 1), (-1, 1), (1, 0), (0, 50), (0, 0), (0.0, 1)])
def test_invalid_ranges_are_rejected(start, end):
    a = identity()
    ledger = EvidenceLedger(a)
    ledger.admit_file(a.artifact_sha256, "x", b"data")
    with pytest.raises(ValueError):
        ledger.show(a.artifact_sha256, "x", start, end, request_id="r")
