"""Versioned, byte-addressed evidence contracts for the new assessment pipeline.

These primitives do not read files, unpack archives, or infer runtime reachability.
Callers supply admitted bytes from the parse sandbox. Only issued spans can count
as evidence shown to a model; matching arbitrary text somewhere is insufficient.
"""
from dataclasses import asdict, dataclass
import hashlib
import json


CONTRACT_VERSION = 1
ASSESSMENT_SCOPES = frozenset({"release-change", "existing-behavior"})


def fingerprint(value: dict) -> str:
    """Canonical identities exclude timestamps and incidental transport state."""
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def _digest(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("expected lowercase SHA-256 digest")


@dataclass(frozen=True)
class AnalysisInput:
    registry: str
    package: str
    version: str
    artifact_sha256: str
    prior_version: str | None
    prior_sha256: str | None
    scope: str
    profile_sha256: str
    engine_version: str
    rules_version: str
    policy_sha256: str
    prompt_sha256: str
    gate_version: str
    provider: str
    model: str
    is_first_release: bool = False

    def __post_init__(self):
        if type(self.is_first_release) is not bool or (self.is_first_release and self.prior_version is not None):
            raise ValueError("first-release identity must be explicit and cannot have a predecessor")
        if self.scope not in ASSESSMENT_SCOPES:
            raise ValueError("assessment scope must be release-change or existing-behavior")
        for value in (self.artifact_sha256, self.profile_sha256, self.policy_sha256, self.prompt_sha256):
            _digest(value)
        if (self.prior_version is None) != (self.prior_sha256 is None):
            raise ValueError("predecessor version and digest must both be present or absent")
        if self.prior_sha256 is not None:
            _digest(self.prior_sha256)
        for value in (self.registry, self.package, self.version, self.scope, self.engine_version,
                      self.rules_version, self.gate_version, self.provider, self.model):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("input identity fields must be non-empty strings")

    @property
    def id(self) -> str:
        return fingerprint({"contract": CONTRACT_VERSION, **asdict(self)})


@dataclass(frozen=True)
class EvidenceSpan:
    input_id: str
    artifact_sha256: str
    path: str
    file_sha256: str
    start: int
    end: int
    quote_sha256: str
    request_id: str
    encoding: str = "bytes"

    @property
    def id(self) -> str:
        return fingerprint({"contract": CONTRACT_VERSION, **asdict(self)})


@dataclass(frozen=True)
class EvidenceCheck:
    ok: bool
    reasons: tuple[str, ...]


class EvidenceLedger:
    """Bound host-retained bytes and exact ranges issued in admitted requests.

    A request ID identifies the request receiving a span, not a generated summary.
    Derived/decoded text cannot masquerade as original bytes in this ledger; a
    future decoder adapter must supply a separate transformation contract.
    """

    def __init__(self, identity: AnalysisInput, *, max_bytes=16 * 1024 * 1024, max_spans=256):
        if type(max_bytes) is not int or max_bytes <= 0 or type(max_spans) is not int or max_spans <= 0:
            raise ValueError("evidence budgets must be positive integers")
        self.identity = identity
        self.max_bytes, self.max_spans = max_bytes, max_spans
        self._files: dict[tuple[str, str], bytes] = {}
        self._spans: dict[str, EvidenceSpan] = {}
        self._bytes = 0

    def admit_file(self, artifact_sha256: str, path: str, data: bytes) -> str:
        if artifact_sha256 not in (self.identity.artifact_sha256, self.identity.prior_sha256):
            raise ValueError("artifact is outside the admitted current/prior pair")
        if not isinstance(path, str) or not path or len(path.encode()) > 4096:
            raise ValueError("invalid evidence path identity")
        if not isinstance(data, bytes):
            raise ValueError("evidence requires original bytes")
        key = (artifact_sha256, path)
        if key in self._files:
            if self._files[key] != data:
                raise ValueError("file identity changed within an admitted artifact")
        else:
            if self._bytes + len(data) > self.max_bytes:
                raise ValueError("retained evidence byte budget exceeded")
            self._files[key] = data
            self._bytes += len(data)
        return hashlib.sha256(data).hexdigest()

    def show(self, artifact_sha256: str, path: str, start: int, end: int, *, request_id: str,
             max_read_bytes=4096) -> tuple[EvidenceSpan, bytes]:
        if (artifact_sha256, path) not in self._files:
            raise ValueError("file has not been admitted")
        data = self._files[(artifact_sha256, path)]
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(data):
            raise ValueError("invalid original byte range")
        if type(max_read_bytes) is not int or max_read_bytes <= 0 or end - start > max_read_bytes:
            raise ValueError("read byte budget exceeded")
        if not isinstance(request_id, str) or not request_id.strip() or len(request_id) > 256:
            raise ValueError("invalid request identity")
        quote = data[start:end]
        span = EvidenceSpan(self.identity.id, artifact_sha256, path, hashlib.sha256(data).hexdigest(),
                            start, end, hashlib.sha256(quote).hexdigest(), request_id)
        if span.id not in self._spans and len(self._spans) >= self.max_spans:
            raise ValueError("evidence span budget exceeded")
        self._spans[span.id] = span
        return span, quote

    def validate(self, span: EvidenceSpan, quote: bytes) -> EvidenceCheck:
        reasons = []
        if not isinstance(span, EvidenceSpan) or self._spans.get(span.id) != span:
            return EvidenceCheck(False, ("span was not issued by this input ledger",))
        if not isinstance(quote, bytes):
            return EvidenceCheck(False, ("quote must preserve original bytes",))
        data = self._files[(span.artifact_sha256, span.path)]
        if quote != data[span.start:span.end] or hashlib.sha256(quote).hexdigest() != span.quote_sha256:
            reasons.append("quote does not match the exact issued original byte range")
        return EvidenceCheck(not reasons, tuple(reasons))

    def was_shown(self, span: EvidenceSpan) -> bool:
        """An issued original span, not a free-form model evidence reference."""
        return isinstance(span, EvidenceSpan) and self._spans.get(span.id) == span
