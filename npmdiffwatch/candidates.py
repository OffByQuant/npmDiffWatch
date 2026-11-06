"""Candidate/validation binding for the new pipeline, without legacy publication.

Mechanical validation deliberately does not infer maliciousness from quotes or
operation names. Semantic results must come from the separately audited reasoning
stage, and reconciliation must still respect human decisions and revision fencing.
"""
from dataclasses import asdict, dataclass

from .assessment import Assessment, REVIEW_MODES, SemanticJudgment
from .evidence import AnalysisInput, EvidenceLedger, EvidenceSpan, fingerprint


@dataclass(frozen=True)
class Citation:
    role: str
    span: EvidenceSpan
    quote: bytes


@dataclass(frozen=True)
class Candidate:
    input_id: str
    policy_sha256: str
    mode: str
    assessment: Assessment
    reasoning: str
    citations: tuple[Citation, ...]
    concerning_observation: str = ""
    unresolved_abuse_question: str = ""

    def __post_init__(self):
        if self.mode not in REVIEW_MODES or not isinstance(self.assessment, Assessment):
            raise ValueError("invalid assessment mode or classification")
        if self.assessment == Assessment.NONE:
            raise ValueError("no-assessment is a workflow outcome, not a model candidate")
        if not isinstance(self.citations, tuple) or any(not isinstance(c, Citation) for c in self.citations):
            raise ValueError("citations must be an immutable tuple of citation records")
        for value in (self.input_id, self.policy_sha256, self.reasoning):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("candidate identity and reasoning must be explicit")
        for c in self.citations:
            if c.role not in ("source", "sink", "explanation", "activation", "baseline"):
                raise ValueError("invalid citation role")
            if not isinstance(c.span, EvidenceSpan) or not isinstance(c.quote, bytes):
                raise ValueError("citations require byte-exact source spans")
        for value in (self.concerning_observation, self.unresolved_abuse_question):
            if not isinstance(value, str):
                raise ValueError("suspicion observation/question must be strings")

    @property
    def id(self) -> str:
        return fingerprint({"schema": 1, "input_id": self.input_id, "policy_sha256": self.policy_sha256,
                            "mode": self.mode, "assessment": self.assessment.value, "reasoning": self.reasoning,
                            "citations": [{"role": c.role, "span_id": c.span.id, "quote_hex": c.quote.hex()}
                                          for c in self.citations],
                            "concerning_observation": self.concerning_observation,
                            "unresolved_abuse_question": self.unresolved_abuse_question})


@dataclass(frozen=True)
class MechanicalValidation:
    candidate_id: str
    input_id: str
    policy_sha256: str
    ok: bool
    reasons: tuple[str, ...]
    gate_version: str = "1"


def validate_mechanical(candidate: Candidate, identity: AnalysisInput, ledger: EvidenceLedger) -> MechanicalValidation:
    reasons = []
    if candidate.input_id != identity.id or ledger.identity.id != identity.id:
        reasons.append("input identity mismatch")
    if candidate.policy_sha256 != identity.policy_sha256:
        reasons.append("judgment policy mismatch")
    for c in candidate.citations:
        check = ledger.validate(c.span, c.quote)
        reasons.extend(check.reasons)
        if (candidate.assessment == Assessment.MALICIOUS and c.role in ("source", "sink")
                and c.span.artifact_sha256 != identity.artifact_sha256):
            reasons.append("malicious chain endpoints must exist in the assessed current artifact")
    roles = {c.role for c in candidate.citations}
    if candidate.assessment == Assessment.MALICIOUS and not {"source", "sink"} <= roles:
        reasons.append("malicious candidate requires source and sink evidence")
    if candidate.assessment == Assessment.SUSPICIOUS:
        if not candidate.citations or not candidate.concerning_observation.strip() or not candidate.unresolved_abuse_question.strip():
            reasons.append("suspicious candidate requires evidence, observation and unresolved abuse question")
    # The matching quotations establish provenance only, never connectivity.
    return MechanicalValidation(candidate.id, identity.id, identity.policy_sha256, not reasons, tuple(reasons),
                                identity.gate_version)


@dataclass(frozen=True)
class ValidationDecision:
    eligible: bool
    reasons: tuple[str, ...]


def publication_eligibility(candidate: Candidate, identity: AnalysisInput, mechanical: MechanicalValidation,
                            semantic: SemanticJudgment) -> ValidationDecision:
    """Check bindings and explicit dispositions, not the truth of model reasoning.

    This is a precondition, not authorization to write an effective revision or
    send an alert. Coordinator reconciliation provides that transaction boundary.
    """
    reasons = []
    binding = (candidate.id, identity.id, identity.policy_sha256)
    for result in (mechanical, semantic):
        if (result.candidate_id, result.input_id, result.policy_sha256) != binding:
            reasons.append("validation is not bound to the exact candidate/input/policy")
    if candidate.input_id != identity.id or candidate.policy_sha256 != identity.policy_sha256:
        reasons.append("candidate input/policy mismatch")
    if mechanical.gate_version != identity.gate_version or not mechanical.ok:
        reasons.append("mechanical validation did not pass the admitted gate version")
    if semantic.disposition != "supported":
        reasons.append("semantic judgment is unresolved or contradicted")
    if candidate.assessment == Assessment.MALICIOUS:
        if semantic.unresolved_links:
            reasons.append("malicious chain has unresolved required links")
        if (identity.scope == "release-change" and not identity.is_first_release
                and semantic.baseline_relation not in ("introduced", "expanded")):
            reasons.append("malicious introduction/expansion is not established for release-change scope")
    return ValidationDecision(not reasons, tuple(reasons))


def candidate_record(candidate: Candidate) -> dict:
    """Lossless bounded-storage representation; no executable package materialization."""
    return {"schema": 1, "candidate_id": candidate.id, "input_id": candidate.input_id,
            "policy_sha256": candidate.policy_sha256, "mode": candidate.mode,
            "assessment": candidate.assessment.value, "reasoning": candidate.reasoning,
            "concerning_observation": candidate.concerning_observation,
            "unresolved_abuse_question": candidate.unresolved_abuse_question,
            "citations": [{"role": c.role, "span": asdict(c.span), "span_id": c.span.id,
                           "quote_hex": c.quote.hex()} for c in candidate.citations]}
