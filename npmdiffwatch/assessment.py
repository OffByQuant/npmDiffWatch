"""Pure canonical state projection for the revision-4 assessment contract.

Not yet a replacement for the legacy store/dashboard adapter. There is no model
intent keyword classifier here: provenance and semantic judgments are separate.
"""
from dataclasses import dataclass
from enum import Enum


class Assessment(str, Enum):
    NONE = "N"
    BENIGN = "B"
    SUSPICIOUS = "S"
    MALICIOUS = "M"


class Coverage(str, Enum):
    NONE = "C0"
    PARTIAL = "C1"
    COMPLETE = "C2"


class Workflow(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    ADJUDICATION = "awaiting_adjudication"
    COMPLETED = "completed"
    RETRYABLE = "retryable_failure"
    TERMINAL = "terminal_failure"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True)
class EffectiveState:
    assessment: Assessment
    coverage: Coverage
    workflow: Workflow
    retained_validated: bool = False
    disputed_candidate: bool = False

    def __post_init__(self):
        if not isinstance(self.assessment, Assessment) or not isinstance(self.coverage, Coverage) or not isinstance(
                self.workflow, Workflow):
            raise ValueError("state requires explicit assessment, coverage and workflow enums")
        if type(self.retained_validated) is not bool or type(self.disputed_candidate) is not bool:
            raise ValueError("state flags must be booleans")
        a, c, w = self.assessment, self.coverage, self.workflow
        if c == Coverage.NONE and a != Assessment.NONE:
            raise ValueError("an assessment requires validated inspection")
        if c == Coverage.COMPLETE and a == Assessment.NONE:
            raise ValueError("complete coverage requires a validated outcome")
        if w == Workflow.COMPLETED and c == Coverage.NONE:
            raise ValueError("uninspected work cannot be completed")
        if w == Workflow.ADJUDICATION:
            if c == Coverage.NONE or a == Assessment.BENIGN:
                raise ValueError("invalid adjudication tuple")
            if a == Assessment.NONE and not self.disputed_candidate:
                raise ValueError("adjudication without assessment requires an explicit disputed candidate")
        if c == Coverage.COMPLETE and w != Workflow.COMPLETED and not self.retained_validated:
            raise ValueError("complete noncompleted work must retain an independently validated result")


@dataclass(frozen=True)
class Projection:
    badge: str
    threat: str | None
    release_cleared: bool


def project(state: EffectiveState) -> Projection:
    """Exactly one badge, plus event eligibility (not a delivery instruction)."""
    if not isinstance(state, EffectiveState):
        raise ValueError("projection requires a validated effective-state tuple")
    if state.assessment == Assessment.MALICIOUS:
        return Projection("Malicious", "malicious", False)
    if state.assessment == Assessment.SUSPICIOUS:
        return Projection("Suspicious — evidence-backed", "suspicious", False)
    badges = {
        Workflow.DEAD_LETTER: "Analysis blocked — dead letter",
        Workflow.TERMINAL: "Review failed",
        Workflow.RETRYABLE: "Review delayed",
        Workflow.ADJUDICATION: "Needs adjudication",
        Workflow.RUNNING: "Reviewing",
        Workflow.QUEUED: "Queued",
    }
    if state.workflow in badges:
        return Projection(badges[state.workflow], None, False)
    if state.coverage == Coverage.PARTIAL:
        return Projection("Incomplete", None, False)
    return Projection("Cleared within scope", None, True)


BASELINE_RELATIONS = frozenset({"introduced", "expanded", "narrowed", "unchanged", "indeterminate"})
REVIEW_MODES = frozenset({"initial_review", "targeted_review", "claim_investigation"})


@dataclass(frozen=True)
class SemanticJudgment:
    """Explicit semantic result, not inferred from quote success or free-text keywords.

    Supplied by a bounded reasoning/adjudication stage. Schema completeness is
    not proof that these statements are true; publication adapters must bind and
    reconcile the exact input/candidate and respect human authority.
    """
    candidate_id: str
    input_id: str
    policy_sha256: str
    disposition: str
    behavior: str
    authorization: str
    activation: str
    template_activation: str
    baseline_relation: str
    legitimate_functionality: str
    unresolved_links: tuple[str, ...] = ()
    vulnerability_observations: tuple[str, ...] = ()

    def __post_init__(self):
        if self.disposition not in ("supported", "unresolved", "contradicted"):
            raise ValueError("invalid semantic disposition")
        if self.baseline_relation not in BASELINE_RELATIONS:
            raise ValueError("invalid baseline relation")
        for value in (self.candidate_id, self.input_id, self.policy_sha256, self.behavior, self.authorization,
                      self.activation, self.template_activation, self.legitimate_functionality):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("semantic fields and identity bindings must be explicit")
        for values in (self.unresolved_links, self.vulnerability_observations):
            if not isinstance(values, tuple) or any(not isinstance(v, str) or not v.strip() for v in values):
                raise ValueError("observations/unknowns must be immutable nonempty strings")
