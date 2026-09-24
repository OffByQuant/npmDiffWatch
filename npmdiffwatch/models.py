from dataclasses import dataclass, field

@dataclass(frozen=True)
class NewRelease:
    package: str; version: str; serial: int

@dataclass(frozen=True)
class ArtifactSet:
    package: str; version: str; prior_version: str | None
    basis: str
    new_files: dict[str, bytes]
    prior_files: dict[str, bytes]
    artifact_hashes: dict[str, str]
    added_binaries: list[dict] = field(default_factory=list)
    is_new_package: bool = False
    maintainer_metadata: dict | None = None
    added_dep_findings: list[dict] = field(default_factory=list)
    scripts_field: dict | None = None
    has_lockfile: bool = False
    has_shrinkwrap: bool = False

@dataclass(frozen=True)
class Hunk:
    old_range: tuple[int, int]; new_range: tuple[int, int]
    added: list[str]; removed: list[str]

@dataclass(frozen=True)
class FileDiff:
    path: str; change_kind: str; hunks: list[Hunk]
    new_text: str | None = None

@dataclass(frozen=True)
class PkgJsonChange:
    field: str; old: str | None; new: str | None

@dataclass(frozen=True)
class Diff:
    package: str; version: str; is_first_release: bool
    changed: list[FileDiff]; added_binaries: list[dict]
    added_dep_findings: list[dict] = field(default_factory=list)
    package_json_changes: list[PkgJsonChange] = field(default_factory=list)
    description: str = ""          # the new version's package.json description: the author's claim, context only

@dataclass(frozen=True)
class FiredRule:
    rule: str; weight: float; file: str; lines: tuple[int, int]

@dataclass(frozen=True)
class TriageResult:
    score: float; fired_rules: list[FiredRule]; escalate: bool

@dataclass(frozen=True)
class Verdict:
    package: str; version: str; classification: str
    score: float; fired_rules: list[FiredRule]; urgent: bool
    confidence: float | None = None
    attack_type: str | None = None
    reasoning: str | None = None
    cited_hunk: str | None = None
    recommended_action: str | None = None
    model: str | None = None
