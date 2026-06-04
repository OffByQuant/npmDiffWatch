import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path


@dataclass(frozen=True)
class ReviewerConfig:
    provider: str = "openai"
    base_url: str = "http://localhost:8000/v1"
    model: str = "qwen-singleshot"
    api_key_env: str | None = None
    structured_output: str = "json_schema"
    escalation_model: str | None = None
    timeout: float = 120.0
    max_input_chars: int = 200_000
    max_output_tokens: int = 8192
    opus_escalation_confidence: float = 0.6
    extra_body: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Config:
    db_path: Path = Path(".diffwatch/diffwatch.sqlite")
    cache_dir: Path = Path(".diffwatch/artifact_cache")
    lock_path: Path = Path(".diffwatch/diffwatch.lock")
    max_download_bytes: int = 50_000_000
    max_members: int = 5000
    max_member_bytes: int = 10_000_000
    max_total_bytes: int = 100_000_000
    max_source_file_bytes: int = 1_000_000
    max_name_bytes: int = 4096
    max_foreign_files: int = 25
    dep_brandnew_days: int = 30
    max_dep_lookups: int = 10
    publisher_footprint_max: int = 3
    max_decompressed_bytes: int = 120_000_000
    max_package_json_bytes: int = 100_000
    fetch_timeout_s: float = 30.0
    max_releases_per_run: int = 200
    fetch_concurrency: int = 4
    new_package_policy: str = "surface"
    threshold_t: float = 40.0
    npm_registry: str = "https://registry.npmjs.org"
    npm_replicate: str = "https://replicate.npmjs.com/registry"
    webhook_url: str | None = None
    evidence_max_chars: int = 200_000
    reviewer_enabled: bool = True
    rules_dir: Path = Path("rules/community")
    top_npm_path: Path = None
    reviewer: ReviewerConfig = field(default_factory=ReviewerConfig)


def load_config(path) -> Config:
    path = Path(path)
    if not path.exists():
        return Config()
    raw = tomllib.loads(path.read_text())
    rv = raw.pop("reviewer", {})
    default_rv = ReviewerConfig()
    reviewer = replace(default_rv, **{k: v for k, v in rv.items() if hasattr(default_rv, k)})
    default = Config()
    top = {k: v for k, v in raw.items() if hasattr(default, k) and k != "reviewer"}
    for pk in ("db_path", "cache_dir", "lock_path", "rules_dir", "top_npm_path"):
        if pk in top:
            top[pk] = Path(top[pk])
    return replace(default, reviewer=reviewer, **top)
