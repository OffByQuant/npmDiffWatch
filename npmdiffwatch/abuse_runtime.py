"""Host adapter for the frozen abuse contract and optional trusted extensions.

Package bytes are data. Extensions are selected only by the operator's local
configuration, never by package metadata. This module ships no investigator.
"""
from dataclasses import asdict, dataclass
import hashlib
import importlib
import re

from . import abuse_service, abuse_workflow, sandbox
from .assessment import Assessment, SemanticJudgment
from .backends import ReviewUnavailable, make_backend
from .candidates import Candidate, Citation, publication_eligibility, validate_mechanical
from .evidence import AnalysisInput, EvidenceLedger, EvidenceSpan, fingerprint
from .models import Download
from .review_budget import ReviewBudget, ReviewLimits
from .review_policy import POLICY_SHA256


WORKFLOW_VERSION = "abuse-v1"


def identity(cfg, download):
    if download.prior_version is not None and download.prior_blob is None:
        raise ValueError("exact pinned predecessor was not acquired")
    return AnalysisInput(cfg.npm_registry, download.package, download.version,
        hashlib.sha256(download.new_blob).hexdigest(), download.prior_version,
        hashlib.sha256(download.prior_blob).hexdigest() if download.prior_blob is not None else None,
        "release-change" if download.prior_version or download.is_new_package else "existing-behavior",
        fingerprint({"workflow": WORKFLOW_VERSION, "context": cfg.reviewer.context_tokens, "calls": 12,
            "parser": {key: getattr(cfg, key) for key in ("max_members", "max_total_bytes", "max_decompressed_bytes",
                "max_name_bytes", "parse_timeout_s", "parse_memory_max", "parse_rss_max_bytes")}}),
        WORKFLOW_VERSION, "sandbox-byte-evidence-v1", POLICY_SHA256,
        hashlib.sha256(abuse_workflow.SYSTEM.encode()).hexdigest(), "host-owned-block-refs-v1",
        cfg.reviewer.provider, cfg.reviewer.model, bool(download.is_new_package and not download.prior_version))


def limits(cfg):
    return ReviewLimits(cfg.reviewer.context_tokens, cfg.reviewer.context_tokens * 12, 4096 * 12,
        output_tokens_per_call=4096, max_model_calls=12, max_tool_calls=48,
        max_tool_response_bytes=8_000_000, total_tool_response_bytes=384_000_000,
        total_scan_bytes=8_000_000_000, timeout_s=1800)


@dataclass
class Context:
    cfg: object
    identity: AnalysisInput
    download: Download
    kind: str
    sources: dict
    contexts: dict
    binaries: list
    backend: object
    budget: ReviewBudget
    admission: object
    slot: object
    trace: list


def extension_factory(spec):
    if not spec:
        return None
    if not isinstance(spec, str) or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*", spec):
        raise ValueError("reviewer.extension must be an operator-owned module:function")
    module, name = spec.split(":")
    factory = getattr(importlib.import_module(module), name)
    if not callable(factory):
        raise ValueError("review extension factory is not callable")
    return factory


def prepare(cfg, job, slot, cancel_event=None, *, backend=None):
    ident = job["identity"]
    if ident.policy_sha256 != POLICY_SHA256 or ident.prompt_sha256 != hashlib.sha256(abuse_workflow.SYSTEM.encode()).hexdigest():
        raise ValueError("queued job uses another frozen policy/prompt; explicit migration/replay required")
    if (ident.provider, ident.model) != (cfg.reviewer.provider, cfg.reviewer.model):
        raise ValueError("queued job uses another model; no silent provider switch")
    dl = Download(ident.package, ident.version, ident.prior_version, ident.is_first_release,
        job["new_blob"], job["prior_blob"])
    if identity(cfg, dl).id != ident.id:
        raise ValueError("retained queue input/profile changed")
    kind = sandbox.choose(cfg)
    new, bins, current = sandbox.extract_exact_files(cfg, dl.new_blob, kind, full_text=True, with_context=True)
    old, old_bins, prior = sandbox.extract_exact_files(cfg, dl.prior_blob, kind, full_text=True, with_context=True) if dl.prior_blob is not None else ({}, [], {})
    previous = {item["path"]: item["sha256"] for item in old_bins}
    bins = [item for item in bins if previous.get(item["path"]) != item["sha256"]]
    admitted = 0

    def admit():
        nonlocal admitted
        if cancel_event is not None and cancel_event.is_set():
            raise ReviewUnavailable("review cancelled; durable reservation retained")
        if admitted >= 12:
            raise ReviewUnavailable("durable job dispatch allowance exhausted")
        admitted += 1

    model = backend or make_backend(cfg)
    if cancel_event is not None:
        model.cancel_event = cancel_event
    return Context(cfg, ident, dl, kind, {"current": new, "prior": old},
        {"current": current, "prior": prior}, bins, model, ReviewBudget(limits(cfg)), admit, slot, [])


def validate_result(result, context, *, trace=None):
    """Recheck exact host bytes and candidate/semantic/input bindings at publication."""
    if result.get("status") not in ("no_abuse_found", "suspicious", "malicious"):
        return
    ident, record = context.identity, result["candidate"]
    expected = {"no_abuse_found": "B", "suspicious": "S", "malicious": "M"}[result["status"]]
    if record.get("assessment") != expected:
        raise ValueError("result status does not match its validated assessment")
    if result.get("analysis_input") != asdict(ident):
        raise ValueError("review extension returned another analysis input")
    ledger = EvidenceLedger(ident, max_bytes=max(1, sum(len(b) for files in context.sources.values() for b in files.values())), max_spans=128)
    citations = []
    issued_ids = {value for entry in (context.trace if trace is None else trace)
                  for value in entry.get("issued_refs", {}).values()}
    for item in record["citations"]:
        span = EvidenceSpan(**item["span"])
        version = "current" if span.artifact_sha256 == ident.artifact_sha256 else "prior"
        source = context.sources[version][span.path]
        ledger.admit_file(span.artifact_sha256, span.path, source)
        issued, raw = ledger.show(span.artifact_sha256, span.path, span.start, span.end,
            request_id=span.request_id, max_read_bytes=4096)
        if (span != issued or item["span_id"] != span.id or span.id not in issued_ids
                or bytes.fromhex(item["quote_hex"]) != raw):
            raise ValueError("review result citation is not its exact original evidence")
        citations.append(Citation(item["role"], span, raw))
    candidate = Candidate(record["input_id"], record["policy_sha256"], record["mode"], Assessment(record["assessment"]),
        record["reasoning"], tuple(citations), record["concerning_observation"], record["unresolved_abuse_question"])
    if candidate.id != record["candidate_id"]:
        raise ValueError("review result candidate identity changed")
    semantic_record = dict(result["semantic"])
    for name in ("unresolved_links", "vulnerability_observations"):
        semantic_record[name] = tuple(semantic_record[name])
    semantic = SemanticJudgment(**semantic_record)
    eligible = publication_eligibility(candidate, ident, validate_mechanical(candidate, ident, ledger), semantic)
    if not eligible.eligible or result.get("mechanical_validated") is not True:
        raise ValueError("publication validation failed: " + "; ".join(eligible.reasons))
    if not any(c.span.artifact_sha256 == ident.artifact_sha256 for c in citations):
        raise ValueError("review result lacks current-artifact evidence")
    if candidate.assessment == Assessment.MALICIOUS:
        if not any(c.role == "activation" and c.span.artifact_sha256 == ident.artifact_sha256 for c in citations):
            raise ValueError("malicious result lacks current activation evidence")
        if ident.prior_version and not any(c.role == "baseline" and c.span.artifact_sha256 == ident.prior_sha256 for c in citations):
            raise ValueError("malicious result lacks pinned baseline evidence")


def evaluate(context, factory=None):
    try:
        callbacks = factory(context) if factory else {}
        if not isinstance(callbacks, dict) or set(callbacks) - {"targeted", "claim_check"}:
            raise ValueError("invalid host review extension callbacks")

        def targeted():
            result = callbacks["targeted"]()
            validate_result(result, context)
            return result

        def confirm(original):
            start = len(context.trace)
            try:
                result = callbacks["claim_check"](original)
                validate_result(result, context, trace=context.trace[start:])
                return result
            except Exception as error:
                return {"status": "review_failed", "error": f"{type(error).__name__}: {error}"}

        result = abuse_service.review(context.identity, context.sources, context.contexts, context.backend,
            context.budget, context.admission, context.slot,
            targeted=targeted if callbacks.get("targeted") else None,
            claim_check=confirm if callbacks.get("claim_check") else None,
            context_tokens=context.cfg.reviewer.context_tokens, trace=context.trace)
        validate_result(result, context)
        if result["status"] in ("suspicious", "malicious"):
            confirmation = result.get("claim_check", {}).get("result", {})
            if confirmation.get("candidate", {}).get("input_id") != context.identity.id:
                raise ValueError("confirmation is not bound to the selected input")
    except Exception as error:
        result = {"status": "review_failed", "error": f"{type(error).__name__}: {error}", "mechanical_validated": False}
        pause = getattr(error, "status_code", None) or getattr(getattr(error, "__cause__", None), "code", None)
        if pause in (401, 402, 403, 429, 500, 502, 503, 504):
            result["service_failure"] = pause
    result.update(package=context.identity.package, version=context.identity.version, trace=context.trace,
        model_calls=len(context.trace), binary_payload_count=len(context.binaries),
        artifacts=[context.identity.artifact_sha256, context.identity.prior_sha256],
        model=context.identity.model, workflow_version=WORKFLOW_VERSION,
        security_certification=False, automatic_npm_report=False)
    return result
