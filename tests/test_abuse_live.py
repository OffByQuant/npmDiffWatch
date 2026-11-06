from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import threading

import pytest

from npmdiffwatch import abuse_coordinator as coordinator, abuse_jobs, abuse_runtime as runtime
from npmdiffwatch import abuse_service, abuse_workflow as flow, dashboard, fetcher, ingest, notifier, orchestrator, reviewer, sandbox, store
from npmdiffwatch.backends import ReviewUnavailable
from npmdiffwatch.config import Config
from npmdiffwatch.ingest import ChangesPage
from npmdiffwatch.models import Download, NewRelease


def config(tmp_path, **review):
    cfg = replace(Config(), db_path=tmp_path / "d.sqlite", lock_path=tmp_path / "lock", cache_dir=tmp_path / "cache",
        parse_sandbox="on", retention_days=0)
    return replace(cfg, reviewer=replace(cfg.reviewer, **{"workflow": "abuse", "model": "fixture-model", "concurrency": 4, **review}))


def download(name="fixture"):
    return Download(name, "2", "1", False, (name + "-current").encode(), (name + "-prior").encode())


def sources(dl):
    return {"current": {"package.json": json.dumps({"name": dl.package, "version": "2", "scripts": {"postinstall": "node index.js"}}).encode(),
        "index.js": b"const fs=require('node:fs');fs.rmSync('/unrelated/user/.ssh',{recursive:true});"},
        "prior": {"package.json": json.dumps({"name": dl.package, "version": "1"}).encode(), "index.js": b"module.exports=0;"}}


def extraction(monkeypatch, downloads):
    blobs = {}
    for dl in downloads:
        files = sources(dl)
        blobs[dl.new_blob], blobs[dl.prior_blob] = files["current"], files["prior"]
    monkeypatch.setattr(sandbox, "choose", lambda cfg: "seatbelt")

    def exact(cfg, blob, kind, **kwargs):
        files = blobs[blob]
        return files, [], {"artifact_sha256": hashlib.sha256(blob).hexdigest(), "files": {}}
    monkeypatch.setattr(sandbox, "extract_exact_files", exact)


def wire(brief, classification="benign"):
    blocks = brief["source_blocks"]
    current = next(b["ref"] for b in blocks if b["version"] == "current" and b["path"] == "index.js")
    activation = next(b["ref"] for b in blocks if b["version"] == "current" and b["path"] == "package.json")
    prior = next(b["ref"] for b in blocks if b["version"] == "prior" and b["path"] == "index.js")
    return {"classification": classification, "reasoning": "fixture behavior judgment", "concerning_observation": "fixture effect",
        "unresolved_abuse_question": "what does this specific payload do?" if classification == "suspicious" else "",
        "chain": {"source": current, "sink": current, "activation": activation, "baseline": prior},
        "citations": [{"ref": current, "role": "source"}, {"ref": current, "role": "sink"},
            {"ref": activation, "role": "activation"}, {"ref": prior, "role": "baseline"}],
        "semantic": {"supports_selected_classification": True, "behavior": "fixture behavior", "authorization": "fixture boundary",
            "activation": "install hook", "template_activation": "not a template", "baseline_relation": "introduced",
            "legitimate_functionality": "fixture explanation", "unresolved_links": [], "vulnerability_observations": []},
        "abuse_leads": [] if classification == "benign" else [{"observation": "specific fixture effect", "refs": [current],
            "status": "abusive" if classification == "malicious" else "needs_context", "question": "specific payload question"}],
        "inspection_notes": ["Not a security certification"]}


class Backend:
    primary_model = "fixture-model"
    last_usage = None

    def __init__(self, classification="benign", error=None):
        self.classification, self.error, self.calls = classification, error, []

    def complete(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        if kwargs["schema"] == reviewer.SHORT_SCHEMA:
            return '{"decision":"clear"}'  # routing still cannot publish a clearance
        brief = json.loads(kwargs["user_text"].splitlines()[2])
        return json.dumps(wire(brief, self.classification))


def enqueue(cfg, dl):
    conn = store.connect(cfg); store.init_schema(conn)
    coordinator.accept_fetch(cfg, conn, NewRelease(dl.package, dl.version, 10), dl)
    writer = abuse_jobs.Jobs(conn)
    return conn, writer


def context(cfg, job, dl, backend=None):
    ctx = runtime.Context(cfg, job["identity"], dl, "seatbelt", sources(dl), {}, [], backend or Backend(),
        runtime.ReviewBudget(runtime.limits(cfg)), lambda: None, nullcontext, [])
    return ctx


def validated(ctx, classification="benign"):
    packet, metadata = abuse_service.prepare(ctx.identity, ctx.sources, ctx.contexts)
    ctx.trace.append({"stage": "synthetic-contract-witness", "input_estimate": 100,
        "issued_refs": {ref: item["span"].id for ref, item in packet.entries.items()}})
    return flow.validate(wire(packet.brief(**metadata), classification), packet, set(packet.entries))


def test_intake_commits_pair_and_cursor_without_running_legacy_or_model(monkeypatch, tmp_path):
    cfg, dl = config(tmp_path), download()
    c = store.connect(cfg); store.init_schema(c); store.set_last_serial(c, 1); c.close()
    monkeypatch.setattr(ingest, "changes_since", lambda *a, **k: ChangesPage([NewRelease(dl.package, "2", 10)], 10))
    monkeypatch.setattr(orchestrator, "_fetch_one", lambda *a, **k: dl)
    monkeypatch.setattr(orchestrator, "_load_ruleset", lambda *a: pytest.fail("legacy triage must not own new review"))
    monkeypatch.setattr(reviewer, "apply_chain_gate", lambda *a, **k: pytest.fail("legacy M-to-S gate"))
    monkeypatch.setattr(notifier, "emit", lambda *a, **k: pytest.fail("no unsolicited notification"))
    assert orchestrator.run_once(cfg) == 1
    c = store.connect(cfg)
    assert store.get_last_serial(c) == 10
    row = c.execute("SELECT new_blob,prior_blob,state,reserved_calls FROM abuse_jobs_v1").fetchone()
    assert tuple(row) == (dl.new_blob, dl.prior_blob, "queued", 0)
    assert c.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0] == 0
    assert store.all_verdicts(c)[0]["abuse_result"]["status"] == "queued"
    c.close()


def test_worker_runs_substantive_review_after_short_clear_and_restart_does_not_repeat(monkeypatch, tmp_path):
    cfg, dl = config(tmp_path), download()
    extraction(monkeypatch, [dl])
    c, _ = enqueue(cfg, dl); c.close()
    backend = Backend()
    assert coordinator.drain(cfg, backend_factory=lambda: backend) == 1
    assert len(backend.calls) == 2
    assert coordinator.drain(cfg, backend_factory=lambda: pytest.fail("completed work cannot be repeated")) == 0
    c = store.connect(cfg)
    row = store.all_verdicts(c)[0]
    assert row["abuse_result"]["status"] == "no_abuse_found"
    assert dashboard.counts([row])["model_reviewed"] == 1
    assert "No abuse found in assessed behavior" in dashboard.render_dashboard([row])
    assert c.execute("SELECT reserved_calls FROM abuse_jobs_v1").fetchone()[0] == 12
    assert c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    c.close()


def test_lease_expiry_is_terminal_and_fences_late_completion(tmp_path):
    cfg, dl = config(tmp_path), download()
    c, _ = enqueue(cfg, dl)
    clock = [100.0]
    writer = abuse_jobs.Jobs(c, clock=lambda: clock[0])
    job = writer.claim(lease_seconds=10)
    result = validated(context(cfg, job, dl))
    clock[0] = 111
    assert writer.expire() == 1
    assert writer.claim(lease_seconds=10) is None
    with pytest.raises(abuse_jobs.StaleCompletion):
        writer.finish(job, result)
    assert c.execute("SELECT reserved_calls FROM abuse_jobs_v1").fetchone()[0] == 12
    assert store.all_verdicts(c)[0]["abuse_result"]["status"] == "review_failed"
    assert c.execute("SELECT COUNT(*) FROM abuse_job_events_v1 WHERE kind='stale_completion'").fetchone()[0] == 1
    c.close()


def test_newer_projection_and_human_decision_cannot_be_overwritten(tmp_path):
    cfg, dl = config(tmp_path), download()
    c, writer = enqueue(cfg, dl)
    job = writer.claim(lease_seconds=100)
    result = validated(context(cfg, job, dl))
    c.execute("INSERT INTO abuse_review_projections_v1(release_id,batch,payload) VALUES(?, 'newer', ?)",
        (job["release_id"], json.dumps({"status": "held"}))); c.commit()
    writer.finish(job, result)
    assert store.all_verdicts(c)[0]["abuse_result"]["status"] == "held"
    assert c.execute("SELECT COUNT(*) FROM abuse_review_projections_v1").fetchone()[0] == 1
    store.adjudicate(c, job["release_id"], "benign", "authoritative decision")
    row = store.all_verdicts(c)[0]
    assert row["human_label"] == "benign" and row["human_note"] == "authoritative decision"
    assert row["abuse_result"]["status"] == "held"
    c.close()


def test_cross_input_or_unvalidated_completion_is_rejected(tmp_path):
    cfg, dl = config(tmp_path), download()
    c, writer = enqueue(cfg, dl)
    job = writer.claim(lease_seconds=100)
    result = validated(context(cfg, job, dl))
    wrong = deepcopy(result); wrong["candidate"]["input_id"] = "0" * 64
    with pytest.raises(ValueError, match="cross-input"):
        writer.finish(job, wrong)
    wrong = deepcopy(result); wrong["mechanical_validated"] = False
    with pytest.raises(ValueError, match="unvalidated"):
        writer.finish(job, wrong)
    assert c.execute("SELECT COUNT(*) FROM abuse_review_projections_v1").fetchone()[0] == 0
    c.close()


@pytest.mark.parametrize("kind", ["missing", "disagreement", "confirmed", "wrong_input"])
def test_conditional_confirmation_and_disabled_outbox(tmp_path, kind):
    cfg, dl = config(tmp_path), download()
    c, writer = enqueue(cfg, dl)
    job = writer.claim(lease_seconds=100)
    ctx = context(cfg, job, dl, Backend("malicious"))

    def factory(ctx):
        def confirm(original):
            result = validated(ctx, "benign" if kind == "disagreement" else "malicious")
            if kind == "wrong_input":
                result["analysis_input"]["package"] = "another-package"
            return result
        return {} if kind == "missing" else {"claim_check": confirm}

    result = runtime.evaluate(ctx, factory)
    expected = "malicious" if kind == "confirmed" else "held"
    assert result["status"] == expected
    writer.finish(job, result)
    assert c.execute("SELECT COUNT(*) FROM abuse_outbox_v1").fetchone()[0] == (kind == "confirmed")
    if kind == "confirmed":
        assert c.execute("SELECT state FROM abuse_outbox_v1").fetchone()[0] == "disabled"
    assert c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    c.close()


@pytest.mark.parametrize("callback", [False, True])
def test_only_typed_overflow_routes_to_optional_neutral_stage(monkeypatch, tmp_path, callback):
    cfg, dl = config(tmp_path), download()
    c, writer = enqueue(cfg, dl)
    job = writer.claim(lease_seconds=100)
    ctx = context(cfg, job, dl)
    decision = validated(ctx)
    monkeypatch.setattr(abuse_service, "prepare", lambda *a, **k: (_ for _ in ()).throw(flow.ContextOverflow(150000, 128000)))
    result = runtime.evaluate(ctx, lambda ctx: {"targeted": lambda: deepcopy(decision)} if callback else {})
    assert result["status"] == ("no_abuse_found" if callback else "context_deferred")
    assert ctx.backend.calls == []
    writer.finish(job, result)
    c.close()


def test_provider_auth_failure_pauses_worker_without_schema_or_context_retry(monkeypatch, tmp_path):
    cfg = config(tmp_path, concurrency=1)
    downloads = [download("one"), download("two")]
    extraction(monkeypatch, downloads)
    for dl in downloads:
        c, _ = enqueue(cfg, dl); c.close()
    error = ReviewUnavailable("provider auth failed"); error.status_code = 401
    backend = Backend(error=error)
    assert coordinator.drain(cfg, backend_factory=lambda: backend) == 1
    assert len(backend.calls) == 1
    assert coordinator.drain(cfg, backend_factory=lambda: pytest.fail("cooldown must survive restart")) == 0
    c = store.connect(cfg)
    assert c.execute("SELECT COUNT(*) FROM abuse_jobs_v1 WHERE state='queued'").fetchone()[0] == 1
    assert c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    c.close()


def test_explicit_legacy_pending_migration_pins_predecessor_and_preserves_original_rows(monkeypatch, tmp_path):
    cfg, dl = config(tmp_path), download()
    c = store.connect(cfg); store.init_schema(c)
    rid = store.record_release(c, dl.package, dl.version, 10, False, "1", "tgz")
    store.park_for_review(c, rid, "too_large", "old text cap", "old untrusted cached text")
    before = tuple(c.execute("SELECT * FROM releases WHERE id=?", (rid,)).fetchone())
    seen = []

    def acquire(config, rel, **kwargs):
        seen.append(kwargs)
        return dl
    monkeypatch.setattr(fetcher, "download", acquire)
    assert coordinator.enqueue_legacy_pending(cfg, c, ["too_large"], 1) == 1
    assert seen == [{"pinned_prior": "1"}]
    assert tuple(c.execute("SELECT * FROM releases WHERE id=?", (rid,)).fetchone()) == before
    assert coordinator.enqueue_legacy_pending(cfg, c, ["too_large"], 1) == 0
    c.close()


def test_queue_refusal_is_a_processing_error_not_a_threat(tmp_path):
    cfg, dl = config(tmp_path, queue_max_bytes=1), download()
    c, _ = enqueue(cfg, dl)
    assert c.execute("SELECT COUNT(*) FROM abuse_jobs_v1").fetchone()[0] == 0
    row = store.all_verdicts(c)[0]
    assert row["abuse_result"]["status"] == "review_failed"
    assert dashboard.counts([row])["flagged"] == 0
    assert c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    c.close()


def test_sqlite_writer_rejects_other_threads_before_accessing_connection(tmp_path):
    cfg, dl = config(tmp_path), download()
    c, writer = enqueue(cfg, dl)
    errors = []

    def other():
        try:
            writer.claim(lease_seconds=100)
        except Exception as error:
            errors.append(error)
    thread = threading.Thread(target=other); thread.start(); thread.join()
    assert len(errors) == 1 and isinstance(errors[0], RuntimeError)
    c.close()


def test_result_cannot_launder_unissued_original_bytes_or_change_its_label(tmp_path):
    cfg, dl = config(tmp_path), download()
    c, writer = enqueue(cfg, dl)
    job = writer.claim(lease_seconds=100)
    ctx = context(cfg, job, dl)
    result = validated(ctx)
    runtime.validate_result(result, ctx)
    ctx.trace.clear()
    with pytest.raises(ValueError, match="exact original evidence"):
        runtime.validate_result(result, ctx)
    result["status"] = "malicious"
    with pytest.raises(ValueError, match="status does not match"):
        runtime.validate_result(result, ctx)
    c.close()


def test_live_worker_preserves_four_way_model_capacity_and_single_writer(monkeypatch, tmp_path):
    cfg = config(tmp_path)
    downloads = [download(f"fixture-{n}") for n in range(4)]
    extraction(monkeypatch, downloads)
    for dl in downloads:
        c, _ = enqueue(cfg, dl); c.close()
    barrier, lock = threading.Barrier(4), threading.Lock()
    active = peak = 0

    class ConcurrentBackend(Backend):
        def complete(self, **kwargs):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(active, peak)
            try:
                if kwargs["schema"] == reviewer.SHORT_SCHEMA:
                    barrier.wait(timeout=5)
                return super().complete(**kwargs)
            finally:
                with lock:
                    active -= 1

    assert coordinator.drain(cfg, backend_factory=ConcurrentBackend) == 4
    assert peak == 4


def test_verified_inert_metadata_uses_sandbox_file_inventory(tmp_path):
    cfg, dl = config(tmp_path), download()
    source = sources(dl)
    source["current"]["README.md"] = b"# Documentation only\n"
    contexts = {"current": {"artifact_sha256": runtime.identity(cfg, dl).artifact_sha256,
        "files": {"README.md": {"verified_inert": True}}}}
    packet, metadata = abuse_service.prepare(runtime.identity(cfg, dl), source, contexts)
    assert metadata["scoped_file_count"] == 5
    assert all(item["path"] != "README.md" for item in packet.brief(**metadata)["source_blocks"])


def test_watch_intake_continues_while_review_worker_is_busy(monkeypatch, tmp_path):
    cfg = config(tmp_path)
    started, release = threading.Event(), threading.Event()
    ticks = []

    def blocked_drain(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return 0

    def tick(*args, **kwargs):
        assert started.wait(5)
        ticks.append(1)
        if len(ticks) == 2:
            release.set()
        return 0

    monkeypatch.setattr(coordinator, "drain", blocked_drain)
    monkeypatch.setattr(orchestrator, "run_once", tick)
    monkeypatch.setattr(orchestrator, "_cursor", lambda cfg: 1)
    monkeypatch.setattr(orchestrator, "_behind", lambda *args: False)
    monkeypatch.setattr(orchestrator, "_baseline_incomplete", lambda *args: False)
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda *args, **kwargs: None)
    assert orchestrator.watch(cfg, iterations=2, sleep_fn=lambda *args: None) == 2
    assert len(ticks) == 2
