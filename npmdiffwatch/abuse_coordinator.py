"""Live intake/worker adapters for abuse review; never invokes the legacy gate.

Intake commits unopened pairs before advancing the registry cursor. Model work
runs in an independent worker with one SQLite writer and bounded model-only
threads. No package execution, historical verdict rewrite, or notification.
"""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import logging
import threading

from . import abuse_jobs, abuse_runtime, fetcher, hostmem, store
from .backends import make_backend
from .evidence import fingerprint
from .models import Download, NewRelease

logger = logging.getLogger(__name__)


def selected(cfg):
    return cfg.reviewer.workflow == "abuse"


def refusal(conn, rid, reason):
    """Append an operational result, not a threat finding or an old-row rewrite."""
    result = {"status": "review_failed", "error": reason, "model_calls": 0,
              "workflow_version": abuse_runtime.WORKFLOW_VERSION, "mechanical_validated": False}
    key = "acquisition:" + fingerprint({"release_id": rid, "error": reason})
    writer = abuse_jobs.Jobs(conn)
    with writer.transaction():
        previous = conn.execute("SELECT batch FROM abuse_review_projections_v1 WHERE release_id=? ORDER BY id DESC LIMIT 1", (rid,)).fetchone()
        if previous is None or previous[0].startswith("acquisition:"):
            conn.execute("INSERT OR IGNORE INTO abuse_review_projections_v1(release_id,batch,payload) VALUES(?,?,?)",
                (rid, key, abuse_jobs.encode(result)))


def accept_fetch(cfg, conn, release, result):
    writer = abuse_jobs.Jobs(conn)
    writer.initialize()
    existing = conn.execute("SELECT id FROM releases WHERE package=? AND version=?", (release.package, release.version)).fetchone()
    if isinstance(result, Download):
        rid = store.record_release(conn, release.package, release.version, release.serial,
            result.is_new_package, result.prior_version, "tgz", stage="abuse_queued")
        from . import abuse_acquisition
        if abuse_acquisition.retryable(result):
            abuse_acquisition.record(cfg, conn, rid, "exact pinned predecessor was not acquired",
                owns_release=not existing, expected_new_sha=hashlib.sha256(result.new_blob).hexdigest())
            return True
        try:
            ident = abuse_runtime.identity(cfg, result)
            writer.enqueue(rid, ident, result.new_blob, result.prior_blob,
                max_bytes=cfg.reviewer.queue_max_bytes, max_jobs=cfg.reviewer.queue_max_jobs)
        except (ValueError, TypeError) as error:
            refusal(conn, rid, f"{type(error).__name__}: {error}")
        return True
    rid = existing[0] if existing else store.record_release(conn, release.package, release.version, release.serial,
        False, None, "tgz", stage="abuse_acquiring")
    from . import abuse_acquisition
    if abuse_acquisition.retryable(result):
        abuse_acquisition.record(cfg, conn, rid, result, owns_release=not existing)
        return True
    if isinstance(result, fetcher.Removed):
        if not existing:
            store.record_removed(conn, rid, result.kind, result.at)
        refusal(conn, rid, "target release was removed before acquisition")
    elif isinstance(result, Exception):
        refusal(conn, rid, f"{type(result).__name__}: {result}")
    else:
        refusal(conn, rid, "no admitted tarball pair; no source was reviewed")
    return True


def enqueue_legacy_pending(cfg, conn, reasons=None, limit=None):
    """Explicit CLI migration only. Startup never bulk-relabels historical rows."""
    writer = abuse_jobs.Jobs(conn)
    writer.initialize()
    rows = store.pending_reviews(conn, reasons)
    done = 0
    for row in rows:
        if limit is not None and done >= limit:
            break
        if conn.execute("SELECT 1 FROM abuse_jobs_v1 WHERE release_id=?", (row["release_id"],)).fetchone():
            continue
        try:
            # Exact predecessor pinning is mandatory; the registry's current
            # semver predecessor cannot replace the recorded pending baseline.
            result = fetcher.download(cfg, NewRelease(row["package"], row["version"], row["serial"] or 0),
                pinned_prior=row["prior_version"])
            if isinstance(result, Download) and row["prior_version"] is None and not row["is_first_release"]:
                result = replace(result, is_new_package=False)
        except Exception as error:
            result = error
        accept_fetch(cfg, conn, NewRelease(row["package"], row["version"], row["serial"] or 0), result)
        done += 1
    return done


def drain(cfg, *, limit=None, stop=None, backend_factory=None):
    """One bounded worker batch. Database operations stay on this owning thread."""
    maximum = cfg.reviewer.max_pending_per_tick if limit is None else limit
    if type(maximum) is not int or maximum < 0:
        raise ValueError("worker limit must be a nonnegative integer")
    if maximum == 0:
        return 0
    if not cfg.reviewer_enabled:
        return 0
    stop = stop or threading.Event()
    conn = store.connect(cfg)
    store.init_schema(conn)
    writer = abuse_jobs.Jobs(conn)
    writer.initialize()
    writer.expire()
    from .abuse_acquisition import retry_due
    retry_due(cfg, conn, accept_fetch)
    if writer.provider_paused():
        conn.close()
        return 0
    try:
        factory = abuse_runtime.extension_factory(cfg.reviewer.extension)
        if backend_factory is None:
            make_backend(cfg)  # configuration/SDK preflight only; never a model request
    except BaseException:
        conn.close()
        raise
    from .orchestrator import _review_slot

    @contextmanager
    def slot():
        with _review_slot(cfg, cancel_event=stop):
            yield

    pending, used, done, source_bytes = {}, 0, 0, 0
    memory = hostmem.for_config(cfg)
    try:
        with ThreadPoolExecutor(max_workers=cfg.reviewer.concurrency, thread_name_prefix="abuse-review") as workers:
            while pending or (not stop.is_set() and used < maximum):
                # Bound prepared-source retention as well as the aggregate model
                # slots. A single parse remains protected by the sandbox RSS cap.
                while not stop.is_set() and used < maximum and len(pending) < cfg.reviewer.concurrency and source_bytes < 1024**3:
                    if memory is not None and memory.pressure():
                        logger.warning("abuse worker deferred by host-memory pressure; queue retained")
                        break
                    job = writer.claim(lease_seconds=2100 + 2 * cfg.parse_timeout_s)
                    if job is None:
                        break
                    used += 1
                    try:
                        backend = backend_factory() if backend_factory else None
                        context = abuse_runtime.prepare(cfg, job, slot, stop, backend=backend)
                        size = sum(len(b) for files in context.sources.values() for b in files.values())
                        source_bytes += size
                        future = workers.submit(abuse_runtime.evaluate, context, factory)
                        pending[future] = (job, size)
                    except Exception as error:
                        writer.finish(job, {"status": "review_failed", "error": f"{type(error).__name__}: {error}",
                            "model_calls": 0, "mechanical_validated": False})
                        done += 1
                if not pending:
                    break
                for future in wait(pending, return_when=FIRST_COMPLETED).done:
                    job, size = pending.pop(future)
                    source_bytes -= size
                    result = future.result()
                    try:
                        writer.finish(job, result)
                    except abuse_jobs.StaleCompletion:
                        logger.warning("stale review completion held for %s", job["identity"].package)
                    done += 1
                    if result.get("service_failure"):
                        # Do not turn a provider outage into retries on every
                        # remaining package in this batch.
                        used = maximum
                        writer.pause_provider(result["service_failure"])
        return done
    finally:
        conn.close()


@contextmanager
def worker(cfg):
    """Background model worker for watch; no intake cursor lock or SQLite sharing."""
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                drain(cfg, stop=stop)
            except Exception:
                logger.exception("abuse worker stopped this batch; intake remains independent")
            stop.wait(1)

    thread = threading.Thread(target=loop, name="abuse-coordinator", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()


def pending_counts(cfg):
    conn = store.connect(cfg)
    try:
        return {key: value for key, value in abuse_jobs.counts(conn).items() if key != "completed"}
    finally:
        conn.close()
