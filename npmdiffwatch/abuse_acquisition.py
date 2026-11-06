"""Bounded acquisition retries, independent of threat classification and feed position."""
import hashlib
import time
import uuid

from . import abuse_jobs, fetcher
from .models import Download, NewRelease


def retryable(result):
    return (isinstance(result, (fetcher.MetadataUnavailable, OSError))
            or isinstance(result, Download) and result.prior_version is not None and result.prior_blob is None)


def record(cfg, conn, rid, error, *, owns_release=False, ticket=None, expected_new_sha=None, terminal=False, clock=time.time):
    writer = abuse_jobs.Jobs(conn, clock=clock)
    reason = str(error)[:1000]
    with writer.transaction():
        old = conn.execute("SELECT attempts,state,owner,expected_new_sha,lease_until FROM abuse_acquisitions_v1 WHERE release_id=?", (rid,)).fetchone()
        if old and (ticket is None or old[1] != "running" or old[2] != ticket["owner"] or old[4] <= clock()):
            return
        attempts = old[0] if old else 1
        state = "completed" if terminal or attempts >= 4 else "queued"
        if old:
            conn.execute("UPDATE abuse_acquisitions_v1 SET state=?,owner=NULL,lease_until=NULL,not_before=?,last_error=? WHERE release_id=?",
                (state, clock() + min(300, 10 * 2**attempts), reason, rid))
        else:
            conn.execute("INSERT INTO abuse_acquisitions_v1 VALUES(?,?,1,?,NULL,NULL,?,?,?,?)",
                (rid, cfg.npm_registry, state, clock() + 20, reason, int(owns_release), expected_new_sha))
        writer.event("acquisition:" + str(rid), "acquisition_failure", {"attempt": attempts, "reason": reason, "state": state})
        prior = conn.execute("SELECT batch FROM abuse_review_projections_v1 WHERE release_id=? ORDER BY id DESC LIMIT 1", (rid,)).fetchone()
        if prior is None or prior[0].startswith("acquisition:"):
            result = {"status": "review_failed" if state == "completed" else "queued", "route": "acquisition",
                "error": reason, "acquisition_attempts": attempts, "mechanical_validated": False}
            conn.execute("INSERT OR IGNORE INTO abuse_review_projections_v1(release_id,batch,payload) VALUES(?,?,?)",
                (rid, f"acquisition:{rid}:{attempts}:{state}", abuse_jobs.encode(result)))


def retry_due(cfg, conn, accept, *, limit=4, clock=time.time):
    writer = abuse_jobs.Jobs(conn, clock=clock)
    done = 0
    for _ in range(limit):
        with writer.transaction():
            expired = conn.execute("SELECT release_id,attempts FROM abuse_acquisitions_v1 WHERE state='running' AND lease_until<=?", (clock(),)).fetchall()
            for rid, attempts in expired:
                conn.execute("UPDATE abuse_acquisitions_v1 SET state=?,owner=NULL WHERE release_id=?",
                    ("queued" if attempts < 4 else "completed", rid))
                writer.event("acquisition:" + str(rid), "acquisition_lease_expired", {"attempt": attempts})
                if attempts >= 4:
                    previous = conn.execute("SELECT batch FROM abuse_review_projections_v1 WHERE release_id=? ORDER BY id DESC LIMIT 1", (rid,)).fetchone()
                    if previous is None or previous[0].startswith("acquisition:"):
                        conn.execute("INSERT OR IGNORE INTO abuse_review_projections_v1(release_id,batch,payload) VALUES(?,?,?)",
                            (rid, f"acquisition:{rid}:{attempts}:expired", abuse_jobs.encode({"status": "review_failed",
                                "error": "acquisition lease expired at retry limit; no allowance reset", "acquisition_attempts": attempts})))
            row = conn.execute("SELECT a.release_id,a.registry,a.attempts,a.owns_release,a.expected_new_sha,r.package,r.version,r.serial,r.prior_version "
                "FROM abuse_acquisitions_v1 a JOIN releases r ON r.id=a.release_id WHERE a.state='queued' "
                "AND a.not_before<=? ORDER BY a.release_id LIMIT 1", (clock(),)).fetchone()
            if row is None:
                break
            rid, registry, attempts, owns, expected, name, version, serial, prior = row
            owner = uuid.uuid4().hex
            conn.execute("UPDATE abuse_acquisitions_v1 SET state='running',owner=?,lease_until=?,attempts=attempts+1 WHERE release_id=?",
                (owner, clock() + cfg.packument_deadline_s + 2 * cfg.fetch_deadline_s + 60, rid))
            writer.event("acquisition:" + str(rid), "acquisition_reserved", {"attempt": attempts + 1, "owner": owner})
        ticket = {"owner": owner, "owns_release": bool(owns), "release_id": rid}
        rel = NewRelease(name, version, serial or 0)
        try:
            if registry != cfg.npm_registry:
                raise ValueError("acquisition registry changed; explicit migration required")
            result = fetcher.download(cfg, rel, **({"pinned_prior": prior} if expected else {}))
            if isinstance(result, Download) and expected and hashlib.sha256(result.new_blob).hexdigest() != expected:
                raise ValueError("acquisition current artifact changed; retained digest cannot be substituted")
        except Exception as error:
            result = error
        if retryable(result):
            record(cfg, conn, rid, result if isinstance(result, Exception) else "exact predecessor download failed",
                ticket=ticket, clock=clock)
        elif not isinstance(result, Download):
            record(cfg, conn, rid, result if isinstance(result, Exception) else "historical artifact is unavailable",
                ticket=ticket, terminal=True, clock=clock)
        else:
            with writer.transaction():
                active = conn.execute("SELECT 1 FROM abuse_acquisitions_v1 WHERE release_id=? AND state='running' AND owner=? AND lease_until>?",
                    (rid, owner, clock())).fetchone()
                if not active:
                    writer.event("acquisition:" + str(rid), "stale_acquisition_completion", {"owner": owner})
                    continue
                if owns and isinstance(result, Download):
                    human = conn.execute("SELECT 1 FROM verdicts WHERE release_id=?", (rid,)).fetchone()
                    guarded = conn.execute("SELECT 1 FROM abuse_human_decisions_v1 WHERE release_id=?", (rid,)).fetchone()
                    if not human and not guarded:
                        conn.execute("UPDATE releases SET prior_version=?,is_first_release=? WHERE id=?",
                            (result.prior_version, int(result.is_new_package), rid))
                conn.execute("UPDATE abuse_acquisitions_v1 SET state='completed',owner=NULL WHERE release_id=? AND owner=?", (rid, owner))
                writer.event("acquisition:" + str(rid), "acquisition_finished", {"attempt": attempts + 1})
            accept(cfg, conn, rel, result)
        done += 1
    return done
