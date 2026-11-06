"""Durable, single-owner queue and append-only release projections.

Only unopened archive blobs are retained. A claimed job reserves its entire
12-call allowance once. Expired work fails visibly; restarting never reruns it.
No original verdict/evidence/cursor rows are rewritten and no alerts are sent.
"""
from contextlib import contextmanager
from dataclasses import asdict
import datetime
import hashlib
import json
import math
import threading
import time
import uuid

from .evidence import AnalysisInput, fingerprint


SCHEMA = """
CREATE TABLE IF NOT EXISTS abuse_jobs_v1(
 id TEXT PRIMARY KEY,release_id INTEGER NOT NULL,input_id TEXT NOT NULL,
 identity_json TEXT NOT NULL,new_blob BLOB NOT NULL,prior_blob BLOB,
 state TEXT NOT NULL CHECK(state IN ('queued','running','completed')),
 owner TEXT,lease_until REAL,reserved_calls INTEGER NOT NULL DEFAULT 0,
 expected_projection INTEGER NOT NULL DEFAULT 0,result_json TEXT,
 created_at TEXT NOT NULL,finished_at TEXT,UNIQUE(release_id,input_id));
CREATE INDEX IF NOT EXISTS ix_abuse_jobs_state_v1 ON abuse_jobs_v1(state,created_at);
CREATE TABLE IF NOT EXISTS abuse_job_events_v1(
 id INTEGER PRIMARY KEY,job_id TEXT NOT NULL,kind TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS abuse_review_projections_v1(
 id INTEGER PRIMARY KEY,release_id INTEGER NOT NULL,batch TEXT NOT NULL,payload TEXT NOT NULL,UNIQUE(release_id,batch));
CREATE TABLE IF NOT EXISTS abuse_human_decisions_v1(
 id INTEGER PRIMARY KEY,release_id INTEGER NOT NULL,label TEXT NOT NULL,note TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS abuse_outbox_v1(
 id TEXT PRIMARY KEY,release_id INTEGER NOT NULL,projection_id INTEGER NOT NULL,payload TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('disabled','pending','sent','cancelled')),attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS abuse_worker_health_v1(id INTEGER PRIMARY KEY CHECK(id=1),paused_until REAL NOT NULL,reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS abuse_acquisitions_v1(
 release_id INTEGER PRIMARY KEY,registry TEXT NOT NULL,attempts INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('queued','running','completed')),owner TEXT,lease_until REAL,
 not_before REAL NOT NULL,last_error TEXT NOT NULL,owns_release INTEGER NOT NULL,expected_new_sha TEXT);
"""


def now():
    return datetime.datetime.now(datetime.UTC).isoformat()


def encode(value):
    text = json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False)
    if len(text.encode()) > 4 * 1024**2:
        raise ValueError("bounded review record exceeds four MiB")
    return text


def exists(conn, table="abuse_jobs_v1"):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


class StaleCompletion(ValueError):
    pass


class QueueFull(ValueError):
    pass


class Jobs:
    def __init__(self, conn, *, clock=time.time):
        self.conn, self.clock, self.owner_thread = conn, clock, threading.get_ident()

    @contextmanager
    def transaction(self):
        if threading.get_ident() != self.owner_thread:
            raise RuntimeError("queue writes belong to the coordinator thread")
        if self.conn.in_transaction:
            raise ValueError("queue cannot commit another caller's transaction")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise

    def initialize(self):
        if self.conn.in_transaction or threading.get_ident() != self.owner_thread:
            raise ValueError("queue migration requires its owning transaction/thread")
        try:
            self.conn.executescript("BEGIN IMMEDIATE;\n" + SCHEMA + "\nCOMMIT;")
        except BaseException:
            self.conn.rollback()
            raise

    def event(self, job_id, kind, payload):
        self.conn.execute("INSERT INTO abuse_job_events_v1(job_id,kind,payload,created_at) VALUES(?,?,?,?)",
            (job_id, kind, encode(payload), now()))

    def enqueue(self, release_id, identity, new_blob, prior_blob, *, max_bytes, max_jobs):
        if (hashlib.sha256(new_blob).hexdigest() != identity.artifact_sha256
                or (hashlib.sha256(prior_blob).hexdigest() if prior_blob is not None else None) != identity.prior_sha256):
            raise ValueError("queue artifact identity mismatch")
        jid = fingerprint({"release_id": release_id, "input_id": identity.id})
        with self.transaction():
            previous = self.conn.execute("SELECT identity_json FROM abuse_jobs_v1 WHERE id=?", (jid,)).fetchone()
            if previous:
                if previous[0] != encode(asdict(identity)):
                    raise ValueError("immutable queue identity collision")
                return jid
            row = self.conn.execute("SELECT package,version,prior_version FROM releases WHERE id=?", (release_id,)).fetchone()
            if not row or tuple(row) != (identity.package, identity.version, identity.prior_version):
                raise ValueError("queue input does not match the pinned release")
            count, retained = self.conn.execute("SELECT COUNT(*),COALESCE(SUM(length(new_blob)+COALESCE(length(prior_blob),0)),0) FROM abuse_jobs_v1").fetchone()
            if count >= max_jobs or retained + len(new_blob) + len(prior_blob or b"") > max_bytes:
                raise QueueFull("durable review retention budget exhausted; no work was silently dropped")
            self.conn.execute("INSERT INTO abuse_jobs_v1(id,release_id,input_id,identity_json,new_blob,prior_blob,state,created_at) "
                "VALUES(?,?,?,?,?,?,'queued',?)", (jid, release_id, identity.id, encode(asdict(identity)), new_blob, prior_blob, now()))
            self.event(jid, "queued", {"input_id": identity.id})
        return jid

    def claim(self, *, lease_seconds):
        if type(lease_seconds) not in (int, float) or not math.isfinite(lease_seconds) or not 0 < lease_seconds <= 86400:
            raise ValueError("lease must be bounded and positive")
        with self.transaction():
            row = self.conn.execute("SELECT id,release_id,identity_json,new_blob,prior_blob FROM abuse_jobs_v1 "
                "WHERE state='queued' ORDER BY created_at,id LIMIT 1").fetchone()
            if row is None:
                return None
            jid, rid, identity_json, new_blob, prior_blob = row
            owner = uuid.uuid4().hex
            revision = self.conn.execute("SELECT COALESCE(MAX(id),0) FROM abuse_review_projections_v1 WHERE release_id=?", (rid,)).fetchone()[0]
            deadline = self.clock() + lease_seconds
            self.conn.execute("UPDATE abuse_jobs_v1 SET state='running',owner=?,lease_until=?,reserved_calls=12,expected_projection=? "
                "WHERE id=? AND state='queued'", (owner, deadline, revision, jid))
            self.event(jid, "claimed", {"owner": owner, "reserved_calls": 12, "lease_until": deadline})
        return {"id": jid, "release_id": rid, "identity": AnalysisInput(**json.loads(identity_json)),
                "new_blob": new_blob, "prior_blob": prior_blob, "owner": owner, "expected_projection": revision}

    def finish(self, job, result):
        calls = result.get("model_calls", 0)
        if type(calls) is not int or not 0 <= calls <= 12:
            raise ValueError("invalid bounded job dispatch count")
        if result["status"] in ("no_abuse_found", "suspicious", "malicious"):
            ident = job["identity"]
            candidate = result.get("candidate", {})
            expected = {"no_abuse_found": "B", "suspicious": "S", "malicious": "M"}[result["status"]]
            if (result.get("mechanical_validated") is not True or candidate.get("assessment") != expected
                    or result.get("analysis_input") != asdict(ident)
                    or candidate.get("input_id") != ident.id or candidate.get("policy_sha256") != ident.policy_sha256):
                raise ValueError("unvalidated or cross-input result cannot be published")
            if result["status"] in ("suspicious", "malicious"):
                check = result.get("claim_check", {})
                confirmation = check.get("result", {})
                if (not check.get("triggered") or confirmation.get("status") != result["status"]
                        or not confirmation.get("mechanical_validated")
                        or confirmation.get("candidate", {}).get("input_id") != ident.id):
                    raise ValueError("unconfirmed finding cannot be published")
        payload = encode(result)
        with self.transaction():
            row = self.conn.execute("SELECT state,owner,lease_until,expected_projection FROM abuse_jobs_v1 WHERE id=?", (job["id"],)).fetchone()
            if not row or row[0] != "running" or row[1] != job["owner"] or row[2] <= self.clock():
                self.event(job["id"], "stale_completion", {"owner": job["owner"], "result": result})
                stale = True
            else:
                stale = False
                self.conn.execute("UPDATE abuse_jobs_v1 SET state='completed',result_json=?,finished_at=? WHERE id=?",
                    (payload, now(), job["id"]))
                self.event(job["id"], "completed", {"status": result["status"], "model_calls": result.get("model_calls", 0)})
                latest = self.conn.execute("SELECT COALESCE(MAX(id),0) FROM abuse_review_projections_v1 WHERE release_id=?", (job["release_id"],)).fetchone()[0]
                human = self.conn.execute("SELECT human_label FROM verdicts WHERE release_id=?", (job["release_id"],)).fetchone()
                guarded = bool(human and human[0]) or self.conn.execute("SELECT 1 FROM abuse_human_decisions_v1 WHERE release_id=?", (job["release_id"],)).fetchone()
                if latest != row[3] or guarded:
                    self.event(job["id"], "publication_held", {"reason": "newer projection or human decision"})
                else:
                    view = {key: value for key, value in result.items() if key not in ("trace", "initial_review_trace", "tools")}
                    check = view.get("claim_check", {})
                    view["claim_check"] = {key: value for key, value in check.items() if key != "result"}
                    self.conn.execute("INSERT INTO abuse_review_projections_v1(release_id,batch,payload) VALUES(?,?,?)",
                        (job["release_id"], "live:" + job["id"], encode(view)))
                    revision = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                    if result["status"] in ("suspicious", "malicious"):
                        eid = fingerprint({"job": job["id"], "candidate": result["candidate"]["candidate_id"]})
                        event = {"event_id": eid, "release_id": job["release_id"], "input_id": job["identity"].id,
                            "status": result["status"], "candidate_id": result["candidate"]["candidate_id"]}
                        self.conn.execute("INSERT INTO abuse_outbox_v1 VALUES(?,?,?,?,'disabled',0)",
                            (eid, job["release_id"], revision, encode(event)))
        if stale:
            raise StaleCompletion("lease/owner expired; result retained but not published")

    def expire(self):
        with self.transaction():
            rows = self.conn.execute("SELECT id,release_id,expected_projection FROM abuse_jobs_v1 WHERE state='running' AND lease_until<=?", (self.clock(),)).fetchall()
            for jid, rid, revision in rows:
                result = {"status": "review_failed", "error": "review worker lease expired; reserved allowance retained; explicit replay required"}
                self.conn.execute("UPDATE abuse_jobs_v1 SET state='completed',result_json=?,finished_at=? WHERE id=?", (encode(result), now(), jid))
                self.event(jid, "lease_expired", result)
                latest = self.conn.execute("SELECT COALESCE(MAX(id),0) FROM abuse_review_projections_v1 WHERE release_id=?", (rid,)).fetchone()[0]
                human = self.conn.execute("SELECT human_label FROM verdicts WHERE release_id=?", (rid,)).fetchone()
                guarded = bool(human and human[0]) or self.conn.execute("SELECT 1 FROM abuse_human_decisions_v1 WHERE release_id=?", (rid,)).fetchone()
                if latest == revision and not guarded:
                    self.conn.execute("INSERT INTO abuse_review_projections_v1(release_id,batch,payload) VALUES(?,?,?)",
                        (rid, "live:" + jid, encode(result)))
        return len(rows)

    def pause_provider(self, status):
        seconds = 900 if status in (401, 402, 403) else 60
        with self.transaction():
            self.conn.execute("INSERT INTO abuse_worker_health_v1 VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET "
                "paused_until=MAX(paused_until,excluded.paused_until),reason=excluded.reason",
                (self.clock() + seconds, f"provider status {status}; no schema/context retry"))

    def provider_paused(self):
        row = self.conn.execute("SELECT paused_until FROM abuse_worker_health_v1 WHERE id=1").fetchone()
        return bool(row and row[0] > self.clock())


def overlay(conn, rows):
    """Read-only view used by every dashboard; human decisions always dominate."""
    output = [dict(row) for row in rows]
    projections = {}
    if exists(conn, "abuse_review_projections_v1"):
        projections = {rid: json.loads(payload) for rid, payload in conn.execute("SELECT release_id,payload FROM abuse_review_projections_v1 "
            "WHERE id IN (SELECT MAX(id) FROM abuse_review_projections_v1 GROUP BY release_id)")}
    queued = {}
    humans = {}
    if exists(conn):
        queued = dict(conn.execute("SELECT release_id,state FROM abuse_jobs_v1 WHERE state IN ('queued','running') ORDER BY created_at"))
        humans = {rid: (label, note) for rid, label, note in conn.execute("SELECT release_id,label,note FROM abuse_human_decisions_v1 "
            "WHERE id IN (SELECT MAX(id) FROM abuse_human_decisions_v1 GROUP BY release_id)")}
    for row in output:
        rid = row["release_id"]
        if rid in projections:
            row["abuse_result"] = projections[rid]
            if rid in queued:
                row["abuse_result"]["workflow_state"] = queued[rid]
                if row["abuse_result"].get("status") in ("queued", "running"):
                    row["abuse_result"]["status"] = queued[rid]
        elif rid in queued:
            row["abuse_result"] = {"status": queued[rid]}
        if rid in humans:
            row["human_label"], row["human_note"] = humans[rid]
        if not row.get("model"):
            row["model"] = "none"
    return output


def counts(conn):
    if not exists(conn):
        return {}
    result = dict(conn.execute("SELECT state,COUNT(*) FROM abuse_jobs_v1 GROUP BY state"))
    for state, count in conn.execute("SELECT state,COUNT(*) FROM abuse_acquisitions_v1 WHERE state!='completed' GROUP BY state"):
        result["acquisition_" + state] = count
    return result
