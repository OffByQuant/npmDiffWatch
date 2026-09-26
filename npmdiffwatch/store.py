import datetime
import json
import sqlite3
import zlib
from .config import Config

SCHEMA = """
CREATE TABLE IF NOT EXISTS cursor(id INTEGER PRIMARY KEY CHECK(id=1),
  last_serial INTEGER NOT NULL DEFAULT 0, updated_at TEXT);
INSERT OR IGNORE INTO cursor(id, last_serial) VALUES (1, 0);
CREATE TABLE IF NOT EXISTS releases(id INTEGER PRIMARY KEY,
  package TEXT, version TEXT, serial INTEGER, is_first_release INTEGER,
  prior_version TEXT, artifact_basis TEXT, triage_score REAL, triage_rules TEXT,
  stage TEXT, processed_at TEXT, evidence TEXT,
  packument_json TEXT, scripts_json TEXT, has_lockfile INTEGER DEFAULT 0,
  has_shrinkwrap INTEGER DEFAULT 0, UNIQUE(package, version));
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, release_id INTEGER,
  classification TEXT, score REAL, fired_rules TEXT, dedupe_key TEXT UNIQUE,
  delivery_status TEXT, sent_at TEXT);
CREATE TABLE IF NOT EXISTS verdicts(id INTEGER PRIMARY KEY,
  release_id INTEGER UNIQUE, classification TEXT, confidence REAL,
  attack_type TEXT, reasoning TEXT, cited_hunk TEXT, model TEXT, urgent INTEGER,
  created_at TEXT, human_label TEXT, human_note TEXT, adjudicated_at TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS watchlist_baseline(package TEXT PRIMARY KEY, result TEXT, done_at TEXT,
    attempts INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS feed_retry(package TEXT PRIMARY KEY, seq INTEGER, attempts INTEGER,
    gave_up INTEGER DEFAULT 0, updated_at TEXT);
CREATE TABLE IF NOT EXISTS reviewer_stats(endpoint TEXT, model TEXT, tok_s REAL, chars_per_token REAL,
  samples INTEGER, state TEXT, detail TEXT, paused_until REAL, slow_streak INTEGER, updated_at TEXT,
  PRIMARY KEY(endpoint, model));
"""

def _now(): return datetime.datetime.now(datetime.UTC).isoformat()

def connect(cfg: Config) -> sqlite3.Connection:
    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(cfg.db_path)
    c.execute("PRAGMA journal_mode=WAL"); c.row_factory = sqlite3.Row
    return c

def init_schema(conn): conn.executescript(SCHEMA); conn.commit(); migrate_schema(conn)

def migrate_schema(conn):
    for col in ("maintainer_metadata", "evidence", "packument_json", "scripts_json", "has_lockfile", "has_shrinkwrap",
                "review_attempts", "pending_reason", "pending_detail", "review_input", "review_input_chars",
                "scan_attempts", "removed_reason", "removed_at"):
        try:
            conn.execute(f"SELECT {col} FROM releases LIMIT 1")
        except sqlite3.OperationalError:
            if col in ("has_lockfile", "has_shrinkwrap", "review_attempts", "scan_attempts"):
                conn.execute(f"ALTER TABLE releases ADD COLUMN {col} INTEGER DEFAULT 0")
            elif col == "review_input_chars":
                conn.execute(f"ALTER TABLE releases ADD COLUMN {col} INTEGER")
                for rid, blob in conn.execute("SELECT id, review_input FROM releases "
                                              "WHERE review_input IS NOT NULL").fetchall():
                    conn.execute("UPDATE releases SET review_input_chars=? WHERE id=?",
                                 (len(zlib.decompress(blob).decode()), rid))
            else:
                conn.execute(f"ALTER TABLE releases ADD COLUMN {col} TEXT")
            conn.commit()
    for col in ("runs_when", "chain_source", "chain_sink", "review_tier"):
        try:
            conn.execute(f"SELECT {col} FROM verdicts LIMIT 1")
        except sqlite3.OperationalError:
            conn.execute(f"ALTER TABLE verdicts ADD COLUMN {col} TEXT")
            conn.commit()

def get_last_serial(conn) -> int:
    return conn.execute("SELECT last_serial FROM cursor WHERE id=1").fetchone()[0]

def get_cursor(conn):
    return conn.execute("SELECT last_serial, updated_at FROM cursor WHERE id=1").fetchone()

def count_releases(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM releases").fetchone()[0]

def set_last_serial(conn, serial: int):
    conn.execute("UPDATE cursor SET last_serial=?, updated_at=? WHERE id=1", (serial, _now()))
    conn.commit()

def release_exists(conn, package, version) -> bool:
    return conn.execute("SELECT 1 FROM releases WHERE package=? AND version=?",
                        (package, version)).fetchone() is not None

def record_release(conn, package, version, serial, is_first, prior, basis, stage="ingested") -> int:
    conn.execute("""INSERT OR IGNORE INTO releases
        (package,version,serial,is_first_release,prior_version,artifact_basis,stage,processed_at)
        VALUES(?,?,?,?,?,?,?,?)""",
        (package, version, serial, int(is_first), prior, basis, stage, _now()))
    conn.commit()
    return conn.execute("SELECT id FROM releases WHERE package=? AND version=?",
                        (package, version)).fetchone()[0]

def set_baseline(conn, release_id, prior_version, is_first):
    conn.execute("UPDATE releases SET prior_version=?, is_first_release=? WHERE id=?",
                 (prior_version, int(is_first), release_id))
    conn.commit()

def update_release_metadata(conn, release_id, maintainer_metadata_json):
    conn.execute("UPDATE releases SET maintainer_metadata=? WHERE id=?",
                 (maintainer_metadata_json, release_id))
    conn.commit()

def update_npm_metadata(conn, release_id, scripts_json=None, has_lockfile=None, has_shrinkwrap=None):
    sets, params = [], []
    if scripts_json is not None:
        sets.append("scripts_json=?"); params.append(scripts_json)
    if has_lockfile is not None:
        sets.append("has_lockfile=?"); params.append(int(has_lockfile))
    if has_shrinkwrap is not None:
        sets.append("has_shrinkwrap=?"); params.append(int(has_shrinkwrap))
    if not sets:
        return
    params.append(release_id)
    conn.execute(f"UPDATE releases SET {', '.join(sets)} WHERE id=?", params)
    conn.commit()

def prune(conn, retention_days: int = 0):
    """Shrink the database, keeping everything a person may act on (verdicts, alerts, the review queues and
    their evidence):
    - clear packuments stored by older versions (never read; up to 65 MB each);
    - compress evidence stored as plain text by older versions;
    - drop evidence nobody needs: releases reviewed benign, and releases below the review threshold;
    - with retention_days > 0, delete plain release rows older than that (no verdict, no alert, not queued),
      except each package's newest release, which later diffs and dedupe rely on;
    then compact the file."""
    conn.execute("UPDATE releases SET packument_json=NULL WHERE packument_json IS NOT NULL")
    for rid, text in conn.execute("SELECT id, evidence FROM releases WHERE typeof(evidence)='text'").fetchall():
        conn.execute("UPDATE releases SET evidence=? WHERE id=?", (zlib.compress(text.encode()), rid))
    conn.execute("UPDATE releases SET evidence=NULL WHERE evidence IS NOT NULL AND (stage='triaged' OR id IN "
                 "(SELECT release_id FROM verdicts WHERE classification='benign' "
                 "AND COALESCE(human_label,'benign')='benign'))")
    if retention_days > 0:
        cutoff = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=retention_days)).isoformat()
        conn.execute("DELETE FROM releases WHERE processed_at < ? "
                     "AND stage NOT IN ('pending_review','needs_adjudication') "
                     "AND id NOT IN (SELECT release_id FROM verdicts WHERE release_id IS NOT NULL) "
                     "AND id NOT IN (SELECT release_id FROM alerts WHERE release_id IS NOT NULL) "
                     "AND id NOT IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY package "
                     "ORDER BY processed_at DESC, id DESC) AS n FROM releases) WHERE n = 1)", (cutoff,))
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("VACUUM")

def maybe_prune(conn, retention_days: int, every_s: float, now: float) -> bool:
    """prune() if the last one (recorded in the database, so cron-driven `run` counts too) is every_s old."""
    row = conn.execute("SELECT value FROM meta WHERE key='last_prune'").fetchone()
    if row and now - float(row[0]) < every_s:
        return False
    prune(conn, retention_days)
    conn.execute("INSERT INTO meta(key, value) VALUES('last_prune', ?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now),))
    conn.commit()
    return True

def evidence_text(value):
    """Stored evidence as text: compressed bytes, or plain text written by older versions."""
    if value is None or isinstance(value, str):
        return value
    return zlib.decompress(value).decode()

def update_evidence(conn, release_id, evidence_text):
    conn.execute("UPDATE releases SET evidence=? WHERE id=?", (zlib.compress(evidence_text.encode()), release_id))
    conn.commit()

def clear_evidence(conn, release_id):
    conn.execute("UPDATE releases SET evidence=NULL WHERE id=?", (release_id,))
    conn.commit()

def get_evidence(conn, release_id):
    row = conn.execute("SELECT evidence FROM releases WHERE id=?", (release_id,)).fetchone()
    return evidence_text(row[0]) if row else None

def releases_needing_evidence(conn, release_id=None, all_flagged=False):
    base = ("SELECT DISTINCT r.id AS release_id, r.package, r.version, r.serial, "
            "r.is_first_release FROM releases r")
    where = ["r.evidence IS NULL", "r.triage_rules IS NOT NULL", "r.triage_rules != '[]'"]
    params = []
    if not all_flagged:
        base += (" LEFT JOIN verdicts v ON v.release_id = r.id"
                 " LEFT JOIN alerts a ON a.release_id = r.id")
        where.append("(v.classification IN ('malicious','suspicious') "
                     "OR (a.classification IS NOT NULL AND a.classification != 'benign'))")
    if release_id is not None:
        where.append("r.id = ?"); params.append(release_id)
    return conn.execute(base + " WHERE " + " AND ".join(where) + " ORDER BY r.id", params).fetchall()

def get_release_metadata(conn, package, version):
    row = conn.execute("SELECT maintainer_metadata FROM releases WHERE package=? AND version=?",
                       (package, version)).fetchone()
    return json.loads(row[0]) if row and row[0] else None

def review_attempts(conn, release_id) -> int:
    return conn.execute("SELECT review_attempts FROM releases WHERE id=?", (release_id,)).fetchone()[0] or 0

def bump_review_attempts(conn, release_id) -> int:
    conn.execute("UPDATE releases SET review_attempts=COALESCE(review_attempts,0)+1 WHERE id=?", (release_id,))
    conn.commit()
    return review_attempts(conn, release_id)

def park_for_review(conn, release_id, reason, detail, review_input):
    """Queue a flagged release for a later LLM review. The review input is kept (compressed) so the
    review doesn't depend on npm still hosting the tarball; it is dropped once a verdict lands."""
    conn.execute("UPDATE releases SET stage='pending_review', pending_reason=?, pending_detail=?, "
                 "review_input=?, review_input_chars=? WHERE id=?",
                 (reason, detail, zlib.compress(review_input.encode()), len(review_input), release_id))
    conn.commit()

def clear_pending(conn, release_id):
    conn.execute("UPDATE releases SET pending_reason=NULL, pending_detail=NULL, review_input=NULL, "
                 "review_input_chars=NULL WHERE id=?",
                 (release_id,))
    conn.commit()

def pending_reviews(conn, reasons=None, max_chars=None):
    sql = ("SELECT id AS release_id, package, version, serial, triage_score, triage_rules, pending_reason, "
           "pending_detail, COALESCE(review_attempts,0) AS review_attempts, review_input "
           "FROM releases WHERE stage='pending_review'")
    params = list(reasons or [])
    if params:
        sql += f" AND pending_reason IN ({','.join('?' * len(params))})"
    if max_chars is not None:
        sql += " AND review_input_chars <= ?"
        params.append(max_chars)
    return conn.execute(sql + " ORDER BY id", params).fetchall()

def review_input(row) -> str:
    return zlib.decompress(row["review_input"]).decode()

FEED_RETRIES = 3     # retries after the first failure, then the release is given up on (visibly)


def note_feed_failure(conn, package, seq):
    now = datetime.datetime.now(datetime.UTC).isoformat()
    conn.execute("INSERT INTO feed_retry(package, seq, attempts, updated_at) VALUES(?,?,1,?) "
                 "ON CONFLICT(package) DO UPDATE SET attempts=attempts+1, updated_at=excluded.updated_at, "
                 "gave_up=(attempts+1 > ?)", (package, seq, now, FEED_RETRIES))
    conn.commit()

def clear_feed_retry(conn, package):
    conn.execute("DELETE FROM feed_retry WHERE package=? AND gave_up=0", (package,))
    conn.commit()

def feed_retries_due(conn, limit=20):
    return conn.execute("SELECT package, seq, attempts FROM feed_retry WHERE gave_up=0 ORDER BY seq LIMIT ?",
                        (limit,)).fetchall()

def feed_retry_counts(conn) -> dict:
    r = conn.execute("SELECT COALESCE(SUM(gave_up=0),0), COALESCE(SUM(gave_up=1),0) FROM feed_retry").fetchone()
    return {"retrying": r[0], "gave_up": r[1]}

def _baselined(conn) -> set:
    return {r[0] for r in conn.execute("SELECT package FROM watchlist_baseline WHERE result != 'fetch_failed'")}

def baseline_pending(conn, names, limit):
    """Listed packages whose latest release hasn't been reviewed yet (fetch_failed ones are retried)."""
    return sorted(set(names) - _baselined(conn))[:limit]

def mark_baseline(conn, package, result) -> str:
    """Record a baseline outcome. fetch_failed is retried FEED_RETRIES times, then recorded as gave_up (done),
    so one package that never downloads can't keep the baseline open forever. Returns the stored result."""
    row = conn.execute("SELECT attempts FROM watchlist_baseline WHERE package=?", (package,)).fetchone()
    attempts = (row[0] or 0) if row else 0
    if result == "fetch_failed":
        attempts += 1
        if attempts > FEED_RETRIES:
            result = "gave_up"
    conn.execute("INSERT INTO watchlist_baseline(package, result, done_at, attempts) VALUES(?,?,?,?) "
                 "ON CONFLICT(package) DO UPDATE SET result=excluded.result, done_at=excluded.done_at, "
                 "attempts=excluded.attempts", (package, result, _now(), attempts))
    conn.commit()
    return result

def baseline_counts(conn, names) -> tuple:
    names = set(names)
    return len(names & _baselined(conn)), len(names)

def record_removed(conn, release_id, reason, at):
    conn.execute("UPDATE releases SET stage='removed_before_scan', removed_reason=?, removed_at=? WHERE id=?",
                 (reason, at, release_id))
    conn.commit()

def removed_counts(conn) -> dict:
    return dict(conn.execute("SELECT removed_reason, count(*) FROM releases WHERE stage='removed_before_scan' "
                             "GROUP BY removed_reason").fetchall())

def pending_review_counts(conn) -> dict:
    return dict(conn.execute("SELECT pending_reason, count(*) FROM releases WHERE stage='pending_review' "
                             "GROUP BY pending_reason").fetchall())

def get_reviewer_stats(conn, endpoint, model):
    row = conn.execute("SELECT tok_s, chars_per_token, samples, state, detail, paused_until, slow_streak "
                       "FROM reviewer_stats WHERE endpoint=? AND model=?", (endpoint, model)).fetchone()
    return dict(row) if row else None

def save_reviewer_stats(conn, endpoint, model, *, tok_s, chars_per_token, samples, state, detail,
                        paused_until, slow_streak):
    conn.execute("""INSERT INTO reviewer_stats(endpoint, model, tok_s, chars_per_token, samples, state, detail,
                        paused_until, slow_streak, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(endpoint, model) DO UPDATE SET tok_s=excluded.tok_s,
                        chars_per_token=excluded.chars_per_token, samples=excluded.samples,
                        state=excluded.state, detail=excluded.detail, paused_until=excluded.paused_until,
                        slow_streak=excluded.slow_streak, updated_at=excluded.updated_at""",
                 (endpoint, model, tok_s, chars_per_token, samples, state, detail, paused_until,
                  slow_streak, _now()))
    conn.commit()

def update_stage(conn, release_id, stage, score=None, rules=None):
    sets = ["stage=?"]; params = [stage]
    if score is not None:
        sets.append("triage_score=?"); params.append(score)
    if rules is not None:
        sets.append("triage_rules=?"); params.append(rules)
    params.append(release_id)
    conn.execute(f"UPDATE releases SET {', '.join(sets)} WHERE id=?", params)
    conn.commit()

def record_alert(conn, release_id, classification, score, fired_rules_json, dedupe_key) -> bool:
    cur = conn.execute("""INSERT OR IGNORE INTO alerts
        (release_id,classification,score,fired_rules,dedupe_key,delivery_status,sent_at)
        VALUES(?,?,?,?,?,?,?)""",
        (release_id, classification, score, fired_rules_json, dedupe_key, "pending", _now()))
    conn.commit()
    return cur.rowcount == 1

def record_verdict(conn, release_id, verdict) -> int:
    conn.execute("""INSERT INTO verdicts
        (release_id,classification,confidence,attack_type,reasoning,cited_hunk,model,urgent,created_at,
         runs_when,chain_source,chain_sink,review_tier)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(release_id) DO UPDATE SET
          classification=excluded.classification, confidence=excluded.confidence,
          attack_type=excluded.attack_type, reasoning=excluded.reasoning,
          cited_hunk=excluded.cited_hunk, model=excluded.model,
          urgent=excluded.urgent, created_at=excluded.created_at,
          runs_when=excluded.runs_when, chain_source=excluded.chain_source, chain_sink=excluded.chain_sink,
          review_tier=excluded.review_tier""",
        (release_id, verdict.classification, verdict.confidence, verdict.attack_type,
         verdict.reasoning, verdict.cited_hunk, verdict.model, int(verdict.urgent), _now(),
         getattr(verdict, "runs_when", None), getattr(verdict, "chain_source", None),
         getattr(verdict, "chain_sink", None), getattr(verdict, "review_tier", None)))
    conn.commit()
    return conn.execute("SELECT id FROM verdicts WHERE release_id=?", (release_id,)).fetchone()[0]

def scan_attempts(conn, package, version) -> int:
    """Failed download/processing attempts so far for a release (0 if it has none or isn't recorded)."""
    row = conn.execute("SELECT scan_attempts FROM releases WHERE package=? AND version=?",
                       (package, version)).fetchone()
    return (row[0] or 0) if row else 0

def bump_scan_attempts(conn, release_id) -> int:
    conn.execute("UPDATE releases SET scan_attempts=COALESCE(scan_attempts,0)+1 WHERE id=?", (release_id,))
    conn.commit()
    return conn.execute("SELECT scan_attempts FROM releases WHERE id=?", (release_id,)).fetchone()[0]

def scan_retries_due(conn, limit=20):
    """Releases whose download or processing failed on an earlier scan, oldest first."""
    return conn.execute("SELECT package, version, serial FROM releases WHERE stage='fetch_failed' "
                        "ORDER BY serial LIMIT ?", (limit,)).fetchall()

def get_stage(conn, package, version):
    row = conn.execute("SELECT stage FROM releases WHERE package=? AND version=?",
                       (package, version)).fetchone()
    return row[0] if row else None

def pending_adjudication(conn):
    return conn.execute(
        """SELECT r.id AS release_id, r.package, r.version, r.serial, r.triage_score, r.triage_rules,
                  r.evidence, r.stage,
                  v.classification, v.confidence, v.attack_type, v.reasoning, v.cited_hunk, v.model
           FROM releases r JOIN verdicts v ON v.release_id = r.id
           WHERE r.stage IN ('needs_adjudication', 'refused_to_extract', 'refused_to_fetch', 'scan_failed',
                             'reviewed_partial')
             AND v.human_label IS NULL
           ORDER BY r.id""").fetchall()

def all_verdicts(conn):
    return conn.execute(
        """SELECT r.id AS release_id, r.package, r.version, r.prior_version,
                  r.is_first_release, r.triage_score,
                  v.classification, v.confidence, v.attack_type, v.reasoning,
                  v.cited_hunk, v.model, v.urgent, v.created_at, v.human_label, v.human_note
           FROM releases r JOIN verdicts v ON v.release_id = r.id
           ORDER BY CASE COALESCE(v.human_label, v.classification) WHEN 'malicious' THEN 0
                    WHEN 'suspicious' THEN 1 ELSE 2 END, r.id DESC""").fetchall()

def adjudicate(conn, release_id, label, note):
    conn.execute("UPDATE verdicts SET human_label=?, human_note=?, adjudicated_at=? WHERE release_id=?",
                 (label, note, _now(), release_id))
    conn.commit()
    return conn.execute("SELECT package, version, serial, triage_score, triage_rules "
                        "FROM releases WHERE id=?", (release_id,)).fetchone()

def prior_version(conn, package, version):
    row = conn.execute("""SELECT version FROM releases WHERE package=? AND version<?
        ORDER BY serial DESC LIMIT 1""", (package, version)).fetchone()
    return row[0] if row else None
