"""The scan database must not grow without bound: evidence is compressed, and kept only for releases a person
may still act on (not for releases reviewed benign or never escalated)."""
import dataclasses
import datetime

from npmdiffwatch import orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import Verdict

_EV = "--- file: a.js ---\n" + "+ some flagged code line\n" * 2000


def _db(tmp_path, **over):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", **over)
    conn = store.connect(cfg); store.init_schema(conn)
    return cfg, conn


def _raw(conn, rid):
    return conn.execute("SELECT evidence FROM releases WHERE id=?", (rid,)).fetchone()[0]


def test_evidence_is_stored_compressed_and_read_back_as_text(tmp_path):
    _, conn = _db(tmp_path)
    rid = store.record_release(conn, "p", "1.0.0", 1, False, None, "tgz")
    store.update_evidence(conn, rid, _EV)
    assert isinstance(_raw(conn, rid), bytes) and len(_raw(conn, rid)) < len(_EV) / 4
    assert store.get_evidence(conn, rid) == _EV


def test_evidence_written_as_plain_text_by_older_versions_still_reads(tmp_path):
    _, conn = _db(tmp_path)
    rid = store.record_release(conn, "p", "1.0.0", 1, False, None, "tgz")
    conn.execute("UPDATE releases SET evidence=? WHERE id=?", (_EV, rid)); conn.commit()
    assert store.get_evidence(conn, rid) == _EV


def test_a_benign_verdict_drops_the_evidence_and_a_flagged_one_keeps_it(tmp_path):
    cfg, conn = _db(tmp_path)
    ids = {}
    for cls in ("benign", "suspicious", "malicious"):
        ids[cls] = store.record_release(conn, cls, "1.0.0", 1, False, None, "tgz")
        store.update_evidence(conn, ids[cls], _EV)
        orchestrator._record(cfg, conn, ids[cls], Verdict(cls, "1.0.0", cls, 60.0, [], False, confidence=0.9,
                             attack_type="none", reasoning="r", cited_hunk="", model="m"), 60.0)
    assert store.get_evidence(conn, ids["benign"]) is None
    assert store.get_evidence(conn, ids["suspicious"]) == _EV == store.get_evidence(conn, ids["malicious"])


def _old(conn, pkg, ver, days, **cols):
    rid = store.record_release(conn, pkg, ver, 1, False, None, "tgz")
    when = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)).isoformat()
    conn.execute("UPDATE releases SET processed_at=?, stage=? WHERE id=?", (when, cols.get("stage", "triaged"), rid))
    if "evidence" in cols:
        conn.execute("UPDATE releases SET evidence=? WHERE id=?", (cols["evidence"], rid))
    conn.commit()
    return rid


def test_prune_compresses_legacy_evidence_and_drops_what_nobody_needs(tmp_path):
    cfg, conn = _db(tmp_path)
    flagged = _old(conn, "bad", "1.0.0", 1, stage="needs_adjudication", evidence=_EV)
    store.record_verdict(conn, flagged, Verdict("bad", "1.0.0", "suspicious", 60.0, [], False, confidence=0.5,
                                                attack_type="none", reasoning="r", cited_hunk="", model="m"))
    below = _old(conn, "quiet", "1.0.0", 1, stage="triaged", evidence=_EV)          # never escalated
    cleared = _old(conn, "fine", "1.0.0", 1, stage="reviewed", evidence=_EV)
    store.record_verdict(conn, cleared, Verdict("fine", "1.0.0", "benign", 60.0, [], False, confidence=0.9,
                                                attack_type="none", reasoning="r", cited_hunk="", model="m"))
    store.prune(conn, retention_days=90)
    assert isinstance(_raw(conn, flagged), bytes) and store.get_evidence(conn, flagged) == _EV
    assert _raw(conn, below) is None and _raw(conn, cleared) is None


def test_retention_keeps_findings_queues_and_the_newest_release_of_each_package(tmp_path):
    cfg, conn = _db(tmp_path)
    old_plain = _old(conn, "lib", "1.0.0", 120)
    newest = _old(conn, "lib", "1.1.0", 120)                      # still the newest of its package
    recent = _old(conn, "other", "1.0.0", 10)
    old_other = _old(conn, "other", "0.9.0", 120)
    queued = _old(conn, "q", "1.0.0", 120, stage="pending_review")
    _old(conn, "q", "1.1.0", 1)
    flagged = _old(conn, "bad", "1.0.0", 120, stage="reviewed")
    store.record_verdict(conn, flagged, Verdict("bad", "1.0.0", "malicious", 90.0, [], True, confidence=1.0,
                                                attack_type="dropper", reasoning="r", cited_hunk="", model="m"))
    _old(conn, "bad", "1.1.0", 1)
    store.prune(conn, retention_days=90)
    left = {r[0] for r in conn.execute("SELECT id FROM releases")}
    assert old_plain not in left and old_other not in left
    assert {newest, recent, queued, flagged} <= left


def test_retention_zero_keeps_everything(tmp_path):
    cfg, conn = _db(tmp_path)
    old = _old(conn, "lib", "1.0.0", 400)
    _old(conn, "lib", "1.1.0", 1)
    store.prune(conn, retention_days=0)
    assert conn.execute("SELECT count(*) FROM releases WHERE id=?", (old,)).fetchone()[0] == 1


def test_prune_runs_by_itself_at_most_once_a_day(tmp_path):
    cfg, conn = _db(tmp_path)
    t0 = 1_000_000.0
    assert store.maybe_prune(conn, retention_days=90, every_s=86_400, now=t0) is True
    assert store.maybe_prune(conn, retention_days=90, every_s=86_400, now=t0 + 3_600) is False
    assert store.maybe_prune(conn, retention_days=90, every_s=86_400, now=t0 + 86_401) is True


def test_config_defaults():
    assert Config().retention_days == 90 and Config().prune_every_hours == 24.0


def test_a_release_below_the_review_threshold_stores_no_evidence(tmp_path, monkeypatch):
    from pathlib import Path
    from npmdiffwatch import engine, reviewer
    from npmdiffwatch.models import ArtifactSet, FiredRule, NewRelease, TriageResult
    cfg, conn = _db(tmp_path, rules_dir=Path("rules/community"), reviewer_enabled=False)
    monkeypatch.setattr(engine, "triage", lambda *a, **k: TriageResult(10.0, [FiredRule("js-eval", 10.0, "a.js", (1, 1))], False))
    monkeypatch.setattr(reviewer, "build_evidence", lambda *a, **k: _EV)
    art = ArtifactSet("quiet", "1.0.1", "1.0.0", "tgz", {"a.js": b"eval(x)\n"}, {"a.js": b"x\n"}, {})
    orchestrator._process_fetched(cfg, conn, None, orchestrator._load_ruleset(cfg), NewRelease("quiet", "1.0.1", 5), art)
    assert conn.execute("SELECT evidence FROM releases WHERE package='quiet'").fetchone()[0] is None
