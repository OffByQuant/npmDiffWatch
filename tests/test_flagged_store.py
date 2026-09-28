import dataclasses
import os

from npmdiffwatch import flagged, orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import Download, Verdict


def _cfg(tmp_path, enabled=True):
    inv = dataclasses.replace(Config().investigator, enabled=enabled)
    return dataclasses.replace(Config(), db_path=tmp_path / "d.sqlite", lock_path=tmp_path / "l", investigator=inv)


def _conn(cfg):
    c = store.connect(cfg); store.init_schema(c); return c


def _dl(**kw):
    return Download("p", "1.0.1", "1.0.0", False, b"NEW", b"PRIOR", **kw)


def test_capture_stores_both_tarballs_as_private_files(tmp_path):
    cfg = _cfg(tmp_path); conn = _conn(cfg)
    rid = store.record_release(conn, "p", "1.0.1", 7, False, None, "tgz")
    assert flagged.capture(cfg, conn, rid, download=lambda c, rel: _dl()) == "stored"
    row = store.flagged_get(conn, rid)
    assert open(row["new_path"], "rb").read() == b"NEW" and open(row["prior_path"], "rb").read() == b"PRIOR"
    assert oct(os.stat(row["new_path"]).st_mode & 0o777) == "0o600"
    assert flagged.load(cfg, conn, rid).new_blob == b"NEW"


def test_capture_twice_keeps_the_first(tmp_path):
    cfg = _cfg(tmp_path); conn = _conn(cfg)
    rid = store.record_release(conn, "p", "1.0.1", 7, False, None, "tgz")
    flagged.capture(cfg, conn, rid, download=lambda c, rel: _dl())
    assert flagged.capture(cfg, conn, rid, download=lambda c, rel: _dl()) == "exists"


def test_a_release_gone_from_npm_is_not_stored(tmp_path):
    cfg = _cfg(tmp_path); conn = _conn(cfg)
    rid = store.record_release(conn, "p", "1.0.1", 7, False, None, "tgz")
    assert flagged.capture(cfg, conn, rid, download=lambda c, rel: None) == "gone"
    assert store.flagged_get(conn, rid) is None


def test_a_failed_download_is_reported_not_raised(tmp_path):
    cfg = _cfg(tmp_path); conn = _conn(cfg)
    rid = store.record_release(conn, "p", "1.0.1", 7, False, None, "tgz")
    def boom(c, rel): raise OSError("reset")
    assert flagged.capture(cfg, conn, rid, download=boom).startswith("failed: ")


def test_a_malicious_verdict_captures_only_when_the_investigator_is_on(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(flagged, "capture", lambda cfg, conn, rid, **k: calls.append(rid) or "stored")
    for enabled in (False, True):
        cfg = _cfg(tmp_path / str(enabled), enabled); conn = _conn(cfg)
        rid = store.record_release(conn, "p", "1.0.1", 7, False, None, "tgz")
        orchestrator._record(cfg, conn, rid, Verdict("p", "1.0.1", "malicious", 0.0, [], True), 0.0)
    assert len(calls) == 1


def test_prune_keeps_malicious_labels_and_drops_benign_and_old(tmp_path):
    cfg = _cfg(tmp_path); conn = _conn(cfg)
    rids = [store.record_release(conn, "p", v, i, False, None, "tgz") for i, v in enumerate(("1", "2", "3"))]
    for r in rids:
        store.record_verdict(conn, r, Verdict("p", "x", "malicious", 0.0, [], True))
        flagged.capture(cfg, conn, r, download=lambda c, rel: _dl())
    store.adjudicate(conn, rids[0], "malicious", "")
    store.adjudicate(conn, rids[1], "benign", "")
    conn.execute("UPDATE flagged_packages SET stored_at='2000-01-01T00:00:00+00:00' WHERE release_id IN (?,?)",
                 (rids[0], rids[2])); conn.commit()
    flagged.prune(cfg, conn)
    assert [r["release_id"] for r in store.flagged_all(conn)] == [rids[0]]


def test_prune_evicts_the_oldest_unlabelled_over_the_size_cap(tmp_path):
    inv = dataclasses.replace(Config().investigator, enabled=True, flagged_max_gb=10 / 1e9)   # 10 bytes
    cfg = dataclasses.replace(_cfg(tmp_path), investigator=inv); conn = _conn(cfg)
    rids = [store.record_release(conn, "p", v, i, False, None, "tgz") for i, v in enumerate(("1", "2"))]
    for r in rids:
        store.record_verdict(conn, r, Verdict("p", "x", "malicious", 0.0, [], True))
        flagged.capture(cfg, conn, r, download=lambda c, rel: _dl())      # 8 bytes each
    flagged.prune(cfg, conn)
    assert [r["release_id"] for r in store.flagged_all(conn)] == [rids[1]]
