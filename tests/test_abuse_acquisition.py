from dataclasses import replace
import json

from npmdiffwatch import abuse_acquisition as acquisition, abuse_coordinator as coordinator, fetcher, store
from npmdiffwatch.models import NewRelease
from tests.test_abuse_live import config, download


def first_failure(tmp_path, result=None):
    cfg, dl = config(tmp_path), download()
    conn = store.connect(cfg); store.init_schema(conn)
    coordinator.accept_fetch(cfg, conn, NewRelease(dl.package, dl.version, 10),
        result if result is not None else fetcher.MetadataUnavailable("registry temporarily unavailable"))
    return cfg, dl, conn


def test_acquisition_retries_have_durable_four_attempt_ceiling_and_no_threat(monkeypatch, tmp_path):
    cfg, dl, conn = first_failure(tmp_path)
    calls = []

    def unavailable(*args, **kwargs):
        calls.append(kwargs)
        raise fetcher.MetadataUnavailable("still unavailable")

    monkeypatch.setattr(fetcher, "download", unavailable)
    clock = [10**12]
    for _ in range(3):
        assert acquisition.retry_due(cfg, conn, coordinator.accept_fetch, clock=lambda: clock[0]) == 1
        clock[0] += 1000
    assert acquisition.retry_due(cfg, conn, coordinator.accept_fetch, clock=lambda: clock[0]) == 0
    assert len(calls) == 3
    assert tuple(conn.execute("SELECT attempts,state FROM abuse_acquisitions_v1").fetchone()) == (4, "completed")
    assert store.all_verdicts(conn)[0]["abuse_result"]["status"] == "review_failed"
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM abuse_job_events_v1 WHERE kind='acquisition_failure'").fetchone()[0] == 4
    conn.close()


def test_first_successful_pair_is_pinned_before_model_queue(monkeypatch, tmp_path):
    cfg, dl, conn = first_failure(tmp_path)
    monkeypatch.setattr(fetcher, "download", lambda *args, **kwargs: dl)
    assert acquisition.retry_due(cfg, conn, coordinator.accept_fetch, clock=lambda: 10**12) == 1
    row = conn.execute("SELECT identity_json,new_blob,prior_blob FROM abuse_jobs_v1").fetchone()
    assert json.loads(row[0])["prior_version"] == "1"
    assert tuple(row[1:]) == (dl.new_blob, dl.prior_blob)
    assert conn.execute("SELECT prior_version FROM releases").fetchone()[0] == "1"
    assert conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0] == 0
    conn.close()


def test_partial_pair_retry_cannot_silently_substitute_current_bytes(monkeypatch, tmp_path):
    dl = download()
    cfg, _, conn = first_failure(tmp_path, replace(dl, prior_blob=None))
    seen = []

    def changed(*args, **kwargs):
        seen.append(kwargs)
        return replace(dl, new_blob=b"a-different-current-payload")

    monkeypatch.setattr(fetcher, "download", changed)
    assert acquisition.retry_due(cfg, conn, coordinator.accept_fetch, clock=lambda: 10**12) == 1
    assert seen == [{"pinned_prior": "1"}]
    assert conn.execute("SELECT COUNT(*) FROM abuse_jobs_v1").fetchone()[0] == 0
    row = store.all_verdicts(conn)[0]["abuse_result"]
    assert row["status"] == "review_failed" and "cannot be substituted" in row["error"]
    conn.close()


def test_security_refusal_is_not_admitted_to_acquisition_retry_lane(tmp_path):
    cfg, dl, conn = first_failure(tmp_path, fetcher.RefusedToFetch("quarantined"))
    assert conn.execute("SELECT COUNT(*) FROM abuse_acquisitions_v1").fetchone()[0] == 0
    assert store.all_verdicts(conn)[0]["abuse_result"]["status"] == "review_failed"
    conn.close()


def test_expired_last_acquisition_lease_is_visible_and_never_gets_fresh_attempts(monkeypatch, tmp_path):
    cfg, dl, conn = first_failure(tmp_path)
    conn.execute("UPDATE abuse_acquisitions_v1 SET attempts=4,state='running',owner='crashed',lease_until=1")
    conn.commit()
    monkeypatch.setattr(fetcher, "download", lambda *a, **k: (_ for _ in ()).throw(AssertionError("retry ceiling reset")))
    assert acquisition.retry_due(cfg, conn, coordinator.accept_fetch, clock=lambda: 10**12) == 0
    assert tuple(conn.execute("SELECT attempts,state FROM abuse_acquisitions_v1").fetchone()) == (4, "completed")
    assert store.all_verdicts(conn)[0]["abuse_result"]["status"] == "review_failed"
    conn.close()
