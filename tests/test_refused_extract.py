"""A tarball the fetcher refused to unpack was never looked at. Oversized or malformed archives can hide a
payload from scanners, so the release is not dropped: the alert says why it was refused, and it waits in
`pending` for a manual review."""
import dataclasses
from pathlib import Path

from npmdiffwatch import fetcher, notifier, orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import NewRelease


def _cfg(tmp_path):
    return dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l",
                               cache_dir=tmp_path / "c", reviewer_enabled=False, rules_dir=Path("rules/community"))


def _refuse(tmp_path, reason, capsys):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    rel = NewRelease("big-native-linux-x64", "0.1.0", 7)
    orchestrator._process_fetched(cfg, conn, None, None, rel, fetcher.RefusedToExtract(reason))
    return cfg, conn, capsys.readouterr().out


def test_alert_names_the_refusal_and_asks_for_a_manual_review(tmp_path, capsys):
    _, _, out = _refuse(tmp_path, "decompressed-size", capsys)
    assert "big-native-linux-x64 0.1.0" in out
    assert "decompressed-size" in out and "manual review" in out


def test_refused_release_waits_in_pending_without_a_refetch(tmp_path, capsys, monkeypatch):
    cfg, conn, _ = _refuse(tmp_path, "members", capsys)
    assert store.get_stage(conn, "big-native-linux-x64", "0.1.0") == "refused_to_extract"
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda *a: (_ for _ in ()).throw(AssertionError("refetched")))
    [item] = orchestrator.list_pending(cfg)
    assert item["package"] == "big-native-linux-x64" and "manual review" in item["reasoning"]
    assert "members" in item["reasoning"] and item["diff_text"] is None and "refused" in item["fetch_error"]


def test_refused_release_can_be_adjudicated(tmp_path, capsys, monkeypatch):
    cfg, conn, _ = _refuse(tmp_path, "total-size", capsys)
    monkeypatch.setattr(notifier, "post_webhook", lambda *a: True)
    rid = conn.execute("SELECT id FROM releases").fetchone()[0]
    assert len(orchestrator.list_pending(cfg)) == 1
    assert orchestrator.adjudicate(cfg, rid, "benign")["label"] == "benign"
    assert orchestrator.list_pending(cfg) == []
