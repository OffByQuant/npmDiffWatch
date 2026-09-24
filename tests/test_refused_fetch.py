"""A tarball the fetcher refused to download was never looked at either: too big to download, or a package on
the quarantine list. Like a refused unpack, it alerts with the reason and waits in `pending` for a person."""
import dataclasses
from pathlib import Path

from npmdiffwatch import fetcher, orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import NewRelease


def _refuse(tmp_path, reason, capsys, package="huge-cli-linux-x64"):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l",
                              cache_dir=tmp_path / "c", reviewer_enabled=False, rules_dir=Path("rules/community"))
    conn = store.connect(cfg); store.init_schema(conn)
    orchestrator._process_fetched(cfg, conn, None, None, NewRelease(package, "0.2.0", 7),
                                  fetcher.RefusedToFetch(reason))
    return cfg, conn, capsys.readouterr().out


def test_an_oversized_download_alerts_with_the_reason_and_asks_for_a_manual_review(tmp_path, capsys):
    _, _, out = _refuse(tmp_path, "download-size", capsys)
    assert "huge-cli-linux-x64 0.2.0" in out
    assert "download-size" in out and "not downloaded" in out and "manual review" in out


def test_a_refused_download_waits_in_pending_without_a_refetch(tmp_path, capsys, monkeypatch):
    cfg, conn, _ = _refuse(tmp_path, "download-size", capsys)
    assert store.get_stage(conn, "huge-cli-linux-x64", "0.2.0") == "refused_to_fetch"
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda *a: (_ for _ in ()).throw(AssertionError("refetched")))
    [item] = orchestrator.list_pending(cfg)
    assert "manual review" in item["reasoning"] and item["diff_text"] is None and "not downloaded" in item["fetch_error"]


def test_a_quarantined_package_alerts_without_calling_it_malicious(tmp_path, capsys):
    _, _, out = _refuse(tmp_path, "quarantined: eslint-scope", capsys, package="eslint-scope")
    assert "eslint-scope 0.2.0" in out and "quarantine list" in out and "manual review" in out
    assert "[DIFFWATCH] malicious" not in out
