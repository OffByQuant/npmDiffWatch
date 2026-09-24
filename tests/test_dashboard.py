"""Local takedown dashboard: pure HTML render + npm URL construction, and the
orchestrator export. Security-critical: untrusted package-derived strings must be
HTML-escaped (an XSS in the security dashboard is a self-own)."""
import dataclasses
from pathlib import Path

from npmdiffwatch import dashboard, orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import Verdict


def _row(package, version, classification, **kw):
    base = dict(release_id=1, package=package, version=version, prior_version=None,
                is_first_release=0, triage_score=100.0, classification=classification,
                confidence=1.0, attack_type="none", reasoning="", cited_hunk="",
                model="gemma", urgent=0, created_at="", human_label=None)
    base.update(kw)
    return base


def test_npm_version_url_scoped_package():
    assert dashboard.npm_version_url("@scope/pkg", "1.2.3") == \
        "https://www.npmjs.com/package/@scope/pkg/v/1.2.3"


def test_render_includes_version_url():
    html = dashboard.render_dashboard([_row("cool-logger", "2.4.1", "malicious")])
    assert "https://www.npmjs.com/package/cool-logger/v/2.4.1" in html


def test_render_flagged_has_report_link():
    html = dashboard.render_dashboard([_row("evil-pkg", "1.0.0", "malicious")])
    assert "https://www.npmjs.com/package/evil-pkg" in html
    assert "Report malware on npm" in html  # the report action button


def test_render_benign_has_no_report_link():
    html = dashboard.render_dashboard([_row("nice-pkg", "1.0.0", "benign")])
    assert "https://www.npmjs.com/package/nice-pkg/v/1.0.0" in html  # version link present
    assert "Report malware on npm" not in html  # no report action on a benign card


def test_render_escapes_untrusted_package_name():
    html = dashboard.render_dashboard([_row("<script>alert(1)</script>", "1.0.0", "benign")])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_orders_flagged_first():
    rows = [_row("benign-one", "1.0.0", "benign"),
            _row("malicious-one", "1.0.0", "malicious")]
    html = dashboard.render_dashboard(rows)
    assert html.index("malicious-one") < html.index("benign-one")


def _status(**kw):
    base = dict(last_serial=None, last_poll_age=None, stale=False, releases_total=0,
                verdicts_total=0, flagged_total=0, reviewer="x", model_reachable=None)
    base.update(kw)
    return base


def test_humanize_age():
    assert dashboard.humanize_age(5) == "just now"
    assert dashboard.humanize_age(180) == "3 minutes ago"
    assert dashboard.humanize_age(7200) == "2 hours ago"
    assert dashboard.humanize_age(172800) == "2 days ago"


def test_render_shows_status_counts():
    html = dashboard.render_dashboard([], status=_status(
        last_serial=999, last_poll_age="3 minutes ago", releases_total=42,
        verdicts_total=10, flagged_total=2, reviewer="127.0.0.1:8080", model_reachable=True))
    assert "42" in html and "3 minutes ago" in html and "127.0.0.1:8080" in html
    assert "999" in html  # cursor serial


def test_render_model_reachable_states():
    up = dashboard.render_dashboard([], status=_status(model_reachable=True))
    down = dashboard.render_dashboard([], status=_status(model_reachable=False))
    assert "reachable" in up.lower()
    assert "unreachable" in down.lower()


def test_render_status_endpoint_escaped():
    html = dashboard.render_dashboard([], status=_status(reviewer="<b>x</b>"))
    assert "<b>x</b>" not in html
    assert "&lt;b&gt;" in html


def _cfg(tmp_path) -> Config:
    return dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite",
                               lock_path=tmp_path / "run.lock", cache_dir=tmp_path / "cache",
                               reviewer_enabled=False)


def test_export_dashboard_writes_file(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "lodash", "4.17.21", 12345, False, "4.17.20", "tgz")
    v = Verdict("lodash", "4.17.21", "benign", 40.0, [], False,
                confidence=1.0, attack_type="none", reasoning="clean refactor", model="gemma")
    store.record_verdict(conn, rid, v)
    conn.close()

    out = orchestrator.export_dashboard(cfg)
    assert Path(out).exists()
    assert "lodash" in Path(out).read_text()


def test_export_dashboard_includes_status(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    store.set_last_serial(conn, 13579)
    rid = store.record_release(conn, "lodash", "4.17.21", 13579, False, "4.17.20", "tgz")
    store.record_verdict(conn, rid, Verdict("lodash", "4.17.21", "benign", 40.0, [], False,
                                            confidence=1.0, model="gemma"))
    conn.close()
    html = Path(orchestrator.export_dashboard(cfg)).read_text()
    assert "13579" in html  # cursor serial in the status strip


def test_render_shows_pending_llm_review_by_reason():
    html = dashboard.render_dashboard([], status=_status(
        pending_review={"too_large": 2, "endpoint_unreachable": 5}))
    assert "7 pending LLM review" in html
    assert "too_large: 2" in html and "endpoint_unreachable: 5" in html
