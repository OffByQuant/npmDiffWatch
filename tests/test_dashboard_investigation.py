from npmdiffwatch import dashboard


def _row(**kw):
    base = {"package": "p", "version": "1.0.1", "classification": "malicious", "confidence": 1.0,
            "attack_type": "credential-exfil", "reasoning": "r", "cited_hunk": "", "model": "m",
            "human_label": None, "inv_status": None, "inv_outcome": None, "inv_verdict": None,
            "inv_reason": None, "inv_indicators": None, "inv_failed": 0}
    base.update(kw)
    return base


def test_confirmed_shows_the_line_and_the_report_button():
    html = dashboard.render_dashboard([_row(inv_status="ok", inv_outcome="confirmed", inv_verdict="malicious",
                                            inv_reason="both ends quoted", inv_indicators='["1.2.3.4"]')])
    assert "Investigated: malicious (confirmed)" in html and "1.2.3.4" in html and "Report malware on npm" in html


def test_disputed_card_keeps_report_button():
    html = dashboard.render_dashboard([_row(inv_status="ok", inv_outcome="disputed", inv_verdict="benign",
                                            inv_reason="build helper")])
    assert "Investigated: benign — was malicious (disputed)" in html and "Report malware on npm" in html


def test_contested_is_shown():
    html = dashboard.render_dashboard([_row(inv_status="ok", inv_outcome="contested", inv_verdict="malicious")])
    assert "contested" in html


def test_failed_runs_are_a_count_not_a_verdict():
    html = dashboard.render_dashboard([_row(inv_failed=2)])
    assert "2 investigation attempt(s) failed" in html and "Investigated:" not in html


def test_no_investigation_no_line():
    assert "Investigated:" not in dashboard.render_dashboard([_row()])
