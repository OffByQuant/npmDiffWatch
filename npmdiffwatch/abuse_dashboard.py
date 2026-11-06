"""Pure HTML view for abuse-focused results; never changes stored verdicts."""
from collections import Counter
import html
from urllib.parse import quote

from .dashboard import npm_report_url


LABELS = {"no_abuse_found": "No abuse found in assessed behavior", "suspicious": "Suspicious — evidence-backed",
    "malicious": "Malicious — evidence-backed", "held": "Finding held — confirmation unresolved",
    "review_failed": "Processing error — no new verdict", "context_deferred": "Context review deferred",
    "historical": "Historical finding — awaiting new review", "unreviewed": "Not reviewed",
    "queued": "Queued for abuse review", "running": "Abuse review in progress"}


def state(row):
    if row.get("human_label"):
        return {"benign": "no_abuse_found", "malicious": "malicious", "suspicious": "suspicious"}.get(row["human_label"], "held")
    return row.get("abuse_result", {}).get("status", "unreviewed" if row.get("model") == "none" else "historical")


def render(rows, *, generated_at="", completed=0, total=None):
    rows = [dict(row) for row in rows]
    counts = Counter(state(row) for row in rows)
    def e(text):
        return html.escape(str(text), quote=True)
    ordered = sorted(rows, key=lambda row: ({"malicious": 0, "suspicious": 1, "held": 2, "review_failed": 3,
        "context_deferred": 4, "historical": 5, "unreviewed": 6, "no_abuse_found": 7}.get(state(row), 8), row.get("package", "")))
    cards = []
    for row in ordered:
        result, current = row.get("abuse_result", {}), state(row)
        candidate = result.get("candidate", {})
        reason = row.get("human_note") if row.get("human_label") else (result.get("adjudication", {}).get("reason")
            or candidate.get("reasoning") or result.get("error") or row.get("reasoning", ""))
        limitations = result.get("inspection_notes", [])
        original = row.get("original_classification", row.get("classification", "unknown"))
        refs = "; ".join(f"{q['role']}: {q['span']['path']} bytes {q['span']['start']}:{q['span']['end']}" for q in candidate.get("citations", []))
        url = f"https://www.npmjs.com/package/{quote(row.get('package', ''), safe='@/')}/v/{quote(row.get('version', ''), safe='')}"
        report = ""
        if current in ("suspicious", "malicious") and (row.get("human_label") or (
                result.get("mechanical_validated") and result.get("claim_check", {}).get("triggered"))):
            report = (f' · <a href="{e(npm_report_url(row.get("package", ""), row.get("version", "")))}" '
                      'target="_blank" rel="noopener noreferrer">Open npm report form</a>')
        cards.append(f'<article class="{e(current)}"><h2>{e(row.get("package", ""))} <small>{e(row.get("version", ""))}</small></h2>'
            f'<strong>{e(LABELS.get(current, current))}</strong>'
            f'<p class="meta">Original finding: {e(original)} · route: {e(result.get("route", "not run"))}'
            + (f' · worker: {e(result["workflow_state"])}' if result.get("workflow_state") else '')
            + f'{" · human decision retained" if row.get("human_label") else ""}</p>'
            f'<p>{e(reason or "No new assessment yet.")}</p>'
            f'<p class="meta">{e(refs)}</p>'
            + (f'<details><summary>Inspection notes (not threat evidence)</summary><p>{e("; ".join(limitations))}</p></details>' if limitations else '')
            + (f'<p class="meta">Unreviewed binary payloads: {e(result["binary_payload_count"])}</p>' if result.get("binary_payload_count") else '')
            + f'<a href="{e(url)}" target="_blank" rel="noopener noreferrer">View exact npm version</a>{report}</article>')
    summary = " · ".join(f"{LABELS.get(key, key)}: {value}" for key,value in sorted(counts.items()))
    progress = f"{completed} / {total} cases processed" if total is not None else f"{completed} cases processed"
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>NpmDiffWatch — abuse-focused review</title><style>'
        'body{background:#0d1117;color:#e6edf3;font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 20px}'
        'article{background:#161b22;border:1px solid #30363d;border-left:4px solid #526174;border-radius:10px;padding:18px;margin:16px 0}'
        '.malicious{border-left-color:#f85149}.suspicious,.held{border-left-color:#d29922}.no_abuse_found{border-left-color:#58a6ff}'
        'small,.meta{color:#8b949e;font-size:13px}p{white-space:pre-wrap;overflow-wrap:anywhere}h2{font:600 17px ui-monospace}a{color:#58a6ff}'
        '</style><h1>NpmDiffWatch — abuse-focused review</h1>'
        f'<p>{e(progress)} · {e(generated_at)}</p>'
        '<p>No abuse found means no abuse established in the assessed behavior—not a security certification. '
        'Inspection limitations and processing errors are not malware findings. Original findings remain in history.</p>'
        f'<p>{e(summary)}</p>' + ''.join(cards) + '</html>')
