"""Local takedown dashboard: render persisted verdicts as a self-contained HTML
page (one card per reviewed package) with a direct npmjs link and, for flagged
packages, a one-click "Report malware on npm" action.

Pure functions only — no DB, no I/O. SECURITY: every string here is derived from
untrusted package content (name, version, cited code, LLM reasoning quoting code),
so all of it is html.escape'd and all URL path segments are urllib.parse.quote'd.
An XSS in the security dashboard would be a self-own.
"""
import html
from urllib.parse import quote

from . import guard as guard_mod

_NPM = "https://www.npmjs.com/package"
_FLAGGED = ("malicious", "suspicious")


def npm_package_url(package: str) -> str:
    # scoped names (@scope/pkg) keep @ and / as path; everything else is encoded.
    return f"{_NPM}/{quote(package, safe='@/')}"


def npm_version_url(package: str, version: str) -> str:
    return f"{npm_package_url(package)}/v/{quote(version, safe='')}"


def humanize_age(seconds) -> str:
    s = int(seconds)
    if s < 60:
        return "just now"
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if s >= size:
            n = s // size
            return f"{n} {unit}{'s' if n != 1 else ''} ago"
    return "just now"


def _conf_pct(conf) -> str:
    if conf is None:
        return "?"
    try:
        c = float(conf)
    except (TypeError, ValueError):
        return "?"
    if c <= 1.0:
        c *= 100.0
    return f"{int(round(c))}%"


def effective_class(row) -> str:
    """Your adjudication, when you've recorded one, overrides the model's call."""
    return (row.get("human_label") or row.get("classification") or "").lower()


def unscanned(row) -> bool:
    """A release nobody looked at: stored as a model="none" placeholder so it stays queued for a person. It is
    not a judgement, so it is never shown as flagged unless you have labelled it yourself."""
    return (row.get("model") or "") == "none" and not row.get("human_label")


def _flagged(row) -> bool:
    return not unscanned(row) and effective_class(row) in _FLAGGED


def counts(rows) -> dict:
    """One set of numbers for the header and the status strip."""
    rows = [dict(r) for r in rows]
    return {"releases": len(rows),
            "model_reviewed": sum(1 for r in rows if (r.get("model") or "") != "none"),
            "flagged": sum(1 for r in rows if _flagged(r)),
            "unscanned": sum(1 for r in rows if unscanned(r))}


def _card(row: dict) -> str:
    cls = "unscanned" if unscanned(row) else (effective_class(row) or "benign")
    pkg = row.get("package") or ""
    ver = row.get("version") or ""
    e = html.escape
    flagged = _flagged(row)
    attack = row.get("attack_type") or ""
    attack_html = (f'<span class="k">attack</span><span class="v">{e(attack)}</span>'
                   if attack and attack != "none" else "")
    actions = [f'<a class="btn view" href="{e(npm_version_url(pkg, ver))}" '
               f'target="_blank" rel="noopener noreferrer">View on npm ↗</a>']
    if flagged:
        actions.insert(0, f'<a class="btn report" href="{e(npm_package_url(pkg))}" '
                       f'target="_blank" rel="noopener noreferrer">Report malware on npm ↗</a>')
    reasoning = row.get("reasoning") or ""
    cited = row.get("cited_hunk") or ""
    reason_html = f'<div class="reason">{e(reasoning)}</div>' if reasoning else ""
    cited_html = (f'<div class="cited"><span class="k">cited</span> {e(cited)}</div>'
                  if cited else "")
    human = row.get("human_label")
    human_html = ""
    if human:
        note = row.get("human_note") or ""
        model_cls = (row.get("classification") or "?").lower()
        human_html = (f'<div class="human">your verdict: {e(human)}{" — " + e(note) if note else ""}'
                      f'{f" · model said {e(model_cls)}" if model_cls != human.lower() else ""}</div>')
    triage = row.get("triage_score")
    triage_html = (f'<span class="k">triage</span><span class="v">{int(triage)}</span>'
                   if triage is not None else "")
    return f"""<div class="card {e(cls)}">
  <div class="head">
    <div class="pkg">{e(pkg)} <span class="ver">{e(ver)}</span></div>
    <div class="badge {e(cls)}">{"not scanned" if cls == "unscanned" else e(cls)}</div>
  </div>
  <div class="meta">
    {triage_html}
    {"" if cls == "unscanned" else f'<span class="k">confidence</span><span class="v">{_conf_pct(row.get("confidence"))}</span>'}
    {attack_html}
    <span class="k">model</span><span class="v">{e(row.get('model') or '?')}</span>
  </div>
  {human_html}
  {reason_html}
  {cited_html}
  <div class="actions">{''.join(actions)}</div>
</div>"""


_STYLE = """
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--ink:#e6edf3;--muted:#8b949e;
  --red:#f85149;--amber:#d29922;--green:#3fb950;--mono:'SF Mono',ui-monospace,Menlo,monospace}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:40px;max-width:1100px;margin:0 auto}
h1{font-size:24px;letter-spacing:-.3px}.sub{color:var(--muted);margin:6px 0 28px;font-size:15px}
.card{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:12px;padding:20px 22px;margin-bottom:16px}
.card.malicious{border-left-color:var(--red)}.card.suspicious{border-left-color:var(--amber)}
.card.benign{border-left-color:#21372a;opacity:.78}.card.unscanned{border-left-color:var(--muted)}
.head{display:flex;justify-content:space-between;align-items:center;gap:12px}
.pkg{font-family:var(--mono);font-size:18px;font-weight:600}.ver{color:var(--muted);font-size:15px}
.badge{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;padding:5px 12px;border-radius:999px}
.badge.malicious{background:#2d1416;border:1px solid var(--red);color:var(--red)}
.badge.suspicious{background:#241c08;border:1px solid var(--amber);color:var(--amber)}
.badge.benign{background:#0f2417;border:1px solid #2c5138;color:var(--green)}
.badge.unscanned{background:#1c2128;border:1px solid var(--line);color:var(--muted)}
.meta{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;margin:14px 0;font-size:13px}
.meta .k{color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-size:11px}
.meta .v{font-family:var(--mono);margin-right:8px}
.reason{background:#0d1117;border:1px solid var(--line);border-radius:8px;padding:12px 14px;font-size:14px;line-height:1.55;color:#c9d1d9}
.human{margin-bottom:10px;font-size:13px;color:var(--ink);font-weight:600}
.cited{margin-top:8px;font-size:12.5px;color:var(--muted);font-family:var(--mono)}
.actions{display:flex;gap:10px;margin-top:14px}
.btn{font-size:13px;font-weight:600;text-decoration:none;padding:8px 14px;border-radius:8px;border:1px solid var(--line);color:var(--ink)}
.btn.report{background:#2d1416;border-color:var(--red);color:var(--red)}
.btn.view{color:#58a6ff}
.status{display:flex;flex-wrap:wrap;gap:8px 22px;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 18px;margin-bottom:24px;font-size:13px;color:var(--muted)}
.status .stat{display:flex;align-items:center;gap:7px}
.status code{font-family:var(--mono);color:var(--ink);font-size:12.5px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.dot.ok{background:var(--green);box-shadow:0 0 6px var(--green)}
.dot.down{background:var(--red);box-shadow:0 0 6px var(--red)}
.dot.idle{background:var(--muted)}
.empty{color:var(--muted);padding:40px;text-align:center}
footer{color:var(--muted);font-size:12.5px;margin-top:28px;text-align:center}
"""


def _rank(row) -> int:
    if unscanned(row):
        return 2
    return {"malicious": 0, "suspicious": 1}.get(effective_class(row), 3)


def _status_strip(status: dict) -> str:
    e = html.escape
    reach = status.get("model_reachable")
    if reach is True:
        dot, model_txt = "ok", "model reachable"
    elif reach is False:
        dot, model_txt = "down", "model unreachable"
    else:
        dot, model_txt = "idle", "model not probed"
    age = status.get("last_poll_age") or "never"
    if status.get("stale") and status.get("last_poll_age"):
        age += " (stale)"
    serial = status.get("last_serial")
    serial_txt = str(serial) if serial is not None else "—"
    pending = status.get("pending_review") or {}
    pending_txt = (f"{sum(pending.values())} pending LLM review ("
                   + ", ".join(f"{k}: {v}" for k, v in sorted(pending.items())) + ")") if pending else ""
    removed = status.get("removed") or {}
    removed_txt = (f"{sum(removed.values())} removed before scan ("
                   + ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in sorted(removed.items()))
                   + ")") if removed else ""
    g = status.get("guard")
    guard_txt = guard_mod.describe(g) if g else ""
    w = status.get("watchlist")
    watch_txt = f"watchlist: {w['describe']} · baseline {w['done']:,}/{w['total']:,}" if w else ""
    return f"""<div class="status">
  <span class="stat"><span class="dot {dot}"></span>{e(model_txt)} <code>{e(status.get('reviewer') or '?')}</code></span>
  <span class="stat">last poll: {e(age)}</span>
  <span class="stat">cursor: {e(serial_txt)}</span>
  <span class="stat">{int(status.get('releases_total') or 0)} releases · {int(status.get('verdicts_total') or 0)} reviewed by the model · {int(status.get('flagged_total') or 0)} flagged{f" · {int(status['unscanned_total'])} not scanned — need manual review" if status.get('unscanned_total') else ""}</span>
{f'  <span class="stat">{e(pending_txt)}</span>' + chr(10) if pending_txt else ''}{f'  <span class="stat">{e(removed_txt)}</span>' + chr(10) if removed_txt else ''}{f'  <span class="stat">{e(guard_txt)}</span>' + chr(10) if guard_txt else ''}{f'  <span class="stat">{e(watch_txt)}</span>' + chr(10) if watch_txt else ''}</div>"""


def render_dashboard(rows, status: dict = None, generated_at: str = "") -> str:
    # flagged-first, independent of caller ordering (stable within each class).
    rows = sorted((dict(r) for r in rows), key=_rank)
    c = counts(rows)
    cards = "\n".join(_card(dict(r)) for r in rows) if rows else \
        '<div class="empty">No verdicts yet. Run <code>npmdiffwatch run</code> first.</div>'
    gen = f" · generated {html.escape(generated_at)}" if generated_at else ""
    strip = _status_strip(status) if status else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NpmDiffWatch — verdicts</title><style>{_STYLE}</style></head><body>
<h1>NpmDiffWatch — supply-chain verdicts</h1>
<div class="sub">{c["model_reviewed"]} package(s) reviewed by the model · {c["flagged"]} flagged for review{f" · {c['unscanned']} not scanned — need manual review" if c["unscanned"] else ""}{gen}</div>
{strip}
{cards}
<footer>Flagged a real attack? Open it on npm and use “Report malware” for takedown. Static, no-execution analysis · 100% local.</footer>
</body></html>"""
