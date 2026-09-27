"""Code, not the model, decides what an investigation's answer is allowed to change. The original verdict is
malicious; anything below it needs every runnable path examined and a quoted explanation, from the flagged
version's own files, or the original stands."""
from dataclasses import dataclass, field

from . import reviewer

_QUOTE = {"type": ["object", "null"], "properties": {
    "version": {"type": "string"}, "path": {"type": "string"}, "code": {"type": "string"}},
    "required": ["version", "path", "code"]}
ANSWER_SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign"]},
                   "confidence": {"type": "number", "default": 0.0},
                   "reason": {"type": "string"},
                   "chain_source": _QUOTE, "chain_sink": _QUOTE, "explanation": _QUOTE,
                   "indicators": {"type": "array", "items": {"type": "string"}, "default": []}},
    "required": ["verdict", "reason", "chain_source", "chain_sink", "explanation"],
}
SUBMIT_SPEC = {"name": "submit_answer",
               "description": "Submit the finished investigation. Call once, at the end.",
               "parameters": ANSWER_SCHEMA}


@dataclass
class Outcome:
    verdict: str
    outcome: str
    notes: list = field(default_factory=list)
    rejected_quotes: int = 0


def _quote_ok(q, ws, notes, *, code_only=False) -> bool:
    """A quote counts only if it is from the flagged version, in a file the agent read, with its lines in order."""
    if not isinstance(q, dict) or q.get("version") != "flagged":
        notes.append("a quote is not from the flagged version")
        return False
    path, raw = q.get("path"), str(q.get("code") or "")
    seen = ws.read_text.get(("flagged", path))
    if seen is None:
        notes.append(f"a quote is from {path!r}, which the investigation did not read")
        return False
    lines = [ln for ln in (reviewer._norm(x) for x in raw.strip().strip("`").splitlines()) if ln]
    texts = [reviewer._norm(seen)]
    if str(path).endswith(".json"):      # JSON strings are escaped in the file; a command is quoted as written
        texts.append(reviewer._norm(reviewer._JSON_ESCAPE.sub(r"\1", seen)))
    if not any(len(ln.replace(" ", "")) >= reviewer._MIN_QUOTE for ln in lines) or \
            not any(reviewer._in_order(lines, t) for t in texts):
        notes.append(f"a quote is not in {path} as read")
        return False
    if code_only and str(path).endswith(reviewer._CODE_EXT) and reviewer._only_text(reviewer._norm(raw)):
        notes.append(f"a quoted end in {path} is a string or comment, not code")
        return False
    return True


def judge(answer: dict, ws) -> Outcome:
    notes: list[str] = []
    rejected = 0
    verdict = answer.get("verdict")
    injected = any("addresses the reviewer" in f for f in ws.facts)
    if verdict == "malicious":
        ok = True
        for end in ("chain_source", "chain_sink"):
            if not _quote_ok(answer.get(end), ws, notes, code_only=True):
                ok, rejected = False, rejected + 1
        if ok:
            s, k = answer["chain_source"]["path"], answer["chain_sink"]["path"]
            files = ws.files["flagged"]
            if s != k and not (reviewer._names(files.get(s, b"").decode("utf-8", "replace"), k)
                               or reviewer._names(files.get(k, b"").decode("utf-8", "replace"), s)):
                ok = False
                notes.append("source and sink are not in the same file or in files that name each other")
        return Outcome("malicious", "contested" if injected else "confirmed" if ok else "inconclusive", notes,
                       rejected)
    # Anything below malicious: coverage, then an explanation.
    covered = True
    if "flagged" not in ws.scripts_seen:
        covered = False; notes.append("the install scripts were not examined")
    for p in ws.required_files():
        if ("flagged", p) not in ws.read_full and p not in ws.too_large():
            covered = False; notes.append(f"{p} runs but was not read in full")
    for p in ws.too_large():
        covered = False; notes.append(f"{p} runs and is too large to examine in full")
    explained = _quote_ok(answer.get("explanation"), ws, notes)
    rejected += 0 if explained or answer.get("explanation") is None else 1
    if not explained:
        notes.append("no quoted explanation of the original chain")
    if not (covered and explained):
        return Outcome("malicious", "contested" if injected else "inconclusive", notes, rejected)
    if injected:            # an injection attempt never clears anything
        return Outcome("malicious", "contested", notes, rejected)
    return Outcome(verdict, "disputed", notes, rejected)
