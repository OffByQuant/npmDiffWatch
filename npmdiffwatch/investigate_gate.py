"""The model's answer is recorded only with evidence that exists: a malicious verdict needs both ends of the chain
quoted from the flagged version, anything below it a quoted explanation, or the original verdict stands."""
import re
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


_ELISION = re.compile(r"/\*\s*(?:\.\.\.|…)\s*\*/|\.\.\.|…")
_ADDED_COMMENT = re.compile(r"(?:^|\s)//\s.*$")


def _pieces(raw: str, text: str) -> list[str]:
    """The quoted code in order: an elision ("...", "/* ... */") marks code left out, and a // comment that is not
    in the file is the model's own note, not a quote."""
    out = []
    for line in raw.strip().strip("`").splitlines():
        for piece in _ELISION.split(line):
            piece = reviewer._norm(piece)
            if piece and piece not in text:
                piece = reviewer._norm(_ADDED_COMMENT.sub("", piece))
            if piece:
                out.append(piece)
    return out


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
    texts = [reviewer._norm(seen)]
    if str(path).endswith(".json"):      # JSON strings are escaped in the file; a command is quoted as written
        texts.append(reviewer._norm(reviewer._JSON_ESCAPE.sub(r"\1", seen)))
    def matches(t):
        ls = _pieces(raw, t)
        return any(len(ln.replace(" ", "")) >= reviewer._MIN_QUOTE for ln in ls) and reviewer._in_order(ls, t)
    if not any(matches(t) for t in texts):
        notes.append(f"a quote is not in {path} as read")
        return False
    if code_only and str(path).endswith(reviewer._CODE_EXT) and reviewer._only_text(reviewer._norm(raw)):
        notes.append(f"a quoted end in {path} is a string or comment, not code")
        return False
    return True


def judge(answer: dict, ws) -> Outcome:
    """The model decides; its evidence must exist. What it did not examine, and any text addressing the reviewer,
    is noted for the person reading the record."""
    notes = [f for f in ws.facts if "addresses the reviewer" in f]
    rejected = 0
    if answer.get("verdict") == "malicious":
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
        return Outcome("malicious", "confirmed" if ok else "inconclusive", notes, rejected)
    if "flagged" not in ws.scripts_seen:
        notes.append("the install scripts tool was not used")
    for p in ws.required_files():
        if ("flagged", p) not in ws.read_full and p not in ws.too_large():
            notes.append(f"{p} runs but was not read in full")
    for p in ws.too_large():
        notes.append(f"{p} runs and is too large to examine in full")
    if not _quote_ok(answer.get("explanation"), ws, notes):
        rejected += 0 if answer.get("explanation") is None else 1
        notes.append("no quoted explanation of the original chain")
        return Outcome("malicious", "inconclusive", notes, rejected)
    return Outcome(answer["verdict"], "disputed", notes, rejected)
