"""Does a file's content match what its name says it is? This only decides who looks at a file (the model or a
person, when a documentation name hides something else); it never decides a verdict."""
import json
import re

DOC_EXT = (".map", ".md", ".markdown", ".css", ".scss", ".less", ".svg", ".html", ".htm", ".d.ts", ".d.mts",
           ".d.cts")
DOC_NAMES = {"readme", "license", "licence", "changelog", "history", "authors", "notice", "contributing"}
_TYPES = (".d.ts", ".d.mts", ".d.cts")
_MARKUP = (".html", ".htm", ".svg")
_STYLE = (".css", ".scss", ".less")
_JSISH = re.compile(r"\brequire\s*\(|\bimport\s*\(|\bimport\b[^;\n]*\bfrom\b|=>|\bfunction\b|\beval\s*\("
                    r"|\bnew\s+Function\b|^\s*(?:const|let|var)\s+[\w$]")
_RUNTIME = re.compile(r"\brequire\s*\(|\beval\s*\(|\bnew\s+Function\b|child_process|process\.env|\bfetch\s*\("
                      r"|https?\.request")
_FENCE = re.compile(r"```.*?```|~~~.*?~~~", re.S)


def looks_like_doc(path: str) -> bool:
    base = path.lower().rsplit("/", 1)[-1]
    return base.endswith(DOC_EXT) or base.split(".")[0] in DOC_NAMES


def matches_name(path: str, text: str) -> bool:
    low = path.lower()
    if not text.strip():
        return True
    if low.endswith(".map"):
        try:
            return isinstance(json.loads(text), dict)
        except (ValueError, RecursionError):
            return False
    if low.endswith(_TYPES):
        return not _RUNTIME.search(text)
    if low.endswith(_MARKUP):
        return text.lstrip("﻿ \t\r\n").startswith("<")
    body = text if low.endswith(_STYLE) else _FENCE.sub("", text)   # code examples in docs live in fences
    lines = [ln for ln in body.splitlines() if ln.strip()]
    return not lines or sum(1 for ln in lines if _JSISH.search(ln)) / len(lines) < 0.3
