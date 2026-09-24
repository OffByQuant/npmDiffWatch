"""Watchlist: the npm packages to watch, read from a names file, package-lock.json, or a CycloneDX / SPDX
JSON SBOM. Parsed as data only; nothing from the file is executed. Matching is by name, not version."""
import fnmatch
import json
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

FORMATS = "a names file (one name or @scope/* pattern per line), package-lock.json, CycloneDX JSON or SPDX JSON"
_NAME = re.compile(r"^(@[A-Za-z0-9\-~][A-Za-z0-9\-._~]*/)?[A-Za-z0-9\-~][A-Za-z0-9\-._~]*$")
_PATTERN = re.compile(r"^(@[A-Za-z0-9\-~*][A-Za-z0-9\-._~*]*/)?[A-Za-z0-9\-~*][A-Za-z0-9\-._~*]*$")


class WatchlistError(Exception):
    pass


@dataclass(frozen=True)
class Watchlist:
    path: str
    fmt: str
    names: frozenset
    patterns: tuple
    skipped: int = 0

    def matches(self, name: str) -> bool:
        return name in self.names or any(fnmatch.fnmatchcase(name, p) for p in self.patterns)

    def describe(self) -> str:
        n, p = len(self.names), len(self.patterns)
        return (f"{Path(self.path).name} · {n:,} package{'s' if n != 1 else ''}"
                + (f", {p} pattern{'s' if p != 1 else ''}" if p else ""))


def _purl_name(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:npm/"):
        return None
    body = purl[len("pkg:npm/"):].split("?", 1)[0].split("#", 1)[0]
    body = urllib.parse.unquote(body)
    at = body.rfind("@")
    return body[:at] if at > 0 else body


def _alias_target(version):
    """'npm:string-width@4.2.3' -> 'string-width' (lockfile v1 alias); None otherwise."""
    if not isinstance(version, str) or not version.startswith("npm:"):
        return None
    body = version[4:]
    at = body.rfind("@")
    return body[:at] if at > 0 else body


def _lock_names(doc):
    if isinstance(doc.get("packages"), dict):
        for key, meta in doc["packages"].items():
            if key and "node_modules/" in key and not (isinstance(meta, dict) and meta.get("link")):
                real = meta.get("name") if isinstance(meta, dict) else None     # set when the entry is an alias
                yield real if isinstance(real, str) else key.rsplit("node_modules/", 1)[1]
    else:
        stack = [doc.get("dependencies") or {}]
        while stack:
            for name, meta in stack.pop().items():
                version = meta.get("version") if isinstance(meta, dict) else None
                yield _alias_target(version) or name
                if isinstance(meta, dict) and isinstance(meta.get("dependencies"), dict):
                    stack.append(meta["dependencies"])


def _cyclonedx_names(doc):
    stack = list(doc.get("components") or [])
    while stack:
        c = stack.pop()
        if isinstance(c, dict):
            yield _purl_name(c.get("purl"))
            stack.extend(c.get("components") or [])


def _spdx_names(doc):
    for p in doc.get("packages") or []:
        for ref in (p.get("externalRefs") or []) if isinstance(p, dict) else []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                yield _purl_name(ref.get("referenceLocator"))


def load(path) -> Watchlist:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise WatchlistError(f"cannot read watchlist {path}: {e}. Accepted: {FORMATS}") from e
    names, patterns, skipped = set(), [], 0
    if text.lstrip().startswith(("{", "[")):
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError):
            doc = None
        if isinstance(doc, dict) and "lockfileVersion" in doc:
            fmt, found = "package-lock", _lock_names(doc)
        elif isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
            fmt, found = "cyclonedx", _cyclonedx_names(doc)
        elif isinstance(doc, dict) and "spdxVersion" in doc:
            fmt, found = "spdx", _spdx_names(doc)
        else:
            raise WatchlistError(f"watchlist {path} is not a recognized format. Accepted: {FORMATS}")
        try:
            for n in found:
                if isinstance(n, str) and _NAME.match(n):
                    names.add(n)
                elif n:
                    skipped += 1
        except (AttributeError, TypeError, RecursionError) as e:       # a field of the wrong type
            raise WatchlistError(f"watchlist {path} is malformed {fmt} ({type(e).__name__}). "
                                 f"Accepted: {FORMATS}") from e
    else:
        fmt = "names"
        for line in text.splitlines():
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            if "*" in entry and _PATTERN.match(entry):
                patterns.append(entry)
            elif _NAME.match(entry) and len(entry) <= 214:
                names.add(entry)
            else:
                skipped += 1
    if not names and not patterns:
        raise WatchlistError(f"watchlist {path} has no packages. Accepted: {FORMATS}")
    return Watchlist(str(path), fmt, frozenset(names), tuple(patterns), skipped)
