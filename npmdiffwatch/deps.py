import os
import re
from datetime import datetime, timezone

_CORPUS_PATH = os.path.join(os.path.dirname(__file__), "data", "top_npm_names.txt")
_NAME_SEP = re.compile(r"\s+")
_MIN_TYPOSQUAT_LEN = 5


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def parse_dependencies(deps: dict | None) -> set[str]:
    if not deps:
        return set()
    return {normalize_name(n) for n in deps}


def load_corpus(path: str | None = None) -> set[str]:
    out = set()
    with open(path or _CORPUS_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.add(normalize_name(line))
    return out


def edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def nearest_corpus(name: str, corpus, max_dist: int = 2) -> str | None:
    if len(name) < _MIN_TYPOSQUAT_LEN or name in corpus:
        return None
    best, best_d = None, max_dist + 1
    for c in corpus:
        if abs(len(c) - len(name)) > max_dist:
            continue
        d = edit_distance(name, c)
        if 1 <= d < best_d:
            best, best_d = c, d
            if d == 1:
                break
    return best


def _earliest_upload(meta: dict):
    times = []
    for files in (meta.get("time") or {}).values():
        if isinstance(files, str):
            try:
                times.append(datetime.fromisoformat(files.replace("Z", "+00:00")))
            except ValueError:
                pass
    return min(times) if times else None


def screen_added_deps(added, corpus, *, fetch_json, now=None, brandnew_days: int = 30,
                      cap: int = 10, cache: dict | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    cache = cache if cache is not None else {}
    findings, fetched = [], 0
    for name in sorted(added):
        if name in corpus:
            continue
        target = nearest_corpus(name, corpus)
        if target:
            findings.append({"name": name, "reason": "typosquat", "target": target})
            continue
        if name not in cache:
            if fetched >= cap:
                findings.append({"name": name, "reason": "not-screened-cap"})
                continue
            cache[name] = fetch_json(name)
            fetched += 1
        meta = cache[name]
        if meta is None:
            findings.append({"name": name, "reason": "nonexistent"})
            continue
        earliest = _earliest_upload(meta)
        if earliest is not None and (now - earliest).days < brandnew_days:
            findings.append({"name": name, "reason": "brand-new"})
    return findings
