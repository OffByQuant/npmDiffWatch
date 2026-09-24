# Watchlist Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `--watchlist PATH` restricts scanning to listed npm packages (names file, package-lock, CycloneDX, SPDX), filters the change feed before any download, and reviews each listed package's latest release once on start.

**Architecture:** A new pure-data module `watchlist.py` parses the file into a `Watchlist` (exact names in a set, `*` patterns compiled once). `ingest.changes_since` drops unlisted feed rows before fetching packuments. `run_once` gains a baseline step that sends up to 50 not-yet-baselined listed packages' latest releases through the normal pipeline per tick, tracked in a `watchlist_baseline` table; `watch()` keeps going without sleeping while the baseline is incomplete and reloads the file each tick.

**Tech Stack:** Python 3.11 stdlib (`json`, `fnmatch`, `re`, `urllib.parse`), SQLite, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-09-24-watchlist-design.md`

## Global Constraints

- No execution: list files are parsed as data only; nothing from them is run or used to build a command.
- No new dependencies (stdlib + PyYAML + tree-sitter only).
- Default-deny egress is unchanged: no new hosts.
- Without `--watchlist` (and no `watchlist` config key), behavior is unchanged.
- A missing, empty or unparsable list stops the run with a message naming the path and the accepted formats; never fall back to scanning everything or nothing.
- Baseline releases never move the cursor.
- `watchlist_baseline_per_tick` default 50.
- Test first for every behavior (write the test, watch it fail, implement, watch it pass); `pytest` and `ruff check npmdiffwatch/` green at each commit.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. A lockfile whose `packages` keys include workspace links (`"link": true`) or a root `""` entry: links are local and must not be watched; the root is skipped.
2. purls with a percent-encoded scope and qualifiers (`pkg:npm/%40babel/core@7.0.0?foo=bar#sub`) must decode to `@babel/core`.
3. The list file becoming unreadable mid-run (mid-save by an editor) must keep the last good list and warn, not stop scanning or widen to everything.
4. A listed package whose `latest` is already recorded (processed by the feed first) must be marked baselined without a second review.
5. A pattern-only list (`@scope/*` and nothing else) has zero baseline work: `watch` must not spin forever thinking the baseline is incomplete.

---

### Task 1: `watchlist.py` — parse the four formats and match names

**Files:**
- Create: `npmdiffwatch/watchlist.py`
- Test: `tests/test_watchlist_parse.py`

**Interfaces:**
- Produces: `class WatchlistError(Exception)`; `@dataclass(frozen=True) class Watchlist: path: str; fmt: str; names: frozenset[str]; patterns: tuple[str, ...]; skipped: int` with `matches(name: str) -> bool` and `describe() -> str` (e.g. `"deps.txt · 1,000 packages, 3 patterns"`); `load(path) -> Watchlist` (raises `WatchlistError`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_watchlist_parse.py
"""Watchlist files are parsed as data only. Four formats, detected from content."""
import json

import pytest

from npmdiffwatch import watchlist


def _w(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text if isinstance(text, str) else json.dumps(text))
    return watchlist.load(p)


def test_names_file_exact_scoped_patterns_comments_and_invalid(tmp_path):
    w = _w(tmp_path, "deps.txt", "# ours\nleft-pad\n@babel/core\n\n@gooddata/*\nreact-*\nnot a name!\nJSONStream\n")
    assert w.fmt == "names" and w.names == {"left-pad", "@babel/core", "JSONStream"}
    assert w.patterns == ("@gooddata/*", "react-*") and w.skipped == 1
    assert w.matches("@gooddata/sdk-backend-tiger") and w.matches("react-dom") and w.matches("left-pad")
    assert not w.matches("lodash") and not w.matches("@babel/cli")


def test_lockfile_v3_nested_scoped_skips_root_and_links(tmp_path):
    w = _w(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {
        "": {"name": "app"}, "node_modules/a": {}, "node_modules/@s/b": {},
        "node_modules/a/node_modules/c": {}, "node_modules/local-ws": {"link": True}, "packages/ws": {}}})
    assert w.fmt == "package-lock" and w.names == {"a", "@s/b", "c"}


def test_lockfile_v1_recursive_dependencies(tmp_path):
    w = _w(tmp_path, "package-lock.json", {"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}, "@s/c": {"version": "3.0.0"}}})
    assert w.names == {"a", "b", "@s/c"}


def test_cyclonedx_nested_components_and_encoded_purls(tmp_path):
    w = _w(tmp_path, "bom.json", {"bomFormat": "CycloneDX", "components": [
        {"purl": "pkg:npm/%40babel/core@7.0.0?foo=bar#sub"},
        {"purl": "pkg:npm/left-pad@1.3.0", "components": [{"purl": "pkg:npm/inner@1.0.0"}]},
        {"purl": "pkg:pypi/requests@2.0.0"}, {"name": "no-purl"}]})
    assert w.fmt == "cyclonedx" and w.names == {"@babel/core", "left-pad", "inner"}


def test_spdx_purl_external_refs(tmp_path):
    w = _w(tmp_path, "sbom.spdx.json", {"spdxVersion": "SPDX-2.3", "packages": [
        {"externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/%40s/x@1.0.0"}]},
        {"externalRefs": [{"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:x"}]}]})
    assert w.fmt == "spdx" and w.names == {"@s/x"}


@pytest.mark.parametrize("name,text,msg", [
    ("missing.txt", None, "cannot read"),
    ("empty.txt", "# nothing\n\n", "no packages"),
    ("other.json", {"hello": 1}, "not a recognized"),
    ("bad.json", "{not json", "not a recognized"),
])
def test_unusable_files_raise_with_the_path_and_formats(tmp_path, name, text, msg):
    p = tmp_path / name
    if text is not None:
        p.write_text(text if isinstance(text, str) else json.dumps(text))
    with pytest.raises(watchlist.WatchlistError) as e:
        watchlist.load(p)
    assert msg in str(e.value) and str(p) in str(e.value)


def test_describe(tmp_path):
    w = _w(tmp_path, "deps.txt", "a\nb\n@s/*\n")
    assert w.describe() == "deps.txt · 2 packages, 1 pattern"
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest -q tests/test_watchlist_parse.py`
Expected: FAIL at collection with `ImportError: cannot import name 'watchlist'`.

- [ ] **Step 3: Implement**

```python
# npmdiffwatch/watchlist.py
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


def _lock_names(doc):
    if isinstance(doc.get("packages"), dict):
        for key, meta in doc["packages"].items():
            if key and "node_modules/" in key and not (isinstance(meta, dict) and meta.get("link")):
                yield key.rsplit("node_modules/", 1)[1]
    else:
        stack = [doc.get("dependencies") or {}]
        while stack:
            for name, meta in stack.pop().items():
                yield name
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
        except ValueError:
            doc = None
        if isinstance(doc, dict) and "lockfileVersion" in doc:
            fmt, found = "package-lock", _lock_names(doc)
        elif isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
            fmt, found = "cyclonedx", _cyclonedx_names(doc)
        elif isinstance(doc, dict) and "spdxVersion" in doc:
            fmt, found = "spdx", _spdx_names(doc)
        else:
            raise WatchlistError(f"watchlist {path} is not a recognized format. Accepted: {FORMATS}")
        for n in found:
            if n and _NAME.match(n):
                names.add(n)
            elif n:
                skipped += 1
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
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest -q tests/test_watchlist_parse.py && ruff check npmdiffwatch/watchlist.py`
Expected: all tests PASS; ruff clean.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/watchlist.py tests/test_watchlist_parse.py
git commit -m "feat(watchlist): parse names files, package-lock, CycloneDX and SPDX into a name matcher"
```

---

### Task 2: store — `watchlist_baseline` table

**Files:**
- Modify: `npmdiffwatch/store.py` (SCHEMA; helpers after `feed_retry_counts`)
- Test: `tests/test_watchlist_store.py`

**Interfaces:**
- Produces: `baseline_pending(conn, names: set[str], limit: int) -> list[str]` (listed names without a row, sorted); `mark_baseline(conn, package: str, result: str)` (upsert; `result` in `scanned|no_versions|not_found|fetch_failed`; a `fetch_failed` row is retried: it counts as pending); `baseline_counts(conn, names: set[str]) -> tuple[int, int]` (done, total).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_watchlist_store.py
import dataclasses

from npmdiffwatch import store
from npmdiffwatch.config import Config


def _conn(tmp_path):
    conn = store.connect(dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite")); store.init_schema(conn)
    return conn


def test_pending_is_listed_names_without_a_result(tmp_path):
    conn = _conn(tmp_path)
    names = {"c", "a", "b"}
    assert store.baseline_pending(conn, names, limit=2) == ["a", "b"]
    store.mark_baseline(conn, "a", "scanned")
    store.mark_baseline(conn, "b", "not_found")
    assert store.baseline_pending(conn, names, limit=10) == ["c"]
    assert store.baseline_counts(conn, names) == (2, 3)


def test_fetch_failed_is_retried_and_counts_as_not_done(tmp_path):
    conn = _conn(tmp_path)
    store.mark_baseline(conn, "a", "fetch_failed")
    assert store.baseline_pending(conn, {"a"}, limit=10) == ["a"]
    assert store.baseline_counts(conn, {"a"}) == (0, 1)
    store.mark_baseline(conn, "a", "scanned")
    assert store.baseline_pending(conn, {"a"}, limit=10) == []


def test_names_removed_from_the_list_do_not_count(tmp_path):
    conn = _conn(tmp_path)
    store.mark_baseline(conn, "gone", "scanned")
    assert store.baseline_counts(conn, {"a"}) == (0, 1)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest -q tests/test_watchlist_store.py`
Expected: FAIL with `AttributeError: module 'npmdiffwatch.store' has no attribute 'baseline_pending'`.

- [ ] **Step 3: Implement**

In `SCHEMA`, before `CREATE TABLE IF NOT EXISTS feed_retry(`:

```sql
CREATE TABLE IF NOT EXISTS watchlist_baseline(package TEXT PRIMARY KEY, result TEXT, done_at TEXT);
```

After `feed_retry_counts`:

```python
def _baselined(conn) -> set:
    return {r[0] for r in conn.execute("SELECT package FROM watchlist_baseline WHERE result != 'fetch_failed'")}

def baseline_pending(conn, names, limit):
    """Listed packages whose latest release hasn't been reviewed yet (fetch_failed ones are retried)."""
    return sorted(set(names) - _baselined(conn))[:limit]

def mark_baseline(conn, package, result):
    conn.execute("INSERT INTO watchlist_baseline(package, result, done_at) VALUES(?,?,?) ON CONFLICT(package) "
                 "DO UPDATE SET result=excluded.result, done_at=excluded.done_at", (package, result, _now()))
    conn.commit()

def baseline_counts(conn, names) -> tuple:
    names = set(names)
    return len(names & _baselined(conn)), len(names)
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest -q tests/test_watchlist_store.py && python -m pytest -q`
Expected: new tests PASS; full suite PASS.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/store.py tests/test_watchlist_store.py
git commit -m "feat(store): watchlist_baseline table for the one-time latest-release review"
```

---

### Task 3: ingest — drop unlisted feed rows before any download

**Files:**
- Modify: `npmdiffwatch/ingest.py` (`changes_since`)
- Test: `tests/test_watchlist_ingest.py`

**Interfaces:**
- Consumes: `Watchlist.matches(name)` (Task 1).
- Produces: `changes_since(cfg, since_serial, conn=None, *, limit=None, watch=None) -> ChangesPage`; with `watch`, rows (and feed retries) for unlisted packages are dropped before packument fetch; the watermark still covers the whole page.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_watchlist_ingest.py
from npmdiffwatch import ingest
from npmdiffwatch.config import Config
from npmdiffwatch.watchlist import Watchlist

_W = Watchlist("deps.txt", "names", frozenset({"mine"}), ("@team/*",))


def _fake(fetched):
    changes = {"results": [{"seq": 11, "id": "other"}, {"seq": 12, "id": "mine"}, {"seq": 13, "id": "@team/x"},
                           {"seq": 14, "id": "zzz"}], "last_seq": 14}

    def f(url, cfg, **k):
        if "_changes" in url:
            return changes
        fetched.append(url.rsplit("/", 2)[-1] if "@" not in url else "/".join(url.rsplit("/", 2)[-2:]))
        return {"versions": {"1.0.0": {}}, "time": {"1.0.0": "2026-09-24T00:00:00.000Z"}}
    return f


def test_unlisted_rows_are_never_fetched_and_the_watermark_covers_the_page(monkeypatch):
    fetched = []
    monkeypatch.setattr(ingest, "_fetch_json", _fake(fetched))
    page = ingest.changes_since(Config(), 10, conn=None, limit=200, watch=_W)
    assert sorted(r.package for r in page.releases) == ["@team/x", "mine"]
    assert sorted(fetched) == ["@team/x", "mine"] and page.watermark == 14


def test_without_a_watchlist_everything_is_fetched(monkeypatch):
    fetched = []
    monkeypatch.setattr(ingest, "_fetch_json", _fake(fetched))
    page = ingest.changes_since(Config(), 10, conn=None, limit=200)
    assert len(page.releases) == 4 and len(fetched) == 4
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest -q tests/test_watchlist_ingest.py`
Expected: first test FAILS with `TypeError: changes_since() got an unexpected keyword argument 'watch'`; second PASSES (existing behavior).

- [ ] **Step 3: Implement**

In `ingest.changes_since`, change the signature to `def changes_since(cfg: Config, since_serial: int, conn=None, *, limit: int | None = None, watch=None) -> ChangesPage:`. In the row loop, after `if not name or not isinstance(seq, int): continue`, add:

```python
        if watch is not None and not watch.matches(name):
            continue          # watchlist mode: never download anything for an unlisted package
```

and in the feed-retry extension, filter the same way:

```python
        rows += [(r["package"], since_serial) for r in store.feed_retries_due(conn)
                 if r["package"] not in page_names and (watch is None or watch.matches(r["package"]))]
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest -q tests/test_watchlist_ingest.py && python -m pytest -q`
Expected: PASS; full suite PASS.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/ingest.py tests/test_watchlist_ingest.py
git commit -m "feat(ingest): in watchlist mode drop unlisted feed rows before any download"
```

---

### Task 4: orchestrator — baseline step, filtered feed, reload, don't sleep while the baseline is incomplete

**Files:**
- Modify: `npmdiffwatch/config.py` (`watchlist`, `watchlist_baseline_per_tick`), `npmdiffwatch/orchestrator.py` (`run_once`, `watch`, `_behind`, new `_baseline_step`, new `class WatchlistFile`)
- Test: `tests/test_watchlist_run.py`

**Interfaces:**
- Consumes: `watchlist.load`, `Watchlist` (Task 1); `store.baseline_pending/mark_baseline/baseline_counts` (Task 2); `changes_since(..., watch=)` (Task 3).
- Produces: `Config.watchlist: str | None = None`, `Config.watchlist_baseline_per_tick: int = 50`; `class WatchlistFile(path)` with `current() -> Watchlist` (reloads when mtime changes; on a failed reload keeps the last good list and prints `[npmdiffwatch] WARNING: watchlist <path> could not be re-read (<err>); keeping the last good list`); `run_once(cfg, *, seed_if_fresh=True, recent=None, watch=None)`; `watch(..., watchlist=None)` where `watchlist` is a `WatchlistFile` or None; baseline status via `baseline_status(cfg, wl) -> dict` `{"describe": str, "done": int, "total": int}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_watchlist_run.py
import dataclasses
import os
import time
from pathlib import Path

from npmdiffwatch import fetcher, ingest, orchestrator, store
from npmdiffwatch.config import Config
from npmdiffwatch.ingest import ChangesPage
from npmdiffwatch.watchlist import Watchlist


def _cfg(tmp_path, **over):
    return dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l",
                               cache_dir=tmp_path / "c", reviewer_enabled=False, rules_dir=Path("rules/community"),
                               **over)


def _seeded(cfg, serial=1000):
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, serial); conn.close()


def _no_feed(monkeypatch, seen=None):
    def feed(c, since, conn=None, *, limit=None, watch=None):
        if seen is not None:
            seen.append(watch)
        return ChangesPage([], since)
    monkeypatch.setattr(ingest, "changes_since", feed)


def _registry(monkeypatch, latest):
    """latest: {pkg: version or None(404) or {} (no versions)}"""
    def packument(name, cfg):
        v = latest[name]
        if v is None:
            return None
        return {"dist-tags": {"latest": v}, "versions": {v: {}}} if v else {"versions": {}}
    monkeypatch.setattr(fetcher, "_packument", packument)
    fetched = []
    monkeypatch.setattr(orchestrator, "_fetch_one", lambda cfg, rel: fetched.append((rel.package, rel.version)) or None)
    return fetched


_W = Watchlist("deps.txt", "names", frozenset({"a", "b", "gone", "empty"}), ())


def test_baseline_reviews_each_listed_latest_once_and_never_moves_the_cursor(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); _seeded(cfg)
    _no_feed(monkeypatch)
    fetched = _registry(monkeypatch, {"a": "1.2.0", "b": "3.0.0", "gone": None, "empty": {}})
    orchestrator.run_once(cfg, watch=_W)
    orchestrator.run_once(cfg, watch=_W)
    conn = store.connect(cfg)
    assert sorted(fetched) == [("a", "1.2.0"), ("b", "3.0.0")]
    assert store.baseline_counts(conn, _W.names) == (4, 4) and store.get_last_serial(conn) == 1000
    assert dict(conn.execute("SELECT package, result FROM watchlist_baseline").fetchall()) == \
        {"a": "scanned", "b": "scanned", "gone": "not_found", "empty": "no_versions"}


def test_baseline_is_batched_per_tick(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, watchlist_baseline_per_tick=2); _seeded(cfg)
    _no_feed(monkeypatch)
    _registry(monkeypatch, {"a": "1.0.0", "b": "1.0.0", "gone": "1.0.0", "empty": "1.0.0"})
    orchestrator.run_once(cfg, watch=_W)
    assert store.baseline_counts(store.connect(cfg), _W.names) == (2, 4)


def test_already_recorded_latest_is_marked_without_a_second_review(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); _seeded(cfg)
    conn = store.connect(cfg); store.init_schema(conn)
    store.record_release(conn, "a", "1.2.0", 999, False, None, "tgz", stage="reviewed")
    _no_feed(monkeypatch)
    fetched = _registry(monkeypatch, {"a": "1.2.0", "b": "3.0.0", "gone": None, "empty": {}})
    orchestrator.run_once(cfg, watch=_W)
    assert ("a", "1.2.0") not in fetched and store.baseline_counts(store.connect(cfg), _W.names) == (4, 4)


def test_feed_page_is_filtered_by_the_watchlist(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); _seeded(cfg)
    seen = []
    _no_feed(monkeypatch, seen)
    _registry(monkeypatch, {"a": "1.0.0", "b": "1.0.0", "gone": None, "empty": {}})
    orchestrator.run_once(cfg, watch=_W)
    assert seen == [_W]


def test_watch_keeps_going_while_the_baseline_is_incomplete(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, watchlist_baseline_per_tick=1); _seeded(cfg)
    lst = tmp_path / "deps.txt"; lst.write_text("a\nb\n")
    _no_feed(monkeypatch)
    _registry(monkeypatch, {"a": "1.0.0", "b": "1.0.0"})
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda *a, **k: None)
    slept = []
    orchestrator.watch(cfg, interval=300, iterations=3, sleep_fn=slept.append,
                       watchlist=orchestrator.WatchlistFile(lst))
    assert slept == [300]          # ticks 1-2 do the baseline back to back; tick 2 completes it; then it sleeps


def test_pattern_only_list_has_no_baseline_work(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path); _seeded(cfg)
    lst = tmp_path / "deps.txt"; lst.write_text("@team/*\n")
    _no_feed(monkeypatch)
    monkeypatch.setattr(orchestrator, "export_dashboard", lambda *a, **k: None)
    slept = []
    orchestrator.watch(cfg, interval=300, iterations=2, sleep_fn=slept.append,
                       watchlist=orchestrator.WatchlistFile(lst))
    assert slept == [300]


def test_a_broken_reload_keeps_the_last_good_list(tmp_path, capsys):
    lst = tmp_path / "deps.txt"; lst.write_text("a\n")
    wf = orchestrator.WatchlistFile(lst)
    assert wf.current().names == {"a"}
    lst.write_text("")
    os.utime(lst, (time.time() + 5, time.time() + 5))
    assert wf.current().names == {"a"} and "keeping the last good list" in capsys.readouterr().out
    lst.write_text("b\n")
    os.utime(lst, (time.time() + 10, time.time() + 10))
    assert wf.current().names == {"b"}
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest -q tests/test_watchlist_run.py`
Expected: FAIL with `TypeError: run_once() got an unexpected keyword argument 'watch'` and `AttributeError: ... 'WatchlistFile'`.

- [ ] **Step 3: Implement**

`config.py`, after `prune_every_hours` (or after `retention_days` if Task ordering lands before #16; place it next to `max_releases_per_run` otherwise):

```python
    watchlist: str | None = None          # watch only these packages (names file, package-lock, CycloneDX, SPDX)
    watchlist_baseline_per_tick: int = 50  # listed packages whose latest release is reviewed per tick at start
```

`orchestrator.py` — imports: `from . import watchlist as watchlist_mod`. Add:

```python
class WatchlistFile:
    """The watchlist, re-read when the file changes. A failed re-read keeps the last good list."""
    def __init__(self, path):
        self.path = Path(path)
        self._list = watchlist_mod.load(self.path)
        self._mtime = self.path.stat().st_mtime

    def current(self):
        try:
            mtime = self.path.stat().st_mtime
            if mtime != self._mtime:
                self._list, self._mtime = watchlist_mod.load(self.path), mtime
        except (OSError, watchlist_mod.WatchlistError) as e:
            msg = f"[npmdiffwatch] WARNING: watchlist {self.path} could not be re-read ({e}); keeping the last good list"
            print(msg, flush=True); logger.warning(msg)
        return self._list


def _baseline_step(cfg, conn, rvw, ruleset, watch, offline, guard):
    """Review the latest release of up to watchlist_baseline_per_tick listed packages not yet baselined.
    Their releases use the current cursor as serial and never move it."""
    serial = store.get_last_serial(conn)
    for name in store.baseline_pending(conn, watch.names, cfg.watchlist_baseline_per_tick):
        meta = fetcher._packument(name, cfg)
        if meta is None:
            store.mark_baseline(conn, name, "not_found"); continue
        if meta == {}:
            store.mark_baseline(conn, name, "fetch_failed"); continue
        latest = (meta.get("dist-tags") or {}).get("latest")
        if not latest or latest not in (meta.get("versions") or {}):
            store.mark_baseline(conn, name, "no_versions"); continue
        if store.get_stage(conn, name, latest) in TERMINAL:
            store.mark_baseline(conn, name, "scanned"); continue
        rel = NewRelease(name, latest, serial)
        done = _process_fetched(cfg, conn, rvw, ruleset, rel, _fetch_one(cfg, rel), offline, guard)
        store.mark_baseline(conn, name, "scanned" if done else "fetch_failed")
    d, t = store.baseline_counts(conn, watch.names)
    if d < t:
        print(f"[npmdiffwatch] watchlist baseline: {d:,}/{t:,} packages", flush=True)


def baseline_status(cfg, wl) -> dict:
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        d, t = store.baseline_counts(conn, wl.names)
    finally:
        conn.close()
    return {"describe": wl.describe(), "done": d, "total": t}
```

`run_once` signature: add `watch=None`. Immediately before `page = ingest.changes_since(...)`:

```python
        if watch is not None:
            _baseline_step(cfg, conn, rvw, ruleset, watch, offline, guard)
```

and pass `watch=watch` to `ingest.changes_since`.

Note: `_fetch_one` returns `None` in the test fakes; `_process_fetched` records `no_sdist` for `None` and returns True, which is correct (terminal).

`watch()` signature: add `watchlist=None`. At the top of each loop iteration: `wl = watchlist.current() if watchlist else None`; call `run_once(cfg, recent=recent, watch=wl)`; replace `if not _behind(cfg, before):` with:

```python
            if not _behind(cfg, before) and not _baseline_incomplete(cfg, wl):
                sleep_fn(interval)
```

with

```python
def _baseline_incomplete(cfg, wl) -> bool:
    if wl is None or not wl.names:
        return False
    s = baseline_status(cfg, wl)
    return s["done"] < s["total"]
```

`Path` import: add `from pathlib import Path` if absent.

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest -q tests/test_watchlist_run.py && python -m pytest -q && ruff check npmdiffwatch/`
Expected: PASS; full suite PASS; ruff clean.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/config.py npmdiffwatch/orchestrator.py tests/test_watchlist_run.py
git commit -m "feat(watchlist): baseline each listed package's latest release, filter the feed, reload the list"
```

---

### Task 5: CLI, config key, fail-fast, status line

**Files:**
- Modify: `npmdiffwatch/__main__.py` (`--watchlist` on `run` and `watch`; `_cfg`; startup load; `pending` line), `npmdiffwatch/orchestrator.py` (`export_dashboard` status `"watchlist"`), `npmdiffwatch/dashboard.py` (status span)
- Test: `tests/test_watchlist_cli.py`

**Interfaces:**
- Consumes: `WatchlistFile`, `baseline_status` (Task 4); `watchlist.WatchlistError` (Task 1).
- Produces: `_cfg(args)` honours `args.watchlist` (flag beats config); `_watchlist_or_exit(cfg) -> WatchlistFile | None` (prints the error and `sys.exit(2)` on `WatchlistError`); dashboard status key `"watchlist"`: `{"describe", "done", "total"}` rendered as `watchlist: deps.txt · 2 packages · baseline 2/2`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_watchlist_cli.py
import argparse
import dataclasses

import pytest

from npmdiffwatch import __main__ as cli, dashboard, orchestrator
from npmdiffwatch.config import Config


def _args(**kw):
    return argparse.Namespace(**{"config": None, "model": None, "endpoint": None, "watchlist": None, **kw})


def test_flag_sets_the_watchlist_and_beats_the_config(tmp_path):
    p = tmp_path / "c.toml"; p.write_text('watchlist = "from-config.txt"\n')
    assert cli._cfg(_args(config=str(p))).watchlist == "from-config.txt"
    assert cli._cfg(_args(config=str(p), watchlist="flag.txt")).watchlist == "flag.txt"


def test_an_unusable_watchlist_stops_the_run_with_a_message(tmp_path, capsys):
    cfg = dataclasses.replace(Config(), watchlist=str(tmp_path / "missing.txt"))
    with pytest.raises(SystemExit) as e:
        cli._watchlist_or_exit(cfg)
    assert e.value.code == 2 and "missing.txt" in capsys.readouterr().out


def test_no_watchlist_means_none():
    assert cli._watchlist_or_exit(Config()) is None


def test_dashboard_shows_the_watchlist_and_baseline(tmp_path):
    lst = tmp_path / "deps.txt"; lst.write_text("a\nb\n")
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", watchlist=str(lst))
    out = orchestrator.export_dashboard(cfg, out_path=tmp_path / "d.html")
    assert "watchlist: deps.txt · 2 packages · baseline 0/2" in out.read_text()
    assert "watchlist:" not in dashboard.render_dashboard([], status={}, generated_at="")
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest -q tests/test_watchlist_cli.py`
Expected: FAIL (`_watchlist_or_exit` missing; `watchlist` not honoured; dashboard line absent).

- [ ] **Step 3: Implement**

`__main__.py`: `import sys`; in `_cfg`, before `return cfg`:

```python
    if getattr(args, "watchlist", None):
        cfg = dataclasses.replace(cfg, watchlist=args.watchlist)
```

Add:

```python
def _watchlist_or_exit(cfg):
    if not cfg.watchlist:
        return None
    from .orchestrator import WatchlistFile
    from .watchlist import WatchlistError
    try:
        wf = WatchlistFile(cfg.watchlist)
    except WatchlistError as e:
        print(f"[npmdiffwatch] {e}"); sys.exit(2)
    print(f"[npmdiffwatch] watchlist: {wf.current().describe()}"
          + (f" ({wf.current().skipped} invalid entries skipped)" if wf.current().skipped else ""))
    return wf
```

Arguments on `runp` and `wp`:

```python
    runp.add_argument("--watchlist", default=None, metavar="PATH",
                      help="scan only these packages: a names file (name or @scope/* per line), "
                           "package-lock.json, or a CycloneDX / SPDX JSON SBOM")
```

(same help on `wp`). In `run`: `wf = _watchlist_or_exit(cfg)`; `run_once(cfg, ..., watch=wf.current() if wf else None)`. In `watch`: `wf = _watchlist_or_exit(cfg)`; `watch(..., watchlist=wf)`. In `pending`, after the guard line:

```python
        if cfg.watchlist:
            from .orchestrator import WatchlistFile, baseline_status
            s = baseline_status(cfg, WatchlistFile(cfg.watchlist).current())
            print(f"[npmdiffwatch] watchlist: {s['describe']} · baseline {s['done']:,}/{s['total']:,}")
```

`orchestrator.export_dashboard`: add to `status`:

```python
        "watchlist": _watchlist_status(cfg),
```

with

```python
def _watchlist_status(cfg):
    if not cfg.watchlist:
        return None
    try:
        return baseline_status(cfg, watchlist_mod.load(cfg.watchlist))
    except watchlist_mod.WatchlistError:
        return None
```

`dashboard.py` status block: add

```python
    w = status.get("watchlist")
    watch_txt = f"watchlist: {w['describe']} · baseline {w['done']:,}/{w['total']:,}" if w else ""
```

and append `{f'  <span class="stat">{e(watch_txt)}</span>' + chr(10) if watch_txt else ''}` after the guard span.

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest -q tests/test_watchlist_cli.py && python -m pytest -q && ruff check npmdiffwatch/`
Expected: PASS; full suite PASS; ruff clean.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/__main__.py npmdiffwatch/orchestrator.py npmdiffwatch/dashboard.py tests/test_watchlist_cli.py
git commit -m "feat(cli): --watchlist on run and watch; fail fast on an unusable list; show it in pending and the dashboard"
```

---

### Task 6: Docs, example, live check

**Files:**
- Modify: `README.md` (quick start: one watchlist example), `GETTING-STARTED.md` (new "Watch only your packages" section after §6), `examples/watchlist.txt` (new)

- [ ] **Step 1: Write the example and docs**

`examples/watchlist.txt`:

```text
# One package per line; * patterns match a family. Or point --watchlist at a
# package-lock.json or a CycloneDX / SPDX JSON SBOM instead.
left-pad
@babel/core
@gooddata/*
```

README, under the quick-start command block:

```markdown
Only care about your own dependencies? Point it at your lockfile or SBOM:
`npmdiffwatch --model qwen-singleshot watch --serve --watchlist path/to/package-lock.json`
```

GETTING-STARTED section: the four formats (table from the spec §3), the startup baseline (batched, resumable, progress line), that patterns only match new releases, reload on file change, the fail-fast rule, and that without `--watchlist` nothing changes.

- [ ] **Step 2: Live check (RTX endpoint)**

Build a real list: `python -c` that reads a real project's `package-lock.json` (e.g. any repo on this machine with one) — or generate one with 1,000 names by taking the first 1,000 lines of `npmdiffwatch/data/top_npm_names.txt` into `scratchpad/top1000.txt`. Run with a scratch database:

```bash
npmdiffwatch -c <scratch paths.toml> --model gemma-singleshot --endpoint http://192.168.68.63:8000/v1 \
  watch --serve --port 8788 --watchlist scratchpad/top1000.txt
```

Expected: `watchlist baseline: n/1,000` climbing; baseline completes; then the cursor stays within 200 changes of npm's head (poll `https://replicate.npmjs.com/` `update_seq` against the cursor every minute for 15 minutes). Record baseline duration and the max lag.

- [ ] **Step 3: Commit**

```bash
git add README.md GETTING-STARTED.md examples/watchlist.txt
git commit -m "docs: watchlist mode — formats, baseline, patterns, example list"
```
