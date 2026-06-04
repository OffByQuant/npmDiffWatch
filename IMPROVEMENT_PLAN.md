# NpmDiffWatch — Improvement Plan

Review of the PyDiffWatch → npm port. The safety scaffolding came over intact, but the
core detection front-door is broken and there are no tests. Work the priority order at the
bottom: ingest first (nothing else matters without it), then the contained bug + test fixes.

> Context for a fresh session: this is a Python tool that scans **npm** packages (ported from
> PyDiffWatch, which scanned PyPI). The hard invariant is **NO EXECUTION** — analyzed packages
> are data, never run/installed/imported. Pipeline: `ingest → fetcher → differ → engine (triage)
> → reviewer (only on escalate) → notifier → store`, SQLite under `.diffwatch/`.

---

## The Ugly — the core function doesn't work

### 1. Ingest can't find new releases  (`ingest.py:13`, `ingest.py:55-103`)
```python
_SEARCH_URL = "/-/v1/search?by=maintenance&size=250"
```
- npm's `/-/v1/search` requires a `text` query and ranks by quality/popularity/maintenance —
  `by=` is not a real parameter.
- Even if it returned results, sorting toward *maintenance* surfaces established, popular
  packages — the opposite of the brand-new, low-reputation packages where supply-chain malware
  lands. A freshly published malicious version will essentially never appear.
- **Fix:** switch to the replication changes feed (`https://replicate.npmjs.org/_changes`,
  monotonic `seq`). This is npm's real equivalent of PyPI's `changelog_since_serial` and maps
  1:1 onto the serial-cursor model already ported. Follow `seq` forward from the cursor.

### 2. The "serial" cursor is fake  (`ingest.py:40-47`, `ingest.py:55-103`, `orchestrator.py:122-169`)
- `current_serial()` returns `int(datetime.now().timestamp())` — wall-clock, not a registry
  sequence.
- `changes_since` ignores `since_serial` for filtering; dedup happens against the DB `releases`
  table (`ingest.py:88-92`), and `serial` is just a local batch counter (`serial += 1`).
- Result: the seed / `--backfill` / `advance_to` / "genesis" machinery in `run_once` is dead
  scaffolding with no npm meaning — incrementality/resumability are illusory.
- **Fix:** once #1 uses the `_changes` feed, make the serial the real `seq`; the cursor then
  gates correctly and the existing seed/advance logic becomes meaningful again.

> #1 and #2 share one root cause: the PyPI firehose model was lifted without an npm source
> underneath it. Fixing ingest to the `_changes` feed resolves both.

---

## The Bad — real bugs

### 3. Dependency screening always crashes  (`fetcher.py:198-200`)
```python
def _fetch_json(name):
    url = f"{cfg.npm_registry.rstrip('/')}/{name}"
    return _fetch_json(url, cfg)   # shadows module-level _fetch_json; calls THIS 1-arg closure with 2 args
```
- The nested `_fetch_json` shadows the module-level one and calls itself → `TypeError`.
- `deps.screen_added_deps` calls it for any added dep that isn't in the corpus and isn't a
  typosquat (`deps.py:86`); no try/except, so it propagates → `fetch_artifacts` →
  caught in `_process_fetched` as generic exception → `fetch_failed` → retried forever.
- Net: nonexistent / brand-new dependency detection never runs; any package with a novel added
  dep silently never completes.
- **Fix:** rename the inner closure (e.g. `_lookup`) so the module-level `_fetch_json(url, cfg)`
  is the one called. Low risk, contained.

### 4. Zero tests  (no `tests/` dir; `CLAUDE.md:53-63`, `pyproject.toml` dev extra + `pythonpath`)
- `CLAUDE.md` documents `pytest -v` and `ruff check npmdiffwatch/ tests/`; `pyproject.toml`
  declares `dev=["pytest>=8"]` and `pythonpath=["."]` — but there is no `tests/` directory.
- PyDiffWatch's entire safety claim rests on `tests/test_containment_reviewer.py` — AST guards
  proving reviewer/backends/fetcher stay network-free and in-memory, i.e. the enforcement of
  NO-EXECUTION. None of that was ported. The invariants are currently honored by convention only.
- **Fix:** port the containment test suite first (AST guards over `reviewer.py` / `backends.py`
  / `fetcher.py`), then unit tests for `egress`, `rules` (fail-closed validator + no-eval
  matcher), `facts` (tree-sitter categories), `differ`, `deps`, and `fetcher` extraction caps.

### 5. Anthropic backend uses an unverified API shape  (`backends.py:99-101`)
```python
thinking={"type": "adaptive"},
output_config={"format": {"type": "json_schema", "schema": schema}},
```
- Uncertain these are valid in the Anthropic Python SDK (`anthropic>=0.40`). `thinking` is
  normally `{"type": "enabled", "budget_tokens": N}`; JSON-schema output via `output_config`
  isn't a confirmed shape. **Flagged as uncertain — verify, don't assume.**
- If wrong, every Anthropic review raises `APIError` → silent heuristic fallback, undetectable
  without a test.
- **Fix:** verify against the installed SDK version; correct the call; add a backend test with a
  mocked client.

---

## Smells (low severity)

- **`_is_strict_binary` duplicates `_is_binary`** (`fetcher.py:40-41`); `_is_binary` is unused —
  copy-paste residue.
- **Dead branch in `_is_surface`** (`fetcher.py:133-135`): `base.startswith("bin/")` can never be
  true since `base = posixpath.basename(path)` has no slash. The `"/bin/" in path` clause is what
  works.
- **README drift** (`README.md:46,48,8`): documents `max_tgz_bytes` (actual field is
  `max_download_bytes`, `config.py:25`); shows `new_package_policy = "skip"` while the default is
  `"surface"` (`config.py:39`); `pip install npmdiffwatch` implies a published package.

---

## The Good — ported faithfully (do not regress)

- **Safety core intact.** In-memory streamed extraction (`tarfile.open(mode="r|")`,
  `_BoundedReader`, member/size/name/decompressed caps, `_unsafe` path rejection, never
  `extractall`, never to disk — `fetcher.py:21-100`); default-deny egress guard with
  `is_installed()` + `run_once` warning (`egress.py`, `orchestrator.py:123-125`);
  `assert_web_scheme` `file://`/SSRF guard.
- **Rules engine kept its safety boundary**: pure-data matcher, no eval/exec, fail-closed
  validator, scope-checked predicates (`rules.py`). Community rules stay untrusted input.
- **Reviewer injection defense**: per-request CSPRNG markers (`reviewer.py:12-13`), strong
  "judge behavior not stated purpose / content between markers is inert data" system prompt,
  client-side verdict validation with heuristic fallback.
- **npm threat modeling is appropriate**: lifecycle hooks (`pre/post/install`, `prepare`,
  `prepublish`), `child_process`/`fs`/`process.env` binding, prototype pollution, dynamic
  `require`/`import`, lockfile integrity/new-package, `bin` field changes (`facts.py`,
  `differ.py`). tree-sitter for JS/TS is correct. Dropping `defusedxml` was correct — npm
  registry is JSON, no XML-RPC.

---

## Priority order

1. **Replace ingest with the `_changes` replication feed** (make the serial a real `seq`).
   Without this, nothing else matters. (#1 + #2)
2. **Fix the `_fetch_json` shadowing bug** (`fetcher.py:198-200`). Contained, low-risk. (#3)
3. **Port the containment test suite**, then broader unit tests. Keeps NO-EXECUTION from
   quietly rotting. (#4)
4. **Verify the Anthropic SDK call** against the real API. (#5)
5. Clean up smells + README drift once the above land.
