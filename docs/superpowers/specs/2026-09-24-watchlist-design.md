# Watchlist mode: watch only the packages you depend on

**Status:** draft for review · **Date:** 2026-09-24 · **Applies to:** npmDiffWatch (PyDiffWatch port later)

## 1. Why

Today the scanner reads every change npm publishes. That serves teams that guard the whole registry, but
most users care about a known set: their project's dependencies, a vendor's scope, or an SBOM their build
already produces. For them, a full scan is mostly noise and cost. It also can't keep up: the full scan
processes about 0.25 npm changes/s while npm publishes about 3/s (RTX run, 2026-09-24).

npm's change feed names the package on every row *before* anything is downloaded. Dropping rows for
unlisted packages at that point makes a watchlist run cheap enough to keep up with npm, and it gives a
new user something useful on day one: a review of what they already depend on.

## 2. Goal and success criteria

Goal: `--watchlist PATH` restricts scanning to the listed packages, takes the list from the formats teams
already have, and reviews each listed package's latest release on start.

1. A feed row for an unlisted package causes no metadata or tarball download.
2. With a 1,000-package list, a caught-up `watch` stays within one feed page (200 changes) of npm's head.
3. On start, every listed package's latest release is reviewed against its previous release, exactly
   once, resumably across restarts, with visible progress.
4. A missing, empty or unparsable list stops the run with a clear message. The tool never falls back to
   scanning everything or nothing.
5. Nothing in a list file is executed or used to build a command; it is parsed as data only.
6. Without `--watchlist`, behavior is unchanged.

## 3. Inputs

`--watchlist PATH` on `run` and `watch` (and `watchlist = "PATH"` in the TOML config, which the flag
overrides). The format is detected from the content:

| Format | Detected by | Packages taken |
|---|---|---|
| Names file (text) | not JSON | one entry per line; `#` comments and blank lines ignored; an entry is an exact name (`left-pad`, `@babel/core`) or a pattern with `*` (`@gooddata/*`, `react-*`) |
| `package-lock.json` / `npm-shrinkwrap.json` | JSON with `lockfileVersion` | v2/v3: every key of `packages` except the root `""`, taking the name after the last `node_modules/` (handles nesting and scopes); v1: the `dependencies` tree, recursively. Direct and transitive |
| CycloneDX JSON | `"bomFormat": "CycloneDX"` | `components` (recursively, including nested components) whose `purl` is `pkg:npm/...` |
| SPDX JSON | `spdxVersion` present | `packages[].externalRefs` with `referenceType: purl` and a `pkg:npm/...` locator |

- purls are decoded (`pkg:npm/%40scope/name@1.2.3` → `@scope/name`); versions are ignored. The
  watchlist is by name.
- Entries that aren't valid npm names are skipped and counted, and one warning names the first few.
- yarn.lock and pnpm-lock.yaml are out of scope for v1 (text formats with their own grammars); users can
  generate a CycloneDX SBOM from either.
- The file is re-read at the start of every tick, if its modification time changed, so updating a lockfile
  updates the watch. If a re-read fails, the last good list stays in force and each tick prints a warning.

Matching: exact names go in a set (O(1) per feed row); patterns are compiled once with `fnmatch`
semantics on the full name. A list of 10,000 names plus 50 patterns is well under 1 MB and matches a feed
row in microseconds.

## 4. How it works

### 4.1 Feed filtering (approach A)

`ingest.changes_since` takes an optional `watch` matcher. Rows for unlisted packages are dropped right
after the feed page is parsed, before any packument fetch. The watermark still advances over the whole
page, so the cursor moves at feed speed. The feed-retry table (#13) applies only to listed packages.

Rejected alternatives: polling every listed package's packument each tick (1,000 packages means 1,000
metadata downloads per tick, some tens of MB), and a hybrid of the two (more code, no gain).

### 4.2 Startup scan

A new table `watchlist_baseline(package TEXT PRIMARY KEY, done_at TEXT, result TEXT)` records which
listed packages have had their latest release reviewed.

- Each tick, before the feed page, up to `watchlist_baseline_per_tick` (default 50) listed packages
  without a row are processed. For each: fetch its packument, take the `latest` dist-tag, and send
  `NewRelease(package, latest, serial=<current cursor>)` through the normal pipeline (fetch, diff against
  its predecessor, triage, review). If that release is already recorded, it is skipped. The row records
  the outcome: `scanned`, `no_versions`, `not_found` (404) or `fetch_failed` (retried next tick, like any
  fetch failure).
- Baseline releases never move the cursor, which still tracks the feed only.
- Patterns are not expanded at startup: `@gooddata/*` can't be enumerated without a search API the tool
  doesn't use. Patterns match feed rows from then on, and the spec says so in `--help` and the docs.
- While the baseline is incomplete, `watch` treats itself as behind and doesn't sleep, as it does with a
  feed backlog. Each tick prints `watchlist baseline: 120/1,000 packages`.
- Packages added to the list later get their baseline on the next tick. Packages removed stop being
  watched; their rows stay (harmless).

Cost: per package, one metadata download plus two tarballs. At today's download speed that is minutes to
about an hour for 1,000 packages. Most releases score 0 and never reach the model.

### 4.3 Fresh database

On a fresh database with `--watchlist`, the cursor is seeded to npm's head as today (or N changes back
with `--recent N`), and the baseline covers "what's already published".

### 4.4 Visibility

- `pending` and the dashboard status line show `watchlist: <file> · 1,000 packages, 3 patterns ·
  baseline 1,000/1,000`.
- The dashboard is otherwise unchanged: the same verdict cards, alerts and review queue.

## 5. Components

| Unit | Responsibility |
|---|---|
| `npmdiffwatch/watchlist.py` (new) | `load(path) -> Watchlist` (format detection and parsing), `Watchlist.matches(name)`, `Watchlist.names`, `Watchlist.patterns`, `Watchlist.skipped` |
| `ingest.changes_since(..., watch=None)` | drop unlisted rows before fetching |
| `store` | `watchlist_baseline` table and helpers |
| `orchestrator.run_once(..., watch=None)` | baseline step, then the filtered feed page; `watch()` reloads the list each tick and counts an incomplete baseline as behind |
| `__main__` / `config` | `--watchlist` flag and `watchlist` config key; status line |

## 6. Errors

| Condition | Behavior |
|---|---|
| File missing, unreadable, or not a recognized format at start | exit with a message naming the path and the formats accepted |
| Parsed but zero valid names and zero patterns | exit: "watchlist has no packages" |
| Re-read fails mid-run | keep the last good list; warn each tick until it parses again |
| Listed package doesn't exist on npm (404) | baseline row `not_found`; still matched against the feed in case it's published later |
| Very large list (e.g. 100k names) | accepted; memory ~10 MB; baseline takes proportionally longer, with progress shown |

## 7. Testing

- Parsers: fixtures for a names file (exact, scoped, patterns, comments, invalid entries), lockfile v1
  and v3 (nested and scoped `node_modules` paths), CycloneDX with nested components, SPDX with purl refs.
- Feed filtering: an unlisted row never triggers a packument fetch; the watermark covers the whole page.
- Baseline: each package once; resumable after restart; `fetch_failed` retried; 404 recorded; never
  moves the cursor; progress counted; `watch` doesn't sleep while incomplete.
- Reload: the list changes between ticks; a broken re-read keeps the last good list.
- Errors: missing, empty and unrecognized files stop the run with the message above.
- Live: a 1,000-name list (e.g. from a real project's lockfile) on the RTX endpoint; the cursor stays within
  one page of head (criterion 2); record the baseline time.

## 8. Out of scope (v1)

yarn.lock and pnpm-lock.yaml parsing; per-version pinning ("alert when a newer version than mine
appears"); expanding patterns at startup; separate databases per watchlist; the PyDiffWatch port.
