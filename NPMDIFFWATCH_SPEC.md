# NpmDiffWatch — Specification

Poll the npm registry for new package versions, statically review each version-to-version diff for malicious code, and alert before a compromised release spreads.

## 1. Overview

NpmDiffWatch is a static, no-execution supply-chain scanner for npm. It follows the registry's replication
feed, downloads each new release's `.tgz` into memory (never to disk, never installed), diffs it against the
prior version, scores the change with a pure-data rules engine, and escalates anything suspicious to an LLM
reviewer for a verdict. State is a single local SQLite database.

The design rests on a few invariants:

- **No execution.** Analyzed packages are data, never code — no `npm install`, no lifecycle scripts, no
  `node`, `require`, or `eval` of package content.
- **Default-deny egress.** A process-wide socket allowlist (`egress.py`) restricts outbound traffic to the
  npm registry, the configured reviewer endpoint, and an optional webhook.
- **Rules are pure data.** Detection logic is YAML walked by a safe matcher — no `eval`/`exec`, no
  expression strings.
- **Local-first review.** The reviewer targets a local, open-source LLM (any OpenAI-compatible endpoint),
  with hosted/Anthropic backends as options.

## 2. Pipeline

```
npm registry
    │
    ├── ingest.changes_since() → NewRelease[]
    │       (replication _changes feed, monotonic seq cursor)
    │
    ├── fetcher.fetch(cfg, rel) → ArtifactSet
    │       ├── quarantine check
    │       ├── registry /{package} → packument JSON
    │       ├── pick_predecessor() from version-timeline
    │       ├── download .tgz (size-capped, in-memory)
    │       ├── extract tgz (streamed, bounded, never to disk)
    │       ├── classify files: JS/TS/JSON/binary/other
    │       ├── parse package.json → scripts, bin, dependencies, etc.
    │       └── screen_added_deps() — typosquat / confusion / brand-new
    │
    ├── differ.build_diff(old, new) → Diff
    │       (difflib on .js/.ts/.mjs/.cjs, package.json, lockfiles)
    │
    ├── engine.triage(diff, cfg, ruleset) → TriageResult
    │       ├── facts.build_facts() — JS/TS AST analysis
    │       └── rules.evaluate() per scope
    │
    ├── [if escalate] reviewer.review(diff, triage) → Verdict
    │
    ├── notifier.emit(cfg, conn, verdict)
    │
    └── store.record_verdict(conn, verdict)
```

## 3. npm Facts (`facts.py`)

Facts are derived from a JavaScript/TypeScript AST. NpmDiffWatch parses with **tree-sitter**
(`tree-sitter` + `tree-sitter-javascript`): in-process, no `node` subprocess, no execution risk, and a
concrete syntax tree with enough structure for import/call resolution across JS, TS, and JSON.

### JS Fact Categories

```python
# Execution primitives — turn a string into running code
_PRIM_EXEC = {
    "eval", "Function", "setTimeout", "setInterval",
    "new Function",
}

# Process / OS — spawn external commands
_PRIM_PROCESS = {
    "exec", "execSync", "execFile", "execFileSync",
    "spawn", "spawnSync", "fork",
    "child_process.exec", "child_process.execSync",
    "child_process.spawn", "child_process.fork",
}

# Network egress
_PRIM_NETWORK = {
    "fetch", "http.request", "https.request",
    "net.connect", "dgram.createSocket",
    "axios.post", "request.get", "got.get",
}

# Decode / deobfuscate
_PRIM_DECODE = {
    "Buffer.from", "atob", "btoa",
    "String.fromCharCode",
    "toString('base64')",
}

# Credential / secret access
_PRIM_CREDENTIAL = {
    "process.env", "fs.readFileSync", "fs.readFile",
    "require('dotenv').config",
}

# File-system manipulation
_PRIM_FILE = {
    "fs.writeFileSync", "fs.writeFile", "fs.appendFile",
    "fs.chmod", "fs.copyFile",
}

# Prototype pollution
_PRIM_PROTO = {
    "__proto__", "Object.assign", "Object.defineProperty",
    "constructor.prototype",
}

# Dynamic require — import with a non-literal path
_PRIM_DYNAMIC_REQUIRE = {
    "require", "import",
}
```

### Location Classification

Code in paths npm auto-runs at install or invocation is weighted more heavily:

```python
AUTOEXEC = frozenset({
    "package.json",                                   # scripts field
    "preinstall.js", "install.js", "postinstall.js",  # lifecycle hooks
    ".npmrc",                                          # npm config
    "bin/*.js", "bin/*.mjs",                           # CLI entry
    "main.js", "index.js",                            # common entry
})
# The package.json "bin", "main", and "scripts" fields compute the actual autoexec paths.
```

### Binary Detection

- `.node` — native Node addons
- `.wasm` — WebAssembly
- Executable blobs with high entropy

### Dependency Screening

- Packument lookup: `https://registry.npmjs.org/{name}`
- Typosquat distance: Levenshtein against the vendored top-npm-names corpus
- Dependency confusion: check whether an internal name resolves on the public registry
- Brand-new detection: check the packument `time` field (`dep_brandnew_days`, default 30)

## 4. Detection Rules (`rules/community/`)

### Scope: `code` (JS/TS files)

| Rule | Weight | Location-scaled? | Description |
|---|---|---|---|
| `js-eval` | 15 | yes | `eval()` or `Function()` with dynamic string |
| `js-child-process` | 20 | yes | `child_process.exec` / `spawn` |
| `js-install-script` | 40 | no | Dangerous primitive inside a lifecycle script |
| `js-decode-exec` | 45 | no | decode + exec combo (obfuscated loader) |
| `js-cred-network` | 45 | no | credential access + network egress |
| `js-proto-pollution` | 25 | yes | `__proto__` assignment or `Object.assign` |
| `js-dynamic-require` | 15 | yes | `require` with non-literal argument |
| `js-obfuscated-string` | 10 | yes | Long encoded string / high-entropy blob |
| `js-syntax-error` | 20 | true | Syntax error in added code |

### Scope: `package_json`

| Rule | Weight | Description |
|---|---|---|
| `pkg-install-scripts` | 40 | Added `scripts.preinstall/install/postinstall` |
| `pkg-bin-rewrite` | 30 | Modified `bin` field to unexpected path |
| `pkg-main-rewrite` | 25 | Modified `main` field to suspicious file |
| `pkg-new-dependency` | 10 | Added dependency (volume signal) |

### Scope: `dep`

| Rule | Weight | Description |
|---|---|---|
| `dep-typosquat` | 40 | Edit-distance typosquat on a known package |
| `dep-confusion` | 40 | Internal name resolvable on the public registry |
| `dep-brand-new` | 20 | Package created < 30 days ago |

### Scope: `lockfile`

| Rule | Weight | Description |
|---|---|---|
| `lock-integrity-change` | 35 | Changed integrity hash without a version change |
| `lock-new-package` | 10 | New entry in the lockfile |

## 5. Quarantine List

`quarantine.py` holds a static denylist of confirmed-malicious npm package names. Quarantined packages are
never re-fetched.

## 6. Differ

`difflib.SequenceMatcher` over added/changed source, with structure-aware handling for manifests:

- `package.json` — diffed as JSON, tracking field-level changes (not line-level)
- `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` / `npm-shrinkwrap.json` — structure-aware diff

## 7. Ingest / Registry API

NpmDiffWatch follows npm's **replication `_changes` feed** — the registry's monotonic change stream — which
maps directly onto a resumable serial cursor.

- **Head of feed:** `GET {npm_replicate}/` → `update_seq` (the current sequence head).
- **Window:** `GET {npm_replicate}/_changes?since={seq}&limit={n}` → change rows, each carrying a package
  `id` and a monotonic `seq`.
- **Version resolution:** a `_changes` row names the package and a rev, not a version. NpmDiffWatch resolves
  the most likely new version by fetching the packument and picking the newest-by-publish version not already
  recorded (falling back to `dist-tags.latest`).
- **Cursor:** the highest consumed `seq` (the window's `last_seq`) becomes the watermark, so windows
  containing only deletes or non-release changes still advance the cursor instead of being re-read forever.

Defaults: `npm_replicate = "https://replicate.npmjs.com/registry"`,
`npm_registry = "https://registry.npmjs.org"`.

## 8. Store Schema

A single SQLite database under `.diffwatch/` holds the cursor, releases, alerts, and verdicts. npm-specific
fields on the `releases` table:

```sql
--   packument_json TEXT    (cached packument fields)
--   scripts_json TEXT      (pre/post/install scripts)
--   has_lockfile INTEGER   (does this release ship a lockfile)
--   has_shrinkwrap INTEGER (npm-shrinkwrap.json present)
--   evidence TEXT          (flagged payload code captured at detection time)
```

## 9. Config

```toml
# NpmDiffWatch config (defaults shown; see examples/ for endpoint wiring)
npm_registry  = "https://registry.npmjs.org"
npm_replicate = "https://replicate.npmjs.com/registry"

# download / extraction caps (bytes)
max_download_bytes     = 50_000_000
max_total_bytes        = 100_000_000
max_decompressed_bytes = 120_000_000
max_member_bytes       = 10_000_000
max_members            = 5000
max_package_json_bytes = 100_000

max_releases_per_run = 200
new_package_policy   = "surface"   # | "full" | "skip"
threshold_t          = 40.0        # escalate to the reviewer at/above this triage score
reviewer_enabled     = true

# [reviewer] block — provider/base_url/model/structured_output, same for every endpoint
```

## 10. The No-Execution Invariant

The hard guarantee, enforced throughout the pipeline and by the containment test suite:

- **Never execute** an analyzed package. No `npm install`, no lifecycle-script execution, no `node`,
  `require`, or `eval` of package content.
- **Never extract to disk.** The `.tgz` is streamed and read in memory (`tarfile.open(mode="r|")` with
  bounded readers and member/size/name/decompressed caps) — never `extractall`, never written out.
- **Egress is default-deny.** The `egress.py` allowlist permits only the npm registry, the reviewer
  endpoint, and the webhook; package bytes reach the model only as request-body text, never as a URL it
  fetches.
- **Rules stay data.** The YAML matcher has no `eval`/`exec`; a malformed rule is rejected by the
  fail-closed validator, never run.
