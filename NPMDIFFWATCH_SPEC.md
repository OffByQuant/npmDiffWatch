# NpmDiffWatch — Specification

Poll the npm registry for new package versions, statically review each version-to-version diff for malicious code, and alert before a compromised release spreads.

## 1. Relationship to PyDiffWatch

PyDiffWatch's pipeline architecture is registry-agnostic. The reusable modules (zero-charge port) vs npm-specific replacements are:

| Layer | PyDiffWatch | NpmDiffWatch | Port? |
|---|---|---|---|
| `backends.py` | OpenAI-compatible + Anthropic | Identical | **Direct** |
| `egress.py` | Socket-allowlist guard | Identical | **Direct** |
| `store.py` | SQLite schema | Same tables, npm-specific fields | **Trivial** |
| `notifier.py` | Stdout + webhook | Identical | **Direct** |
| `rules.py` | YAML loader + safe evaluator | Identical matcher, npm scopes | **Direct** |
| `engine.py` | Triage: facts × rules | Identical loop, npm facts | **Direct** |
| `models.py` | Diff/Verdict/TriageResult | Same shape, npm package attrs | **Trivial** |
| `config.py` | TOML config dataclasses | Same structure, npm caps | **Trivial** |
| `reviewer.py` | LLM prompt builder | Identical (diff text is text) | **Direct** |
| `ingest.py` | PyPI XML-RPC changelog | npm registry `/_couchdb` changes feed | **Rewrite** |
| `fetcher.py` | PyPI JSON API + sdist | npm registry API + `.tgz` packument | **Rewrite** |
| `differ.py` | difflib.SequenceMatcher | Same tool, npm file structure | **Trivial** |
| `facts.py` | Python `ast.parse` | JavaScript/TypeScript AST parser | **Rewrite** |
| `orchestrator.py` | Pipeline coordinator | Same concurrency model | **Trivial** |

Ported module counts: ~8 direct, 2 trivial, 3 rewrite.

## 2. Pipeline

```
npm registry
    │
    ├── ingest.poll() → NewRelease[]
    │       (npm couchdb changes feed or registry search API)
    │
    ├── fetcher.fetch(cfg, rel) → ArtifactSet
    │       ├── quarantine check
    │       ├── registry /{package} → packument JSON
    │       ├── pick_predecessor() from version-timeline
    │       ├── download .tgz (size-capped, in-memory)
    │       ├── extract tgz (streamed, bounded, never to disk)
    │       ├── classify files: JS/TS/JSON/binary/other
    │       ├── parse package.json → scripts.bin.dependencies, etc.
    │       └── screen_added_deps() — typosquat / confusion / brand-new
    │
    ├── differ.build_diff(old, new) → Diff
    │       (difflib on .js/.ts/.mjs/.cjs, package.json, lockfiles)
    │
    ├── engine.triage(diff, cfg, ruleset) → TriageResult
    │       ├── facts.build_facts() — JS AST analysis
    │       └── rules.evaluate() per npm scope
    │
    ├── [if escalate] reviewer.review(diff, triage) → Verdict
    │       (identical prompt builder, backends)
    │
    ├── notifier.emit(cfg, conn, verdict)
    │       (identical)
    │
    └── store.record_verdict(conn, verdict)
            (identical, npm-specific metadata fields)
```

## 3. npm-Specific Facts (replaces `facts.py`)

Facts need a JavaScript/TypeScript AST parser. Choices:

| Parser | Python binding | JS binding | Notes |
|---|---|---|---|
| **esprima** | `esprima-python` | `esprima` | Mature, ES5+, slow in Python |
| **acorn** | `pyacorn` (thin) | `acorn` | Python bindings exist |
| **node subprocess** | Python calls `node -e` | Any | Adds `node` dependency; containment concern |
| **tree-sitter** | `tree-sitter` + `tree-sitter-javascript` | tree-sitter | Parse in Python, C lib, fast, supports JS/TS/CSS/JSON |

**Recommendation: tree-sitter.** Parses JS, TS, JSON in-process without `node`. Already has Python bindings. No exec risk. Gives CST with enough structure for import/call resolution.

### JS Fact Categories (analogous to `_PRIM_BINDINGS` in `facts.py`)

```python
# Execution primitives — analogous to Python exec/eval/compile
_PRIM_EXEC = {
    "eval", "Function", "setTimeout", "setInterval",  # string→code
    "new Function",                                     # same
}

# Process / OS — analogous to subprocess
_PRIM_PROCESS = {
    "exec", "execSync", "execFile", "execFileSync",
    "spawn", "spawnSync", "fork",
    "child_process.exec", "child_process.execSync",
    "child_process.spawn", "child_process.fork",
}

# Network — analogous to urllib
_PRIM_NETWORK = {
    "fetch", "http.request", "https.request",
    "net.connect", "dgram.createSocket",
    "axios.post", "request.get", "got.get",
}

# Decode / deobfuscate — analogous to base64/bytes
_PRIM_DECODE = {
    "Buffer.from", "atob", "btoa",
    "String.fromCharCode",
    "toString('base64')",
}

# Credential access — analogous to reading env/file
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

# Dynamic require — analogous to import with non-literal path
_PRIM_DYNAMIC_REQUIRE = {
    "require", "import",                      # with non-literal argument
}
```

### Location Classification (same concept, npm paths)

```python
AUTOEXEC = frozenset({
    "package.json",                             # scripts field
    "preinstall.js", "install.js", "postinstall.js",  # lifecycle
    ".npmrc",                                    # npm config
    "bin/*.js", "bin/*.mjs",                    # CLI entry
    "main.js", "index.js",                     # Common entry
})

# Use npm package.json "bin", "main", "scripts" to compute actual autoexec paths.
```

### Binary Detection (same logic as PyDiffWatch)

- `.node` — native Node addons
- `.wasm` — WebAssembly
- Executable blobs with high entropy

### Dependency Screening (same as PyDiffWatch but npm names)

- npm registry API: `https://registry.npmjs.org/{name}`
- Typosquat distance: Levenshtein against top-5000 npm names
- Dependency confusion: check if package exists on public registry
- Brand-new detection: check `time` field in packument

## 4. npm-Specific Rules (`rules/community/`)

### Scope: `code` (JS/TS files)

| Rule | Weight | Location-scaled? | Description |
|---|---|---|---|
| `js-eval` | 15 | yes | `eval()` or `Function()` with dynamic string |
| `js-child-process` | 20 | yes | `child_process.exec` / `spawn` |
| `js-install-script` | 40 | no | Dangerous primitive inside lifecycle script |
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
| `dep-typosquat` | 40 | Edit-distance typosquat on known package |
| `dep-confusion` | 40 | Internal name resolvable on public registry |
| `dep-brand-new` | 20 | Package created <30 days ago |

### Scope: `lockfile`

| Rule | Weight | Description |
|---|---|---|
| `lock-integrity-change` | 35 | Changed integrity hash without version change |
| `lock-new-package` | 10 | New entry in lockfile |

## 5. Quarantine List

Same concept as `quarantine.py` but for npm package names.

## 6. Differ

Same `difflib.SequenceMatcher` approach as PyDiffWatch. Special handling for:

- `package.json` — diff as JSON, track field-level changes (not line-level)
- `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` — structure-aware diff

## 7. Ingest / Registry API

npm has no XML-RPC. Options for polling:

| Method | Pros | Cons |
|---|---|---|
| CouchDB changes feed `/_couchdb/registry/_changes` | Complete history, real-time | Heavy; npm deprecated discovery |
| Registry search `/-/v1/search?by=maintenance` | Simple | Search quality, misses bumps |
| **Packument cache diff** — track known versions, periodically fetch `/{package}` for watched packages | Targeted, cheap | Only works for known packages |
| **Recommended: combined** — npm `/-/v1/search?by=maintenance` for discovery + per-package packument fetch | Covers new + updates | |

## 8. Store Schema Changes

Reuse PyDiffWatch SQLite schema, add:

```sql
-- npm-specific metadata in releases table:
--   packument_json TEXT    (cached packument fields)
--   scripts_json TEXT      (pre/post/install scripts)
--   has_lockfile INTEGER   (does this release ship a lockfile)
--   has_shrinkwrap INTEGER (npm-shrinkwrap.json present)
```

## 9. Config (npm-specific fields)

```toml
# NpmDiffWatch config
npm_registry = "https://registry.npmjs.org"
# unpack caps
max_tgz_bytes = 50_000_000
max_files = 5000
max_package_json_size = 100_000
new_package_policy = "skip"  # | "surface" | "full"
# same reviewer block, same threshold, same store
```

## 10. What Changes NOT to Make From PyDiffWatch

- **Container model**: Same no-execution invariant. Never `npm install`, never `node` eval.
- **Egress guard**: Same implementation in `egress.py`. Install at CLI entry only.
- **Backend config**: Same `reviewer.toml` format. OpenAPI-compatible + Anthropic.
- **Rules engine**: Same `rules.py` (YAML → validate → match tree). Just add npm scopes.
- **LLM prompts**: Same `reviewer.py` structure. npm-specific system prompt examples.
