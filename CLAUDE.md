# NpmDiffWatch — AI Agent Guide

## Project Structure

```
npmdiffwatch/              # Core package
  __init__.py
  __main__.py              # CLI entry point
  config.py                # Config dataclasses + TOML loader
  models.py                # Data models (NewRelease, ArtifactSet, Diff, Verdict, etc.)
  backends.py              # LLM backends (OpenAI-compatible + Anthropic)
  egress.py                # Default-deny egress guard (socket.getaddrinfo wrapper)
  notifier.py              # Alert emitter (stdout + webhook)
  store.py                 # SQLite store (cursor, releases, verdicts, alerts)
  quarantine.py            # Static denylist for confirmed malicious npm packages
  deps.py                  # Dependency reputation gate (typosquat detection)
  ingest.py                # npm registry search API + packument poller
  fetcher.py               # npm .tgz download + in-memory extraction + baseline resolution
  differ.py                # Version-to-version diff (difflib + JSON-aware for package.json)
  facts.py                 # JS/TS AST analysis via tree-sitter
  rules.py                 # YAML rule loader (fail-closed validator + safe matcher)
  engine.py                # Rules engine triage (facts x rules)
  reviewer.py              # LLM reviewer prompt builder + verdict parser
  orchestrator.py          # Pipeline coordinator (run_once, seed, adjudicate, etc.)
  data/
    top_npm_names.txt      # Vendored top npm names for typosquat corpus
rules/community/           # Shipped YAML detection rules
  code.yaml                # JS/TS code-level rules
  package_json.yaml        # package.json field change rules
  deps.yaml                # Dependency reputation rules
  lockfile.yaml             # Lockfile integrity rules
  maintainer.yaml          # Maintainer set change rules
  binaries.yaml            # Binary foreign-language rules
examples/                  # Example config files
  local-qwen.toml
  ollama.toml
  llamacpp.toml
  openai.toml
  anthropic.toml
```

## Key Architecture Rules

- **No execution**: Never `npm install`, never `node eval`. All analysis is static, in-memory.
- **No execution** of extracted .tgz files — streamed extract, never `extractall()`, never `fs.write()`.
- **Default-deny egress**: Only the configured npm registry, LLM endpoint, and webhook are contactable.
- **Rules are pure data**: YAML files walked by a matcher — no eval/exec/expression strings.
- **LLM injection defense**: Per-request CSPRNG markers around untrusted package content.
- **Evidence persistence**: Flagged payload diffs stored in SQLite for takedown reports.
- **Cursor-based**: Incremental scanning with `flock` mutual exclusion.

## Testing

```bash
pip install -e ".[dev]"
pytest -v
```

## Lint / Typecheck

```bash
ruff check npmdiffwatch/ tests/
```

## Pipeline Flow

```
npm registry search → ingest() → [NewRelease]
  → fetcher() → ArtifactSet (new + prior .tgz files in memory)
    → differ() → Diff (FileDiff[] + package.json changes + lockfile meta)
      → engine.triage() → TriageResult (score + FiredRule[])
        → [if escalate] reviewer.review() → Verdict (LLM classification)
          → notifier + store → alerts + SQLite
```
