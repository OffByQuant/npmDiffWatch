# NpmDiffWatch

Poll the npm registry for new package versions, statically review each version-to-version diff for malicious code, and alert before a compromised release spreads.

## Quick Start

```bash
# Install from source (not published to PyPI):
pip install -e .

# Seed the cursor to now (start monitoring from this point):
npmdiffwatch seed-now

# Run one polling tick:
npmdiffwatch run

# See what was flagged:
npmdiffwatch pending

# To use a config file (see examples/):
npmdiffwatch -c examples/ollama.toml run
```

## Architecture

Same pipeline as PyDiffWatch — registry-agnostic modules ported directly, with npm-specific rewrites for:

- **ingest**: npm replication `_changes` feed (monotonic `seq` cursor) + per-package packument fetch
- **fetcher**: npm `.tgz` download and in-memory extraction (streamed, capped, never to disk)
- **facts**: JavaScript/TypeScript AST analysis via tree-sitter

## Requirements

- Python 3.11+
- tree-sitter >= 0.22 + tree-sitter-javascript (for JS/TS analysis)
- PyYAML >= 6.0 (for rule loading)

## Config

Config templates in `examples/`:

| File | Backend |
| --- | --- |
| `local-qwen.toml` | Local Qwen (OpenAI-compatible server) |
| `ollama.toml` | Ollama |
| `llamacpp.toml` | llama.cpp server |
| `openai.toml` | OpenAI API |
| `anthropic.toml` | Anthropic API |
| `deepseek.toml` | DeepSeek / reasoning ("thinking") models |

Reasoning models (DeepSeek and the like) spend output-token budget on internal
thinking and can truncate the JSON verdict. The reviewer keeps `classification`
(which drives alerting) mandatory and defaults the rest, so a truncated verdict
still alerts; use `structured_output = "json_object"` and, if needed,
`[reviewer.extra_body]` to disable thinking. See `examples/deepseek.toml`.

Key options in `npmdiffwatch.toml`:

```toml
npm_registry = "https://registry.npmjs.org"
npm_replicate = "https://replicate.npmjs.com/registry"
max_download_bytes = 50_000_000
max_members = 5000
new_package_policy = "surface"  # "surface" (default) | "skip" | "full"

[reviewer]
provider = "openai"
base_url = "http://localhost:11434/v1"
model = "qwen2.5:7b"
```

## License

MIT
