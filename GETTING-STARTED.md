# Getting Started with NpmDiffWatch

A step-by-step guide from install to running NpmDiffWatch continuously under your own harness. For the
project overview and the no-execution security model, see the [README](README.md); for the detection
rules, see the YAML files in [`rules/community/`](rules/community).

**Contents**
1. [Install](#1-install)
2. [Choose and wire your LLM endpoint](#2-choose-and-wire-your-llm-endpoint)
3. [API keys](#3-api-keys)
4. [Structured-output modes](#4-structured-output-modes)
5. [The operating loop](#5-the-operating-loop)
6. [Running on a harness](#6-running-on-a-harness-cron--systemd--docker--ci)
7. [State, persistence & containment](#7-state-persistence--containment)
8. [Alerts](#8-alerts)
9. [Heuristic-only mode (no LLM)](#9-heuristic-only-mode-no-llm)
10. [Troubleshooting](#10-troubleshooting)
11. [Detection scope on brand-new packages](#11-detection-scope-on-brand-new-packages)

---

## 1. Install

NpmDiffWatch is a Python tool that statically analyzes npm packages — you need Python, not Node.

```bash
git clone https://github.com/OffByQuant/npmDiffWatch npmdiffwatch && cd npmdiffwatch
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                 # core: stdlib + PyYAML + tree-sitter + tree-sitter-javascript
pip install -e ".[claude]"       # ONLY if you'll use the Anthropic provider (pulls in the anthropic SDK)
```

Requires Python 3.11+ (the config loader uses the stdlib `tomllib`). Verify the CLI:

```bash
npmdiffwatch -c examples/local-qwen.toml --help
```

---

## 2. Choose and wire your LLM endpoint

NpmDiffWatch scores every changed release with the rules engine and escalates anything at or above
`threshold_t` to an LLM for a verdict. The reviewer talks to **any OpenAI-compatible endpoint** or the
**Anthropic** API — pick the one matching the model server you run, copy its example to
`npmdiffwatch.toml`, and edit `model`/`base_url`.

```bash
cp examples/ollama.toml npmdiffwatch.toml      # then edit
```

**Local, OpenAI-compatible, no key** — llama-swap / vLLM / LM Studio
(e.g. `vllm serve Qwen/Qwen2.5-Coder-7B-Instruct --port 8000`) — `examples/local-qwen.toml`:

```toml
[reviewer]
provider = "openai"
base_url = "http://localhost:8000/v1"
model = "qwen-singleshot"            # the model name your server exposes
structured_output = "json_schema"
```

**Ollama** (`ollama serve` exposes `/v1` on 11434; `ollama pull qwen2.5`) — `examples/ollama.toml`:

```toml
[reviewer]
provider = "openai"
base_url = "http://localhost:11434/v1"
model = "qwen2.5:7b"
structured_output = "json_object"    # Ollama json_schema support varies by model; loose JSON is safe
```

**llama.cpp** (`llama-server -m model.gguf --port 8080`) — `examples/llamacpp.toml`:

```toml
[reviewer]
provider = "openai"
base_url = "http://localhost:8080/v1"
model = "qwen-singleshot"
structured_output = "json_schema"    # recent GBNF-backed builds; drop to json_object on older ones
```

**OpenAI** — `examples/openai.toml`:

```toml
[reviewer]
provider = "openai"
base_url = "https://api.openai.com/v1"
model = "gpt-4o"
api_key_env = "OPENAI_API_KEY"
structured_output = "json_schema"
```
then `export OPENAI_API_KEY=sk-...` (see §3).

**OpenRouter / Groq / Together / any hosted OpenAI-compatible gateway** — same shape as OpenAI with that
gateway's `base_url` and key variable:

```toml
[reviewer]
provider = "openai"
base_url = "https://openrouter.ai/api/v1"
model = "qwen/qwen-2.5-coder-32b-instruct"
api_key_env = "OPENROUTER_API_KEY"
structured_output = "json_object"
```

**DeepSeek / reasoning ("thinking") models** — `examples/deepseek.toml`:

```toml
[reviewer]
provider = "openai"
base_url = "https://api.deepseek.com/v1"
model = "deepseek-chat"
api_key_env = "DEEPSEEK_API_KEY"
structured_output = "json_object"   # DeepSeek 400s on strict json_schema — use json_object
max_output_tokens = 32000           # reasoning eats the budget; leave room for thinking + the verdict

# Optional: pass provider-specific knobs verbatim into the request body.
# [reviewer.extra_body]
# reasoning = { enabled = false }   # disable thinking to reclaim output budget (key is provider-specific)
```
Reasoning models spend output tokens on internal thinking, so a small `max_output_tokens` truncates the
JSON verdict; 32000 leaves room for both. The reviewer keeps `classification` (which drives alerting)
mandatory and fills defaults for the other fields, so even a truncated verdict still carries the verdict
and alerts. Set `structured_output = "json_object"` — the strict `json_schema` variant is an OpenAI
extension DeepSeek doesn't accept.

**Anthropic** (needs `pip install -e ".[claude]"`) — `examples/anthropic.toml`:

```toml
[reviewer]
provider = "anthropic"
model = "claude-sonnet-4-6"
escalation_model = "claude-opus-4-8"   # optional: escalate low-confidence verdicts to Opus
structured_output = "json_schema"
```
then `export ANTHROPIC_API_KEY=sk-ant-...` (see §3).

---

## 3. API keys

**The rule: the config file holds the env-var NAME; the shell holds the key.** No secret ever lands in a
file you might commit, so any `npmdiffwatch.toml` is safe to check in.

For every OpenAI-compatible provider, wire a key in two steps:

1. In `[reviewer]`, set `api_key_env` to the **name** of the variable (not the key):
   ```toml
   api_key_env = "OPENAI_API_KEY"
   ```
2. Export the key in the environment that runs `npmdiffwatch`:
   ```bash
   export OPENAI_API_KEY="sk-..."
   ```

At request time NpmDiffWatch reads `$OPENAI_API_KEY` and sends `Authorization: Bearer <key>`. The variable
name is yours to choose — use a distinct one per provider so multiple configs coexist (`OPENAI_API_KEY`,
`OPENROUTER_API_KEY`, `GROQ_API_KEY`, …). If `api_key_env` is unset, or the variable is empty, **no auth
header is sent** — which is exactly what a local server wants, so just omit `api_key_env` for
llama-swap / vLLM / Ollama / llama.cpp / LM Studio.

**Anthropic is the exception.** The Anthropic SDK reads `ANTHROPIC_API_KEY` from the environment itself,
so `api_key_env` is **ignored** when `provider = "anthropic"`. Just `export ANTHROPIC_API_KEY=...`. If the
key is missing, that run logs a notice and falls back to heuristic-only — it does not crash.

> Getting the key to your *scheduler* (cron/systemd/Docker/CI), not just your login shell, is the part
> people miss — see §6 for how each harness injects it.

---

## 4. Structured-output modes

`structured_output` controls how strictly the model is made to return machine-readable JSON:

| mode | meaning | use when |
|---|---|---|
| `json_schema` | strict, server-enforced schema | the server supports it (OpenAI, vLLM, recent llama.cpp, Anthropic) — **preferred** |
| `json_object` | "return valid JSON", no schema | Ollama, DeepSeek, and many gateways |
| `none` | prompt-only; nothing enforces the shape | very small models / last resort |

Regardless of mode, the parsed verdict is **validated client-side** against the review schema. A verdict
with an out-of-range enum or a missing `classification` is rejected, and the release degrades to a
heuristic alert — never a silent pass. Non-critical fields that a reasoning model truncates are filled
from defaults so the verdict still lands. Start at `json_schema`; step down only if the logs show
`ReviewUnavailable: non-JSON content`.

---

## 5. The operating loop

**First time only** — set the starting point so you process *new* releases, not all of npm history:

```bash
npmdiffwatch -c npmdiffwatch.toml seed-now
```

(You can skip this: a plain `run` on a fresh database self-seeds the cursor to "now" and processes
nothing that tick, then the next tick polls forward. Use `run --backfill` to process historical releases
from the current replication sequence instead.)

**Each tick** — this is what your scheduler runs:

```bash
npmdiffwatch -c npmdiffwatch.toml run
```

`run` pulls every release since the last cursor (capped by `max_releases_per_run`), diffs each against
its prior version, scores it with the ruleset, and escalates anything ≥ `threshold_t` to the reviewer.
Clear-malicious verdicts alert immediately; borderline "suspicious" ones queue for your judgement.

**Triage the queue:**

```bash
npmdiffwatch -c npmdiffwatch.toml pending                      # suspicious releases awaiting a verdict, with diffs
npmdiffwatch -c npmdiffwatch.toml adjudicate <id> malicious --note "curl|sh in postinstall"
npmdiffwatch -c npmdiffwatch.toml evidence <id>                # print the stored flagged payload for a release
```

`adjudicate` records `benign` | `malicious` | `suspicious`; a non-benign call emits an alert. `evidence`
prints the payload code captured **at detection time** and stored in the DB, so it survives the package
later being pulled from npm. To backfill evidence for older flagged rows captured before evidence storage
existed:

```bash
npmdiffwatch -c npmdiffwatch.toml capture-evidence                 # all reportable rows missing evidence
npmdiffwatch -c npmdiffwatch.toml capture-evidence --release-id <id>
npmdiffwatch -c npmdiffwatch.toml capture-evidence --all           # widen to every fired-rule row (more re-fetches)
```

---

## 6. Running on a harness (cron / systemd / Docker / CI)

NpmDiffWatch is a plain CLI over a local SQLite DB; "running it" means invoking `run` on a schedule under
whatever runtime you already operate. All four patterns below are equivalent — pick one. Concurrent runs
are safe: a second `run` that overlaps the first sees the lock, prints `run already in progress; exiting`,
and no-ops.

### cron

cron runs with a minimal environment, so inject the key via a small wrapper and use absolute paths. Keep
the key out of the crontab itself.

```bash
# /opt/npmdiffwatch/run.sh   (chmod 700)
#!/usr/bin/env bash
set -euo pipefail
cd /opt/npmdiffwatch
source ./.env                 # contains: export OPENAI_API_KEY=sk-...   (chmod 600, git-ignored)
exec .venv/bin/npmdiffwatch -c npmdiffwatch.toml run
```

```cron
*/15 * * * * /opt/npmdiffwatch/run.sh >> /opt/npmdiffwatch/run.log 2>&1
```

### systemd timer

Better isolation and journald logging. A oneshot service + a timer.

`/etc/systemd/system/npmdiffwatch.service`:
```ini
[Unit]
Description=NpmDiffWatch one tick

[Service]
Type=oneshot
WorkingDirectory=/opt/npmdiffwatch
EnvironmentFile=/opt/npmdiffwatch/.env          # KEY=VALUE lines (NO `export`), e.g. OPENAI_API_KEY=sk-...
ExecStart=/opt/npmdiffwatch/.venv/bin/npmdiffwatch -c npmdiffwatch.toml run
```

`/etc/systemd/system/npmdiffwatch.timer`:
```ini
[Unit]
Description=Run NpmDiffWatch every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now npmdiffwatch.timer
```

> `EnvironmentFile` lines are `KEY=VALUE`, **not** `export KEY=VALUE` (that's the cron wrapper's `.env`).

### Docker

Bind-mount the state directory so the cursor and history persist across container runs.

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -e .
ENTRYPOINT ["npmdiffwatch", "-c", "npmdiffwatch.toml"]
```

```bash
docker build -t npmdiffwatch .
docker run --rm -v "$PWD/.diffwatch:/app/.diffwatch" -e OPENAI_API_KEY npmdiffwatch seed-now
docker run --rm -v "$PWD/.diffwatch:/app/.diffwatch" -e OPENAI_API_KEY npmdiffwatch run
```

Schedule the `run` line from the host (cron/systemd calling `docker run`). For a **local** model, point
`base_url` at the host — `http://host.docker.internal:11434/v1` — or share a Docker network with the
model container.

### CI (GitHub Actions cron)

Works, with two caveats: the DB must persist between runs, and there's no local GPU so the reviewer must
be a **hosted** endpoint. Store the key as an Actions secret.

```yaml
on:
  schedule:
    - cron: "*/30 * * * *"
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e .
      - uses: actions/cache@v4
        with: { path: .diffwatch, key: npmdiffwatch-state }
      - run: npmdiffwatch -c npmdiffwatch.toml run
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

> The Actions cache is best-effort, not durable storage. For anything you rely on, run NpmDiffWatch on a
> host you control and keep `.diffwatch/` on a real volume.

---

## 7. State, persistence & containment

All state lives under `.diffwatch/` (paths configurable via `db_path`, `cache_dir`, `lock_path`):

- `diffwatch.sqlite` — the cursor, every processed release, verdicts, alerts, and stored payload evidence.
- `artifact_cache/` — downloaded `.tgz` tarballs (size-capped, read in memory, never installed).
- `diffwatch.lock` — an exclusive `flock` that prevents overlapping `run`s.

Persist `.diffwatch/` and you can move NpmDiffWatch between machines without losing the cursor or history.
The download/extraction caps (`max_download_bytes`, `max_member_bytes`, `max_total_bytes`,
`max_decompressed_bytes`, …) bound how much of any tarball is ever read into memory; the package is never
installed, built, `require`d, or executed — see the
[README invariant](README.md#the-one-hard-invariant-no-execution).

**Hardening (defense-in-depth).** NpmDiffWatch installs a process-wide default-deny egress allowlist
(`npmdiffwatch/egress.py`) so it can only contact the npm registry, the configured reviewer endpoint, and
an optional webhook. That guard is in-process; for production, back it with an OS-level boundary you
control — run under a container/VM or an unprivileged user, and restrict outbound traffic at the network
layer (a domain-aware proxy, a `systemd` `IPAddressAllow`/`IPAddressDeny` pair, or `nftables`) to the same
three destinations. The OS boundary is what holds if the process itself is ever compromised.

---

## 8. Alerts

Set `webhook_url` (top-level, not under `[reviewer]`) to receive each new alert as a JSON POST —
`{"text": "..."}`, Slack-incoming-webhook compatible:

```toml
webhook_url = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

Alerts are also printed to stdout and recorded (deduped) in the DB, so a webhook failure never loses one.

---

## 9. Heuristic-only mode (no LLM)

To run with no model at all — rules and weights only, no endpoint required — set:

```toml
reviewer_enabled = false
```

Every release crossing `threshold_t` becomes a heuristic alert. Useful for a first pass on a box with no
GPU and no API budget, or to keep monitoring when your endpoint is down.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ReviewUnavailable: non-JSON content` in logs | the model isn't honoring the JSON contract. Lower `structured_output` (`json_schema` → `json_object` → `none`) or use a more capable model. The release still alerted heuristically — nothing was dropped. |
| Every Anthropic run logs `heuristic-only this run` | `ANTHROPIC_API_KEY` isn't in the environment the *scheduler* uses. Put it in the systemd `EnvironmentFile` / cron wrapper / Actions secret, not just your interactive shell. |
| `401`/`403` from a hosted endpoint | `api_key_env` names a variable that's unset, empty, or wrong. Check it from the harness's environment: `echo $OPENAI_API_KEY`. |
| `400`/`ReviewUnavailable: HTTP Error 400` from DeepSeek (or another reasoning model) | the endpoint rejects strict `json_schema` (an OpenAI-only extension). Set `structured_output = "json_object"`. See `examples/deepseek.toml`. |
| DeepSeek verdicts arrive with empty `reasoning`/`cited_hunk` or `attack_type: none` | the response truncated — reasoning ate the output budget. Raise `max_output_tokens` (try 32000) and/or disable thinking via `[reviewer.extra_body]`. The `classification` still survives. |
| First `run` returns `processed 0 releases` | expected — a fresh DB seeds the cursor to "now" and processes nothing that tick; the next tick polls forward. Use `run --backfill` to process history instead. |
| `run already in progress; exiting` | a previous tick still holds the lock. Harmless; space your schedule so a tick finishes before the next fires. |
| Local endpoint refused / connection error | the model server isn't up, or `base_url` is wrong (check the port and the trailing `/v1`). From Docker, use `host.docker.internal`, not `localhost`. |

---

## 11. Detection scope on brand-new packages

The pipeline's core signal is the **version-to-version diff**, so a package's first-ever release has no
prior version to diff against. `new_package_policy` controls how those are handled:

| Value | First-release behavior |
|---|---|
| `surface` (**default**) | Scan only the files npm auto-runs at install or invocation — `package.json` (and its lifecycle scripts), the install hooks `preinstall.js` / `install.js` / `postinstall.js`, the entry points `index.js` / `main.js` / `cli.js`, and anything under `bin/` — treating each as fully added. |
| `full` | Scan **every** JS/TS source file (`.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.mts`, `.cts`, `.tsx`) in the new package as added (complete coverage, higher volume/noise). |
| `skip` | Ignore new packages entirely. |

Under the default, malware that lives in a non-auto-exec module of a brand-new package (e.g.
`lib/utils/helper.js`) is **not** scanned — first-release ≠ full scan. Set `new_package_policy = "full"`
if you want complete coverage of first releases and can absorb the extra volume.
