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
6. [The dashboard & the `watch` daemon](#6-the-dashboard--the-watch-daemon)
7. [Running on a harness](#7-running-on-a-harness-cron--systemd--docker--ci)
8. [State, persistence & containment](#8-state-persistence--containment)
9. [Alerts](#9-alerts)
10. [Heuristic-only mode (no LLM)](#10-heuristic-only-mode-no-llm)
11. [Troubleshooting](#11-troubleshooting)
12. [Detection scope on brand-new packages](#12-detection-scope-on-brand-new-packages)

---

## 1. Install

NpmDiffWatch is a Python tool that statically analyzes npm packages — you need Python, not Node.

```bash
git clone https://github.com/OffByQuant/npmDiffWatch npmdiffwatch && cd npmdiffwatch
python3 -m venv ~/diffwatch && . ~/diffwatch/bin/activate   # one venv for npmDiffWatch and PyDiffWatch
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

**Local Gemma on Apple Silicon** (llama.cpp built with Metal — the setup behind the project's Mac demos) —
`examples/local-gemma-mac.toml`:

```toml
[reviewer]
provider = "openai"
base_url = "http://127.0.0.1:8080/v1"
model = "gemma-4-12b-it-UD-Q8_K_XL.gguf"   # use the exact name your llama-server exposes
structured_output = "json_schema"
max_output_tokens = 4096
timeout = 120.0

# Gemma is a reasoning model — disable thinking so the output budget goes to the structured
# verdict instead of chain-of-thought (which otherwise eats the tokens and truncates the JSON).
[reviewer.extra_body]
chat_template_kwargs = { enable_thinking = false }
```

Serve the model first, then point NpmDiffWatch at it:

```bash
llama-server -m gemma-4-12b-it-UD-Q8_K_XL.gguf -ngl 999 --jinja -c 32768   # OpenAI-compatible API on :8080
```

The Q8 weights are ~13 GB (16 GB+ of unified memory runs it comfortably); it works on Apple Silicon via
Metal — or CPU — with no discrete GPU. This is the local, no-API-cost path the project is built around;
Gemma 4 12B (Apache 2.0) is purpose-built to run on a laptop. See the runtime numbers in the README.

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

**Model protection keys** (any provider; see §5 for what they do):

```toml
[reviewer]
# Model protection (all optional; defaults shown)
budget_safety = 0.6          # a review may be predicted to use at most this share of `timeout`
probe_timeout = 180.0        # health probe / calibration timeout
slowdown_ratio = 0.3         # below this share of measured speed counts as slow
degraded_pause_s = 900       # pause after two slow reviews in a row
host_memory_guard = "auto"   # on for loopback endpoints; true / false to force
max_swap_used_pct = 75
```

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
> people miss — see §7 for how each harness injects it.

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
nothing that tick, then the next tick polls forward. `run --recent N` (or `watch --recent N`) starts N npm
changes back instead and scans them right away. Use `run --backfill` to process historical releases
from the current replication sequence instead.)

**Each tick** — this is what your scheduler runs:

```bash
npmdiffwatch -c npmdiffwatch.toml run
```

`run` pulls every release since the last cursor (capped by `max_releases_per_run`), diffs each against
its prior version, scores it with the ruleset, and escalates anything ≥ `threshold_t` to the reviewer.
Clear-malicious verdicts alert immediately; borderline "suspicious" ones queue for your judgement.

**What the reviewer is shown, and how it decides.** Each flagged release is sent as the changed code,
the `package.json` changes, where the rules fired, and the package's description. All of it is written
by the package author, so all of it sits between random per-request markers the model is told to treat
as data, never as instructions. The description is context only: it can explain a change, but a release
whose only reviewable content is its description isn't sent at all. The verdict follows an evidence
standard. It is `malicious` only when the shown code concretely:

- **exfiltrates**: reads secrets the package didn't create (environment tokens, `~/.npmrc`, `~/.ssh`,
  `~/.aws`, other tools' credentials, browser or wallet data) and sends them off the machine;
- **runs remote or hidden code**: downloads code and runs it, or decodes a payload and runs it;
- **destroys or persists**: deletes or encrypts user files, or installs itself into shell profiles, cron
  or other tools' hooks without being asked.

Without one of these, `child_process`, `eval`, network calls and file writes are `benign`; `suspicious`
means the code points at one of them but a needed piece isn't shown.

**Binaries and large files** (native addons, WebAssembly, oversized or foreign-language files) are
flagged only when the release adds or changes them. Each is compared by SHA-256 with the previous
version, so a bundle republished unchanged by CI doesn't raise an alert.

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

**Keeping the database small.** `run` and `watch` prune the database by themselves at most once every
`prune_every_hours` (24). Pruning keeps everything a person may act on (verdicts, alerts, the review
queues and their evidence) and:

- compresses stored evidence (about 5× smaller) and drops it for releases reviewed benign or never
  escalated to the reviewer;
- deletes plain release rows older than `retention_days` (90; `0` keeps everything), except each
  package's newest release, which later diffs rely on;
- clears npm metadata documents stored by older versions (up to 65 MB each, never read), then compacts
  the file.

To prune right away:

```bash
npmdiffwatch -c npmdiffwatch.toml prune
```

No package tarballs are ever written to disk: they are downloaded and extracted in memory only.

**The LLM-review queue.** Review never blocks the scan. When the reviewer can't handle a flagged release,
the release is parked with a reason and the cursor moves on; the review input is stored (compressed) so a
later review doesn't depend on npm still hosting the tarball.

| reason | when | drained by |
|---|---|---|
| `model_busy` | the reviewer guard deferred it: breaker open after a timeout, the model degrading, or this machine short on memory | every tick, first, once the guard allows reviews |
| `endpoint_unreachable` | the model server is down (each tick prints a warning) | every tick, once it's back |
| `review_failed` | a review timed out or failed; retried at `timeout` × attempt (300s, 600s, 900s) | every tick, up to `max_review_attempts` (3) |
| `too_large` | the highest-risk file alone exceeds this endpoint's input cap (`max_input_chars`, 200k chars, or less for a slow endpoint) | every tick once it fits the cap (after calibration, or after you raise `max_input_chars`); otherwise `review-pending` with a larger-context model |

Each tick retries at most `max_pending_per_tick` (20) queued releases before scanning. The rest wait for
you — typically with a bigger model pointed at the same database:

```bash
npmdiffwatch -c frontier.toml review-pending                     # too_large + exhausted retries
npmdiffwatch -c frontier.toml review-pending --reason too_large --limit 10
```

`frontier.toml` is any reviewer config (e.g. `examples/anthropic.toml`) with the same `db_path` and a
larger `max_input_chars`. `pending` shows the queue counts; the dashboard shows them in its status strip.
A release with **no** reviewable text at all (only binary / oversized-member / ownership signals) is not
queued: no model can review it, so it goes straight to `pending` for a human.

**When a release can't be scanned.** These cases are made visible rather than dropped:

- **Refused tarball.** A tarball over the size limits, with a file path that escapes the package, or that
  isn't a readable gzip is never unpacked. It still raises an alert marked
  `UNREVIEWED: npmdiffwatch refused to unpack this tarball (<reason>) … Needs manual review.` and goes to
  `pending`. Oversized or malformed archives are a known way to hide a payload from scanners, so treat
  these as a cue to look deeper.
- **One oversized file.** A single file over `max_member_bytes` (10 MB), such as a prebuilt platform
  binary or a huge bundle, doesn't stop the scan. Its contents are skipped; its path, size and SHA-256
  are recorded, and everything else in the package (package.json, install scripts, the code that loads
  the file) is scanned as usual. An oversized `.js` still fires `binary-source-too-large`, and a new
  `.node`/`.wasm` still fires `binary-new-binary`.
- **Refused download.** A tarball bigger than `max_download_bytes` (50 MB), or a new release of a package on
  the built-in quarantine list, is never downloaded. It alerts the same way (`… it was not downloaded …` or
  `… on npmdiffwatch's quarantine list …`) and goes to `pending`. The quarantine alert doesn't call the
  release malicious: it says the package had a past compromise.
- **Package metadata that fails to download** (a timeout or a registry error; a package deleted from npm
  is simply skipped) is retried on the next scans. After 4 attempts the release is given up on, and
  `pending` says so: `package metadata failed to download: 2 release(s) being retried, 1 given up on
  after 4 attempts (not scanned)`.

- **A release that fails to download or process** (a timeout, a registry error, a file the tool can't
  handle) doesn't hold up the scan: newer releases are scanned as usual, and the failed one is retried at
  the start of the next scans, with a longer download deadline each time (×2, ×3, ×4). This also covers a
  brand-new release whose tarball npm isn't serving yet. After 4 attempts it alerts as `UNREVIEWED: this
  release could not be scanned after 4 attempts (<error>) … Needs manual review.` and goes to `pending`.

Downloads have a total deadline (`fetch_deadline_s`, 120 s; `packument_deadline_s`, 300 s for package
metadata), so one stalled download can't hold up a scan.

**Model protection.** The reviewer measures your endpoint and adapts to it, so a slow or struggling
model server isn't overloaded:

- **Input size from measured speed.** The tool records how fast the endpoint reads input (from the token
  counts it reports) and caps each review input at `speed × timeout × budget_safety`. Bigger inputs go
  to the `too_large` queue. Until the first measurement, a new endpoint gets one small calibration request
  (filler text, never package content) and a 40,000-char cap.
- **Circuit breaker.** After a timeout, no more reviews are sent that batch; the next batch sends a tiny
  health probe first and resumes only if it answers within `probe_timeout`.
- **Slowdown detector.** Two reviews in a row below `slowdown_ratio` of the measured speed pause reviews
  for `degraded_pause_s` and print a warning — usually the model server is swapping; restart it. It judges
  only servers that time their own input reading (llama.cpp, llama-swap); elsewhere wall-clock time also
  counts output and model loading, so the timeout breaker is the protection.
- **One request at a time.** `watch`/`run` and `review-pending` share a lock (`<lock_path>.review`), so
  two processes never have reviews at the same endpoint at once.
- **Host memory guard.** When the model runs on this machine, reviews pause while swap use is at or above
  `max_swap_used_pct` or the OS reports memory pressure.

`pending` and the dashboard show the current state, e.g. `reviews on · 85 tok/s · input cap 52,020 chars`.

**Size your model server.** Only the server can limit its own memory. Set its context window to what you
need and serve one request at a time:

| runtime | settings |
|---|---|
| llama.cpp | `-c <ctx>` `--parallel 1`; optional `-ctk q8_0 -ctv q8_0` halves KV-cache memory |
| llama-swap | put the llama.cpp flags in the model's `cmd:`; the first request after an unload waits for the model to load (covered by `probe_timeout`) |
| vLLM | `--max-model-len <ctx>` `--max-num-seqs 1` `--gpu-memory-utilization 0.9` |
| Ollama | `num_ctx` in the Modelfile, `OLLAMA_NUM_PARALLEL=1` |
| any reasoning model | turn thinking off (`chat_template_kwargs = { enable_thinking = false }`); reviews get several times faster |

**macOS and a model on another machine.** The first request to a LAN address (e.g. `192.168.x.x`) makes
macOS ask whether your terminal app may use the Local Network. Until you allow it, the endpoint shows as
unreachable. You can change it later under System Settings → Privacy & Security → Local Network.

---

## 6. The dashboard & the `watch` daemon

Two extras make NpmDiffWatch easier to run and easier to *act on*: a built-in daemon loop and a local HTML
dashboard of verdicts with one-click "report to npm" links.

**The dashboard** renders every reviewed release as a card — malicious and suspicious sorted first and
highlighted, benign muted — each with a direct npmjs link, and flagged cards carry a **"Report malware on
npm"** action so going from "the tool flagged this" to "reported for takedown" is one click. It's a single
self-contained HTML file with no JavaScript; every untrusted string (package name, the model's reasoning,
cited code) is HTML-escaped, so a package literally named `<script>…</script>` can't attack the page.

Generate it from whatever the database already holds:

```bash
npmdiffwatch -c npmdiffwatch.toml dashboard                 # writes .diffwatch/dashboard.html
npmdiffwatch -c npmdiffwatch.toml dashboard --serve         # also serve it on http://127.0.0.1:8787
```

`--serve` binds **127.0.0.1 only** (localhost) by default and blocks until Ctrl-C. Use `--out PATH` to
choose the file and `--port N` to change the port.

To view the dashboard from another device on your LAN, bind all interfaces:

```bash
npmdiffwatch -c npmdiffwatch.toml dashboard --serve --host 0.0.0.0   # reachable at http://<this-host-ip>:8787
```

> **Exposing it widens your trust boundary.** The page serves your verdict data and renders strings derived
> from untrusted npm packages. It's HTML-escaped against XSS and the server is read-only with no control
> endpoints, but `--host 0.0.0.0` makes it reachable by anyone who can reach this host. Only do it on a
> network you trust, and keep the default `127.0.0.1` otherwise. The same `--host` flag works on `watch`.

**The `watch` daemon** is the built-in alternative to wiring up cron/systemd (§7): it scans on an interval,
refreshes the dashboard after each tick, and — with `--serve` — serves it the whole time. One command gives
you a running monitor plus a live results page:

```bash
npmdiffwatch -c npmdiffwatch.toml watch --serve --recent 500   # start 500 changes back + live dashboard
npmdiffwatch --model qwen-singleshot watch --serve             # same, no config file: OpenAI-compatible server
# → open http://127.0.0.1:8787/dashboard.html
```

Without `--recent`, a fresh database starts "from now" and the first results appear on the next scan.
While a backlog is waiting (a `--recent` start, or a restart after downtime), `watch` scans back-to-back
and sleeps only once it has caught up. `--model` / `--endpoint` (default `http://localhost:8000/v1`)
override the config's reviewer with an OpenAI-compatible server; no API key needed.

`--interval N` sets the seconds between scans once caught up (default 300); `--out`/`--port` work as above. A failed scan
(network blip, endpoint down) is logged and the daemon keeps going; Ctrl-C stops cleanly. The dashboard's
status strip shows whether your model endpoint is reachable and how long ago the last scan ran — start your
model server (§2) before `watch --serve`, or reviews fall back to heuristics until it's up.

It is a **foreground** process — keep the terminal open, or run it under your agent harness, which will run
it as a background task and hand you back the dashboard URL. For unattended, machine-level scheduling,
prefer the harness patterns in §7.

### Watch only your packages

By default NpmDiffWatch scans every release published to npm. To watch only the packages you care about,
pass `--watchlist PATH` to `watch` or `run` (or set `watchlist = "PATH"` in the config; the flag wins):

```bash
npmdiffwatch -c npmdiffwatch.toml watch --serve --watchlist package-lock.json
```

The format is detected from the file's content:

| Format | Packages taken |
|---|---|
| Names file (text) | one per line: an exact name (`left-pad`, `@babel/core`) or a pattern with `*` (`@gooddata/*`, `react-*`); `#` comments ignored. See `examples/watchlist.txt` |
| `package-lock.json` / `npm-shrinkwrap.json` | every package in the tree, direct and transitive (lockfile v1, v2 and v3); workspace links are skipped |
| CycloneDX JSON | components with a `pkg:npm/...` purl, including nested components |
| SPDX JSON | packages with a `pkg:npm/...` purl external reference |

What happens:

- **On start**, each listed package's latest release is reviewed against its previous one, 50 packages per
  scan (`watchlist_baseline_per_tick`), with progress printed (`watchlist baseline: 120/560 packages`).
  It happens once per package and resumes after a restart; `watch` doesn't sleep until it's done.
- **After that**, only new releases of listed packages are fetched and reviewed. Feed rows for other
  packages are dropped before anything is downloaded, so a watchlist run keeps up with npm.
- **Patterns** match new releases only: a family like `@gooddata/*` can't be listed at start without a
  search API, so the startup review covers exact names.
- **The file is re-read** whenever it changes, so updating your lockfile updates the watch. If a re-read
  fails (say, mid-save), the last good list stays in force and each scan prints a warning.
- **A missing, empty or unrecognized file stops the run** with a message; it never falls back to scanning
  everything or nothing. The file is parsed as data only; nothing in it is executed.
- `pending` and the dashboard show the list and the startup progress, e.g.
  `watchlist: package-lock.json · 560 packages · baseline 560/560`.

yarn.lock and pnpm-lock.yaml aren't read directly; generate a CycloneDX SBOM from them instead.

---

## 7. Running on a harness (cron / systemd / Docker / CI)

NpmDiffWatch is a plain CLI over a local SQLite DB; "running it" means invoking `run` on a schedule under
whatever runtime you already operate. All four patterns below are equivalent — pick one. Concurrent runs
are safe: a second `run` that overlaps the first sees the lock, prints `a scan is already running …`
(naming the holder's pid and the lock file), and no-ops.

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

## 8. State, persistence & containment

All state lives under `.diffwatch/` (paths configurable via `db_path`, `cache_dir`, `lock_path`):

- `diffwatch.sqlite` — the cursor, every processed release, verdicts, alerts, and stored payload evidence
  (compressed, and pruned daily as described in §5).
- `diffwatch.lock` — an exclusive `flock` that prevents overlapping `run`s.
- `diffwatch.lock.review` — the lock that lets only one process at a time send reviews to the model.
- `dashboard.html` — the dashboard, rewritten after each `watch` scan.

No tarball is written to disk: each is downloaded and read in memory only.

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

## 9. Alerts

Set `webhook_url` (top-level, not under `[reviewer]`) to receive each new alert as a JSON POST —
`{"text": "..."}`, Slack-incoming-webhook compatible:

```toml
webhook_url = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

Alerts are also printed to stdout and recorded (deduped) in the DB, so a webhook failure never loses one.

Each alert names how it was reached:

| alert | meaning |
|---|---|
| `malicious` with a `model=` name | the reviewer's verdict; `cited_hunk` is the code it rests on. The model's `suspicious` calls go to `pending` instead |
| `suspicious-heuristic` with a score | the rules fired and no model reviewed it (heuristic-only mode, §10) |
| `suspicious-heuristic` with `UNREVIEWED: …` | nothing could be shown to a model: a tarball refused at download or unpack (§5), or flagged content with no reviewable text. Needs manual review |

---

## 10. Heuristic-only mode (no LLM)

To run with no model at all — rules and weights only, no endpoint required — set:

```toml
reviewer_enabled = false
```

Every release crossing `threshold_t` becomes a heuristic alert. Useful for a first pass on a box with no
GPU and no API budget, or to keep monitoring when your endpoint is down.

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ReviewUnavailable: non-JSON content` in logs | the model isn't honoring the JSON contract. Lower `structured_output` (`json_schema` → `json_object` → `none`) or use a more capable model. The release still alerted heuristically — nothing was dropped. |
| Every Anthropic run logs `heuristic-only this run` | `ANTHROPIC_API_KEY` isn't in the environment the *scheduler* uses. Put it in the systemd `EnvironmentFile` / cron wrapper / Actions secret, not just your interactive shell. |
| `401`/`403` from a hosted endpoint | `api_key_env` names a variable that's unset, empty, or wrong. Check it from the harness's environment: `echo $OPENAI_API_KEY`. |
| `400`/`ReviewUnavailable: HTTP Error 400` from DeepSeek (or another reasoning model) | the endpoint rejects strict `json_schema` (an OpenAI-only extension). Set `structured_output = "json_object"`. See `examples/deepseek.toml`. |
| DeepSeek verdicts arrive with empty `reasoning`/`cited_hunk` or `attack_type: none` | the response truncated — reasoning ate the output budget. Raise `max_output_tokens` (try 32000) and/or disable thinking via `[reviewer.extra_body]`. The `classification` still survives. |
| First `run` returns `processed 0 releases` | expected — a fresh DB seeds the cursor to "now" and processes nothing that tick; the next tick polls forward. Use `run --backfill` to process history instead. |
| `a scan is already running …` | another run holds the lock — the message names the holder pid and the lock file. If it's your scheduled tick, harmless; space the schedule. If nothing is actually running, a prior run hung or was killed mid-fetch and still holds the lock: kill the reported pid and re-run. The lock is an OS advisory lock that frees when its process exits — deleting the lock file does **not** release a live lock. |
| `config file not found: …` | the `-c` path doesn't exist. It stops on purpose: running on the built-in defaults would write to the default database. Check the path. |
| `package metadata failed to download: …` in `pending` | registry errors or timeouts. Those releases are retried on the next scans and given up on after 4 attempts; a steady count points at your network or a proxy. |
| `watch` never catches up; the backlog grows | reviews run inside the scan loop, so a full-firehose run on one local model can cover fewer changes than npm publishes at busy times. Use a watchlist (§6), a faster model, or accept the lag. |
| Local endpoint refused / connection error | the model server isn't up, or `base_url` is wrong (check the port and the trailing `/v1`). From Docker, use `host.docker.internal`, not `localhost`. |

---

## 12. Detection scope on brand-new packages

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
