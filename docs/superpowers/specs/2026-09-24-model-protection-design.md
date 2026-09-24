# Model protection: keep the reviewer from overloading the user's model server

**Status:** draft for review · **Date:** 2026-09-24 · **Applies to:** npmDiffWatch and PyDiffWatch (same design, ported)

## 1. Why

On the night of 2026-09-23 a scan ran against a local Qwen 3.8 27B (fp16, OpenAI-compatible server on
the same 128 GB Mac). At 07:06 IST the kernel killed the model server: `memorystatus: killing Python
[61283] due to low-swap`. What led there, all measured:

- **Inputs sized in characters, not by what the model can handle.** Review inputs near the 200k-character
  cap were ~59k tokens. That server reads input at ~85 tokens/s, so one such review took **691 s** (the
  output was only 235 tokens; nearly all the time went on reading the input).
- **Timeouts that give up on the request but leave it running.** Retries wait 300 s, 600 s, 900 s. The first
  two attempts at a near-cap input can never succeed. After a timeout the server keeps working on the
  abandoned request; an idle probe was answered only **777 s** later. Every later request queues behind
  the dead one and times out too.
- **The server kept growing.** It was seen at 77 GiB resident at 01:35 IST, 34 GB at 04:52 IST, until swap ran
  out. (Attributing the growth to the abandoned long-prompt requests is inference; the timeline fits.)
- **Nothing noticed.** The scanner watched whether the endpoint's port was open. It was, until the kill.

The merged queue (PR #9) keeps the *scan* moving when the model is down, too slow, or can't take an
input. It does not protect the *model* from the scanner. Every user runs their own model — local,
LAN (e.g. llama-swap on an RTX box), or a hosted API — on hardware we don't know. The tool has to measure
the endpoint and adapt to it.

## 2. Goal and success criteria

Goal: the scanner never sends a model server more than it can finish within the timeout, never stacks new
requests behind a request it gave up on, notices when the server degrades, and stops feeding a local
server when the host is short on memory. Every deferred review waits in the existing queue; nothing is
dropped and the cursor keeps moving.

Success, each checked by a test (§7):

1. Replaying last night's numbers (85 tok/s, 300 s timeout), no request is sent whose predicted time
   exceeds the timeout; oversized inputs go to `too_large` with a message naming the measured speed.
2. After a timeout, no further review is sent to that endpoint until a health probe succeeds.
3. During a batch, the model can delay the cursor by at most one timeout plus one probe.
4. A review running at under 30 % of the endpoint's own measured speed, twice in a row, pauses reviews with
   a "model server is degrading" warning.
5. With the model on this machine, reviews pause while swap use is ≥ 75 % (or the OS reports memory
   pressure), and resume once it clears.

## 3. Non-goals

- Capping the model server's own memory. Only the server can do that (context size, parallelism); §6 documents
  how, per runtime.
- Cancelling work on the server after a client timeout. Closing the connection cancels on some servers
  and not others; the design assumes it does not.
- More review throughput (a separate reviewer worker, several endpoints). Separate follow-up.
- Choosing or recommending a model.

## 4. Approaches considered

- **A. Fixed conservative defaults** (lower `max_input_chars`, one fixed timeout). Simple, but wrong for
  every setup except the one it was tuned on: too tight for an RTX GPU, still too loose for a slow laptop.
- **B. Measure the endpoint and adapt (chosen).** The tool measures input-reading speed from the token counts the
  server already returns, sizes inputs to fit the timeout, and trips a breaker on trouble. Works the same
  for local, LAN and hosted endpoints, with no user tuning.
- **C. Require users to configure their hardware** (VRAM, tokens/s). Pushes the measuring onto every user
  and goes stale when they swap models.

## 5. Design

### 5.1 New unit: `ReviewerGuard` (`npmdiffwatch/guard.py`)

One object per run, per reviewer endpoint. It is the single place that decides whether a review may be
sent now and how big it may be. The orchestrator asks it before every review, both new flagged releases and
queue drains, and reports every outcome back to it.

```
guard.admit()                     -> Admit | Defer(reason_detail)   # breaker / memory / degraded
guard.input_cap_chars()           -> int                            # effective cap for this endpoint
guard.record_success(usage, secs, input_chars)                      # updates speed estimate
guard.record_timeout(secs)                                          # opens the breaker
```

It depends on three injected parts, each replaceable in tests: the backend (for the probe), a clock, and a
host-memory reader. State that should survive restarts (measured speed, chars per token) is stored in SQLite
(§5.7).

### 5.2 Circuit breaker (item 1)

States: **closed** (normal) → **open** (no reviews) → **half-open** (probe) → closed.

- A review that times out opens the breaker. The release that timed out is re-queued as today (`review_failed`,
  attempt counted).
- While open, `admit()` returns `Defer`. Every flagged release in the rest of the batch is parked with the
  new queue reason **`model_busy`**, which does not spend an attempt, and the drain stops.
- At the start of the next batch the guard goes half-open: it sends a **probe**, a fixed tiny prompt
  (`max_tokens: 1`, no package content) with timeout `reviewer.probe_timeout` (default 60 s, enough for
  llama-swap to load a model it had unloaded). If the probe answers in time, the breaker closes and the
  drain resumes; `model_busy` rows drain first, oldest first. If not, it stays open and the batch prints
  `reviewer endpoint X is still busy with an abandoned request; reviews paused`.
- Connection refused keeps its current handling (`endpoint_unreachable`). The breaker covers the endpoint
  being up but stuck.

This covers criteria 2 and 3: a stuck endpoint costs at most one timeout plus one probe per batch.

### 5.3 Input size budget from measured speed (item 2)

After every successful review the guard records the prompt's token count and the elapsed time. The token count
comes from `usage.prompt_tokens` for OpenAI-compatible servers and `usage.input_tokens` for Anthropic. When a
llama.cpp server returns `timings.prompt_per_second`, that number is used directly. **Backend interface change:**
`complete()` returns `(verdict_json, usage)` instead of just the verdict text, where `usage` is
`{prompt_tokens, completion_tokens, prompt_per_second?}` or `None` if the server gave none.

- **Speed estimate** `tok_s`: a moving average of `prompt_tokens / elapsed` over reviews with ≥ 2,000
  prompt tokens. Smaller prompts are dominated by fixed overhead and would skew the estimate.
- **Chars per token** `cpt`: a moving average of `input_chars / prompt_tokens`. Last night's measurement:
  ~3.4 chars/token.
- **Effective cap** = `min(max_input_chars, tok_s × timeout × budget_safety × cpt, context_cap)`, with
  `budget_safety = 0.6`. Replaying the Qwen numbers: 85 × 300 × 0.6 ≈ 15.3k tokens ≈ 52k chars, about
  4 minutes per review at most. A GPU endpoint measures far faster and is limited only by `max_input_chars`.
- **Context cap**: best effort from `GET /v1/models`. The field name varies by server (`context_length`,
  `max_model_len`); llama.cpp reports it at `/props` (`n_ctx`). The cap is
  `(ctx − max_output_tokens − system prompt tokens) × cpt`. If nothing is reported, there is no context cap.
- **Cold start**: at the start of the first batch against an endpoint with no stored measurements, the guard
  sends one **calibration prompt**: fixed ~4k-token filler text with `max_tokens: 1`, never package content.
  Until a measurement exists the cap is `min(max_input_chars, 40,000)`.
- `Reviewer.prepare()` uses `guard.input_cap_chars()` instead of `cfg.reviewer.max_input_chars`. Inputs
  over the cap are parked as `too_large` as today, with the reason in the detail:
  `needs 190k chars; this endpoint's cap is 52k (≈85 tok/s × 300 s × 0.6)`.
- The Anthropic provider skips calibration and uses `max_input_chars`: a hosted API reads input far faster than
  any timeout here.

### 5.4 Slowdown detector (item 3)

After each successful review of ≥ 2,000 prompt tokens, compare its speed to the stored `tok_s`. If it is
below `slowdown_ratio × tok_s` (default 0.3) **twice in a row**:

- open the breaker with detail `degraded` and pause for `degraded_pause_s` (default 900 s) before the
  half-open probe;
- print `reviewer endpoint X is running at N% of its measured speed — the model server is likely short
  on memory or swapping; consider restarting it`;
- leave the slow samples out of `tok_s`, so a degrading server can't lower its own baseline;
- post the same message to `webhook_url` when one is configured (§9, decision 2).

Two consecutive slow reviews avoids tripping on one unusually heavy input.

### 5.5 Host memory guard, local endpoints only (item 4)

Active when the endpoint host is loopback (`localhost`, `127.0.0.0/8`, `::1`), or when
`reviewer.host_memory_guard = true` is set for a model on this machine reached through another address.
Before each review, `admit()` reads host memory and defers (`model_busy`, detail `host memory`) when:

- swap used ≥ `max_swap_used_pct` (default 75); last night's kill came at swap-low, ~83 % used; or
- the OS reports memory pressure: macOS `sysctl kern.memorystatus_vm_pressure_level` ≥ 2 (warn);
  Linux `/proc/pressure/memory` "some avg10" ≥ 10, or `MemAvailable` < 10 % of `MemTotal`.

Implemented with the standard library only: `sysctl` / `vm.swapusage` on macOS, `/proc` on Linux. **No new
dependency.** For a supply-chain security tool, adding `psutil` for this is not worth its own
supply-chain risk. On other platforms the guard logs one notice that it is inactive.

Deferring reviews can't shrink a server that is already big. It stops the scanner making things worse, and
the warning tells the user to act.

### 5.6 Queue and status

- New queue reason **`model_busy`**. Detail is one of `breaker open after timeout`, `degraded`,
  `host memory`. It is drained automatically, first in order, and spends no attempt.
- `pending`, the dashboard status strip and the per-batch log show the guard's state: breaker
  closed/open/degraded, measured `tok_s`, effective cap, host-memory status when active.

### 5.7 Stored measurements

New table:

```sql
CREATE TABLE IF NOT EXISTS reviewer_stats(
  endpoint TEXT, model TEXT, tok_s REAL, chars_per_token REAL, samples INTEGER, updated_at TEXT,
  PRIMARY KEY(endpoint, model));
```

Keyed by `base_url` and model, so switching models (Qwen → Gemma) or machines starts a fresh
calibration. Breaker state is per-process and in memory only; a restart starts closed and the first
review, or the probe, finds the truth.

### 5.8 Config (all under `[reviewer]`, all optional)

| key | default | purpose |
|---|---|---|
| `budget_safety` | 0.6 | fraction of the timeout a review may be predicted to use |
| `probe_timeout` | 60.0 | half-open probe and calibration timeout (covers llama-swap model load) |
| `slowdown_ratio` | 0.3 | below this fraction of measured speed counts as degraded |
| `degraded_pause_s` | 900 | pause after a degradation trip before probing |
| `host_memory_guard` | `"auto"` | `auto` (on for loopback endpoints) / `true` / `false` |
| `max_swap_used_pct` | 75 | host memory guard threshold |

`max_input_chars` stays as the upper limit. The effective cap never exceeds it.

## 6. Docs: size your model server (item 5)

New GETTING-STARTED section, "Size your model server". The context limit set on the server bounds its
memory; the tool can't set it for you. Per runtime:

- **llama.cpp / llama-swap**: set `-c` (context) to what you need, `--parallel 1`; optionally `-ctk q8_0 -ctv q8_0`
  to halve KV-cache memory. With llama-swap, put the flags in the model's `cmd:` and note the first request
  after an unload waits for the model to load (covered by `probe_timeout`).
- **vLLM**: `--max-model-len`, `--max-num-seqs 1`, `--gpu-memory-utilization`.
- **Ollama**: `num_ctx` in the Modelfile or request, `OLLAMA_NUM_PARALLEL=1`.
- **Any server**: turn thinking off for reasoning models (Qwen 3.x, Gemma); last night that made reviews
  1.6–4.4× faster with the same verdicts.

Plus a short table of what the guard does and what each warning means.

## 7. Testing (written first, per repo)

Unit tests use a fake clock, a fake backend that returns `usage` and can hang or time out, and a fake memory reader.

- Breaker: timeout → open → rest of the batch parked `model_busy`, no attempts spent → next batch probe succeeds →
  closed and `model_busy` drained first; probe fails → stays open.
- Budget: Qwen replay (85 tok/s, 300 s, 0.6, 3.4 cpt) → cap ≈ 52k chars; a 190k input → `too_large` with the
  measured speed in the detail; a fast endpoint → cap = `max_input_chars`; context cap applied when
  `/v1/models` reports one; calibration prompt carries no package content.
- Slowdown: one slow review → no trip; two → trip, warning, baseline unchanged.
- Memory guard: swap 80 % → defer; pressure level 2 → defer; clears → admit; non-loopback endpoint → never
  consulted unless forced on.
- Integration (`run_once`): hung endpoint → cursor advances within one timeout plus one probe; stored
  `reviewer_stats` survive a restart; model change → recalibrates.
- Backend: `complete()` returns usage for OpenAI-compatible (incl. llama.cpp `timings`) and Anthropic
  responses; missing usage → `None`, no speed update.

## 8. Rollout

One PR per repo: npmDiffWatch first, then the PyDiffWatch port. The two share the reviewer, orchestrator and
store design. No migration beyond the new table. Existing configs keep working: every new key has a
default, and `max_input_chars` keeps its meaning as the upper limit.

## 9. Decisions at review (2026-09-24)

1. `budget_safety = 0.6`, to be checked on the first live run against the RTX llama-swap endpoint.
2. A `degraded` trip also posts the configured webhook (`webhook_url`), in addition to the log and
   dashboard warning.
3. Calibrate with one request per new endpoint and model, as in §5.3, with tests for success, failure, and
   reuse of stored measurements.
