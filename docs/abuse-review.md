# Abuse-focused review: current default

NpmDiffWatch detects malicious npm behavior. It is not a general secure-code
review service and does not certify that a package is safe.

## Install and configure

Requires Python 3.11+ and a working Seatbelt (macOS) or systemd parse sandbox
(Linux). Exact-evidence review refuses to parse without a sandbox, even if
`parse_sandbox = "auto"` cannot find one. Packages are never installed or executed.

```bash
pip install -e ".[dev]"
# Provision the tokenizer cache before the scanner installs its egress guard:
python3 -c 'import tiktoken; tiktoken.get_encoding("o200k_base")'
```

Configure a model endpoint using an existing example. An OpenAI-compatible server
needs no SDK; Anthropic requires `pip install -e ".[claude]"`. The optional
`provider = "opencode"` transport requires an installed, authenticated OpenCode
CLI and an explicit `provider/model` model name. It launches a no-tools child;
package content is sent on stdin, never executed or passed as a command.

Add these settings to the top level and reviewer table of your local TOML:

```toml
parse_sandbox = "on"
parse_rss_max_bytes = 4294967296 # macOS sampled parent + parser RSS, not a kernel limit

[reviewer]
workflow = "abuse"              # default; legacy must be selected explicitly
context_tokens = 128000         # choose 8192..128000 within your model's capacity
concurrency = 1                 # aggregate cross-process slots; size for your endpoint
queue_max_bytes = 2147483648
queue_max_jobs = 10000
# extension = "your_trusted_module:build"
```

The public distribution supplies the initial review and generic callback
interface, **not an overflow investigator or confirmation implementation**.
Without callbacks, ordinary completed no-abuse reviews can publish, overflow is
deferred, and suspicious/malicious candidates remain held. A trusted operator's
`build(context)` returns `targeted` and/or `claim_check` callbacks; they must use
the supplied input identity, evidence, trace, model slots and shared budget.
Do not derive extension names from package metadata or load untrusted plugins.

## Operation and migration

```bash
npmdiffwatch -c local.toml run                       # one intake tick, then a bounded worker batch
npmdiffwatch -c local.toml watch                     # intake and independent review worker
npmdiffwatch -c local.toml review-worker --limit 20   # no feed polling; due acquisition retries may fetch npm
npmdiffwatch -c local.toml pending                   # retained findings and queue counts
npmdiffwatch -c local.toml dashboard --serve         # serves only the selected HTML file
```

Intake durably retains unopened current/prior `.tgz` pairs before advancing the
cursor. Acquisition failures use a separate four-attempt lane; security refusals
are not automatically retried. Every claimed model job reserves its whole
12-call allowance once. Expired work fails visibly: restarting does not refresh
its allowance or resample a completed result. Provider outages pause further
dispatches; context, schema, evidence and archive errors remain distinct.

Queue limits count completed retained jobs too. At 2 GiB or 10,000 jobs by default,
new admissions fail visibly rather than silently dropping evidence. Automatic
archive deletion is not implemented; monitor capacity and plan retention before
unattended use. The macOS RSS monitor samples parent + parser, not model-process
memory. Linux uses the configured systemd `MemoryMax`.

Existing verdicts, evidence and human labels are not bulk-migrated on startup.
New results are append-only projections; human decisions and newer revisions
take precedence. Explicit `review-pending --limit N` acquires pinned artifact
pairs for selected legacy pending rows and then drains jobs. This is **not**
required to adopt the default and can trigger new model work; back up state and
choose a limit deliberately. Legacy cached text is never reused by abuse review.

New findings create **disabled outbox intents only**. No outbox sender, webhook
delivery, automatic npm report or background daemon is enabled by installing or
configuring the package. Starting `watch` is an explicit operator action.
The dashboard distinguishes history, held/deferred work and processing failures.
The older guides' heuristic clearances, short-check clearances, text retries and
automatic alerts apply only to `[reviewer] workflow = "legacy"`.

## Decisions

- **No abuse found in assessed behavior:** supplied evidence does not establish
  malicious behavior. Vulnerabilities, missing hardening and ordinary external
  dependency unknowns do not by themselves require a threat finding.
- **Suspicious:** concrete cited concerning behavior and a specific unresolved
  question about abuse, not merely inability to prove safety.
- **Malicious:** a reachable abusive effect with evidence for source/target,
  sink, activation, authorization boundary and release attribution.
- **Held or failed:** an unresolved confirmation or processing problem, not a
  new threat finding or a clearance.

Coverage and binary limitations remain visible separately. No-abuse results must
not be presented as whole-package security certificates. Human decisions remain
authoritative.

## Host-owned evidence

`npmdiffwatch.abuse_workflow.Packet` accepts immutable current/prior source bytes
from the caller's sandboxed extraction and an `AnalysisInput` bound to the exact
artifacts and policy. `add(version, path, start, end)` creates short evidence refs
for original byte ranges. Exact duplicate bodies can share display text while
retaining distinct source addresses.

The model selects issued refs; it does not retype source quotations. The host
retains the exact original bytes, ranges, hashes and artifact identity. A valid
ref proves provenance, not abusive behavior or data flow. Those remain explicit
reasoning requirements. Unknown refs, unsupported classifications and missing
malicious-chain endpoints fail validation, with at most one bounded repair.

`chain.source`, `chain.sink`, `chain.activation` and `chain.baseline` explicitly
select endpoint refs. For destruction, the source is the selected target path;
one block may supply both source and sink. Empty refs do not become endpoints
merely because the classification is malicious.

## Routing boundary

The short check routes work; it is not a malware verdict. Substantive review
uses the shared versioned judgment policy and bounded context/cumulative budgets.

`review_workflow` accepts caller-supplied stage functions. Only a typed
`ContextOverflow` admission failure selects its targeted-review callback. If
that callback is unavailable, the result is explicitly deferred. Transport,
evidence, archive and budget failures must not be relabeled as context overflow.

Surviving S/M candidates require a caller-supplied confirmation callback.
When that required callback is unavailable, disagrees or fails, the result is
held rather than silently published or cleared. No investigation engine or its
prompts/tools are included in this contract module.

## Publication boundary

The contract and `abuse_dashboard` renderer perform no database writes,
notifications, npm reporting or deployment. The application owns transactional
history preservation, human precedence, revision fencing and safe delivery.
The live coordinator implements the transactional queue and append-only
publication boundary; delivery remains disabled. No package code may be
installed or executed to obtain a result. These are bounded safeguards, not a
claim of universal detection accuracy or unlimited unattended reliability.
