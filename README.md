# 🛡️ NpmDiffWatch

**Catch malicious npm updates before they spread — with a cheap local model and rules anyone can write.**

> 🌐 **A community early-warning system for the npm supply chain.** The more people watching the release
> firehose, the sooner a compromised package gets caught — and reported for takedown. Cheap to run, simple
> to extend, and you don't need to be a security expert to help.

Supply-chain attacks on open-source packages are escalating: an attacker ships a compromised version of a
trusted package, and it's pulled into thousands of installs before anyone notices. Defending against that
shouldn't require a security budget or a SaaS subscription. NpmDiffWatch is an open-source (MIT) scanner
that watches the npm release firehose, statically reviews what changed in each new version, and alerts
you **before** a malicious update spreads — running on hardware you already have.

It's built for the community to **extend** and to **afford**: the per-release review runs on a **local,
open-source LLM** (no per-token bill), and detection logic is **plain YAML rules** anyone can contribute.

---

## ⚙️ How it works

```
new npm releases → diff against the prior version → community rules score the change
   → anything suspicious goes to a local LLM reviewer → you get alerted
```

State lives in a local SQLite database; nothing is hosted, and nothing leaves your machine except the
calls to the npm registry and the model endpoint you point it at.

Every alert says how it was reached: a **model verdict** with the code it cites; a **heuristic alert**
when you run without a model; or **UNREVIEWED — needs manual review** when the tool refused to download or
unpack a tarball (oversized or malformed archives can hide a payload), with the reason.

---

## 💡 Why NpmDiffWatch

- **Cheap by design.** The reviewer is meant to run on a local open-source model — the only setup it has
  been tested against — so watching the whole firehose costs you compute, not API credits. Hosted and
  frontier APIs (OpenAI, Anthropic, OpenRouter, DeepSeek, …) work too, but local keeps it free.
- **It never runs what it inspects.** Analyzed packages are *data, never code*: NpmDiffWatch downloads a
  `.tgz` into memory, reads the source statically, and discards it — no `npm install`, no build, no
  `require`, no `node`, no `eval`. Package bytes reach the model only as request-body text, never as a URL
  it fetches. [More ↓](#-run-it-safely)
- **Evidence, not hunches.** The reviewer calls a release malicious only when the code it is shown
  concretely exfiltrates secrets, downloads or decodes code and runs it, or destroys data or installs
  persistence, and it must cite the hunk. Powerful-but-normal code (`child_process`, `eval`, network calls)
  is benign without that evidence, which keeps false alarms on legitimate CLIs and SDKs down.
- **Community rules, run safely.** Detection rules are pure structured data (YAML) evaluated by a matcher
  with no `eval`/`exec` — so you can run other people's rules without running their code. See
  [`rules/community/`](rules/community).

---

## 🚀 Get started — the easy way

Clone it, open your favorite agent harness (**Claude Code**, **opencode**, or similar), and give it one prompt:

> *"Install the dependencies and let's configure the API endpoint to use a local model and start polling."*

The agent handles setup and drives the polling loop; your local model does the reviews. That's the
two-tier idea in a nutshell — a frontier model can **orchestrate** while a cheap local model does the
**per-release review work**.

---

## 🛠️ Get started — by hand

No agent required. Clone, install, and start scanning with your model server's model name:

```bash
git clone https://github.com/OffByQuant/npmDiffWatch npmdiffwatch && cd npmdiffwatch
python3 -m venv ~/diffwatch && . ~/diffwatch/bin/activate   # one venv for npmDiffWatch and PyDiffWatch
pip install -e .                                           # requires Python 3.11+

npmdiffwatch --model qwen-singleshot watch --serve --recent 500
# → scans npm, reviews flagged releases with your model, dashboard at http://127.0.0.1:8787/dashboard.html
```

- `--model` is the model name your OpenAI-compatible server expects (llama.cpp, llama-swap, Ollama, vLLM).
  No API key needed.
- `--endpoint` is where that server listens. Leave it out for `http://localhost:8000/v1`, or point it at
  another machine: `--endpoint http://192.168.1.20:8000/v1`.
- `--recent 500` starts 500 npm changes back, so results show up within minutes. Leave it out to watch
  only what's published from now on. Once scanning has started, a restart resumes where it stopped, and
  while a backlog is waiting `watch` scans back-to-back, sleeping only once it has caught up.

For everything else (a frontier API with a key, reasoning-model settings, webhooks) use a config file:
`cp examples/local-qwen.toml npmdiffwatch.toml`, then pass `-c npmdiffwatch.toml` (a path that doesn't
exist stops with an error rather than running on the defaults). Other commands:

```bash
npmdiffwatch -c npmdiffwatch.toml run            # one scan tick (for cron, systemd, CI)
npmdiffwatch -c npmdiffwatch.toml pending        # suspicious releases awaiting your verdict
npmdiffwatch -c npmdiffwatch.toml review-pending # review what the LLM couldn't (e.g. with a bigger model)
```

Only care about what you depend on? Point it at your lockfile, an SBOM, or a list of names:

```bash
npmdiffwatch --model qwen-singleshot watch --serve --watchlist path/to/package-lock.json
```

It reviews each listed package's latest release once, then only new releases of those packages. Unlisted
packages are skipped before anything is downloaded, so a watchlist run keeps up with npm easily
([details](GETTING-STARTED.md#watch-only-your-packages)).

You can also run with **no model at all** (rules-only heuristic alerts) when you have no GPU or budget.

**→ Full setup — endpoints, API keys, scheduling, the dashboard, heuristic-only mode, troubleshooting:
[GETTING-STARTED.md](GETTING-STARTED.md)**

---

## 🗄️ What it records

Everything lives in a single local SQLite database under `.diffwatch/` — nothing is hosted. It keeps a
**cursor** (how far through the npm registry's change stream you've scanned), one **releases** row per
version it processed (the diff basis, the triage score, and which rules fired), an **alerts** row per
notification sent, and a **verdicts** row with the reviewer's call — classification, confidence, attack
type, reasoning, and model — plus your own `human_label` once you adjudicate it (`pending` to review,
`adjudicate` to record).

It stays small on its own: once a day it compresses the stored evidence, keeps it only for releases a
person may still act on, and deletes plain rows older than 90 days (`retention_days`). Verdicts, alerts
and the review queues are never pruned.

The triage score is the sum of the weights of the rules that fired; the default escalation threshold is 40,
so anything below it never reaches the reviewer. A high score is not a verdict: a large brand-new package
can rack up a huge score and still be cleared as benign on inspection, which is why the reviewer, not the
score, decides what becomes an alert.

---

## 🖥️ See and act on the results

Finding a malicious release only matters if it gets reported and pulled. NpmDiffWatch turns the verdicts in
your database into a **local dashboard** — a single web page of cards, the dangerous ones sorted to the top,
each with a link straight to the package on npm and a one-click **"Report malware on npm"** button. The goal
is to make the path from *"the tool flagged this"* to *"reported for takedown"* as short as possible, so more
eyes lead to faster reporting and faster removal.

```bash
npmdiffwatch -c npmdiffwatch.toml watch --serve   # keep scanning + open a live dashboard
# → http://127.0.0.1:8787/dashboard.html
```

The page stays on your machine (it's served to `localhost` only by default — `--host 0.0.0.0` opts into
sharing it on your LAN) and runs no code from the packages it shows; every untrusted string is HTML-escaped.
**→ [GETTING-STARTED.md](GETTING-STARTED.md#6-the-dashboard--the-watch-daemon)** for the details.

---

## 🔒 Run it safely

NpmDiffWatch ingests untrusted bytes from the npm registry and runs community-authored rules. The
no-execution design is the primary safeguard, but treat it as one layer: run it in a container, VM, or
unprivileged user with outbound network restricted to the npm registry, your model endpoint, and your
webhook — **not on a workstation that holds credentials or data you care about.** A built-in default-deny
egress allowlist (`npmdiffwatch/egress.py`) enforces this in-process; an OS-level boundary is what holds
if the process itself is ever compromised.

### The one hard invariant: no execution

Analyzed packages are never run. The `.tgz` is streamed and extracted **in memory** (never
`tarfile.extractall`, never written to disk), source is read statically via tree-sitter, and the bytes are
discarded. There is no `npm install`, no lifecycle-script execution, no `node`, no `require`, no `eval` of
package content anywhere in the pipeline. The download/extraction caps (`max_download_bytes`,
`max_member_bytes`, `max_total_bytes`, `max_decompressed_bytes`, …) bound how much of any tarball is ever
read into memory.

### The parse sandbox

Not running package code doesn't mean nothing reads it: gzip, tar, JSON and tree-sitter (C code) all parse
bytes a package author wrote. They run in a separate process that cannot open a network connection, cannot
write files, and cannot read your home directory outside the Python install and NpmDiffWatch itself:

- **macOS:** Seatbelt (`sandbox-exec`), built in.
- **Linux:** `systemd-run` (`PrivateNetwork`, `ProtectSystem=strict`, `ProtectHome=tmpfs`, a syscall
  filter, and memory and time limits).

Each run first checks that the sandbox actually blocks the network, writes and home-directory reads. If it
doesn't, or no sandbox is available, the default (`parse_sandbox = "auto"`) prints a warning and scans
without one; `parse_sandbox = "on"` refuses to scan instead. Starting the separate process adds a little time to
each release.

The sandbox keeps a parser exploit away from the network, the database, other releases and your files. It
cannot make an exploited parser report honestly on the package that exploited it, so the container/VM
advice above still applies. Rules that read registry metadata rather than the tarball (maintainer and publisher
changes, added-dependency reputation) are evaluated outside the sandbox, so they fire even then.

---

## 🧩 Bring your own rules

NpmDiffWatch ships a **basic starter set** of detection rules — enough to get you catching the obvious
attacks out of the box, not the last word. The rules live as plain YAML in the
[`rules/community/`](rules/community) folder (code, `package.json` fields, dependencies, lockfile,
maintainer, and binary signals), and the whole point is that **you extend them with your own**: structured
YAML over engine-provided facts, no code. If you can describe an attack pattern (say, "a base64 decode and
an `eval` in the same changed file", or "a `postinstall` script added to `package.json`"), you can add a
rule in a few minutes — drop another `.yaml` file in that folder and it's picked up automatically. The
loader is fail-closed: a malformed rule is rejected, never run as code.

---

## 🤝 Contributing & community

NpmDiffWatch gets stronger with scale: more people watching the firehose means malicious releases are
spotted sooner, and more shared rules means more attack patterns caught. You don't need to be a security
researcher or own a GPU to help.

- **Watch, and report what you catch.** Run it, and when a flagged release is genuinely malicious, report
  it to npm for takedown — the dashboard's one-click "Report malware on npm" button takes you straight
  there. Every extra watcher shortens the window an attacker has.
- **Write a rule.** If you can describe an attack pattern, you can add a YAML rule and open a pull request.
  See [`rules/community/`](rules/community) for the shipped rules to model yours on. No code, no `eval`.
- **Share a config or a fix.** Better example configs, clearer docs, and bug fixes are all welcome.

If you can clone a repo and edit a YAML file, you can contribute. That's the whole point.

---

## 🗺️ Roadmap

Directions, not promises — contributions toward any of these are welcome:

- **Deeper binary inspection.** Go beyond flagging native addons (`.node`) and WebAssembly (`.wasm`) to
  analyzing what they do, so attacks shipped only in a compiled artifact don't slip past.
- **More alert destinations.** Additional notifier backends beyond the current webhook (e.g. email, chat).
- **A shared rule index.** Make it easy to discover, pull, and combine rule packs others have written.
- **A labeled evaluation set.** Measure detection precision/recall against known-malicious npm releases,
  so rule and weight changes can be scored instead of guessed.
- **Easier install.** A published package / `pipx` one-liner instead of an editable clone.
- **Keep up with the whole firehose on one GPU.** Reviews run inside the scan loop, so on a single local
  model a full-firehose run can fall behind npm at busy times. Moving reviews off the scan path is the
  fix; until then, watchlist mode keeps up easily.

---

## 🤖 Built with AI

NpmDiffWatch was developed with heavy use of AI coding agents (Claude Code) alongside the same kind of
local open-source models it runs on. The parts that matter most — the no-execution boundary, the
no-`eval` rule matcher, the egress allowlist — are human-reviewed and locked down by the containment test
suite, so AI assistance never gets to quietly weaken a security invariant.

---

## 📄 License & attribution

MIT — see [LICENSE](LICENSE); applies to NpmDiffWatch's own code, rules, and docs. The vendored
popularity/typosquat corpus (`npmdiffwatch/data/top_npm_names.txt`) is a snapshot of popular npm package
names used for typosquat detection; it holds package names (facts), not creative content, and is vendored,
not fetched at runtime.
