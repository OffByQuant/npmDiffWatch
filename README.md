# NpmDiffWatch

**Catch malicious npm updates before they spread — with a cheap local model and rules anyone can write.**

Supply-chain attacks on open-source packages are escalating: an attacker ships a compromised version of a
trusted package, and it's pulled into thousands of installs before anyone notices. Defending against that
shouldn't require a security budget or a SaaS subscription. NpmDiffWatch is an open-source (MIT) scanner
that watches the npm release firehose, statically reviews what changed in each new version, and alerts
you **before** a malicious update spreads — running on hardware you already have.

It's built for the community to **extend** and to **afford**: the per-release review runs on a **local,
open-source LLM** (no per-token bill), and detection logic is **plain YAML rules** anyone can contribute.

## How it works

```
new npm releases → diff against the prior version → community rules score the change
   → anything suspicious goes to a local LLM reviewer → you get alerted
```

State lives in a local SQLite database; nothing is hosted, and nothing leaves your machine except the
calls to the npm registry and the model endpoint you point it at.

## Why NpmDiffWatch

- **Cheap by design.** The reviewer is meant to run on a local open-source model — the only setup it has
  been tested against — so watching the whole firehose costs you compute, not API credits. Hosted and
  frontier APIs (OpenAI, Anthropic, OpenRouter, DeepSeek, …) work too, but local keeps it free.
- **It never runs what it inspects.** Analyzed packages are *data, never code*: NpmDiffWatch downloads a
  `.tgz` into memory, reads the source statically, and discards it — no `npm install`, no build, no
  `require`, no `node`, no `eval`. Package bytes reach the model only as request-body text, never as a URL
  it fetches. [More ↓](#run-it-safely)
- **Community rules, run safely.** Detection rules are pure structured data (YAML) evaluated by a matcher
  with no `eval`/`exec` — so you can run other people's rules without running their code. See
  [`rules/community/`](rules/community).

## Get started — the easy way

Clone it, open your favorite agent harness (**Claude Code**, **opencode**, or similar), and give it one prompt:

> *"Install the dependencies and let's configure the API endpoint to use a local model and start polling."*

The agent handles setup and drives the polling loop; your local model does the reviews. That's the
two-tier idea in a nutshell — a frontier model can **orchestrate** while a cheap local model does the
**per-release review work**.

## Get started — by hand

No agent required. Plain commands poll the firehose and still use your local LLM for every review:

```bash
git clone https://github.com/OffByQuant/npmDiffWatch npmdiffwatch && cd npmdiffwatch
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                                # requires Python 3.11+

cp examples/local-qwen.toml npmdiffwatch.toml   # point at your local model endpoint
npmdiffwatch -c npmdiffwatch.toml seed-now      # start watching "from now"
npmdiffwatch -c npmdiffwatch.toml run           # process new releases (repeat on a schedule)
npmdiffwatch -c npmdiffwatch.toml pending       # see suspicious releases awaiting your verdict
```

Drop `run` into a cron job, `systemd` timer, container, or CI schedule to monitor continuously. You can
also run with **no model at all** (rules-only heuristic alerts) when you have no GPU or budget.

**→ Full setup — endpoints, API keys, scheduling, heuristic-only mode, troubleshooting:
[GETTING-STARTED.md](GETTING-STARTED.md)**

## Run it safely

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

## Bring your own rules

NpmDiffWatch ships a **basic starter set** of detection rules — enough to get you catching the obvious
attacks out of the box, not the last word. The rules live as plain YAML in the
[`rules/community/`](rules/community) folder (code, `package.json` fields, dependencies, lockfile,
maintainer, and binary signals), and the whole point is that **you extend them with your own**: structured
YAML over engine-provided facts, no code. If you can describe an attack pattern (say, "a base64 decode and
an `eval` in the same changed file", or "a `postinstall` script added to `package.json`"), you can add a
rule in a few minutes — drop another `.yaml` file in that folder and it's picked up automatically. The
loader is fail-closed: a malformed rule is rejected, never run as code.

## License & attribution

MIT — see [LICENSE](LICENSE); applies to NpmDiffWatch's own code, rules, and docs. The vendored
popularity/typosquat corpus (`npmdiffwatch/data/top_npm_names.txt`) is a snapshot of popular npm package
names used for typosquat detection; it holds package names (facts), not creative content, and is vendored,
not fetched at runtime.
