"""Shared semantic policy, independent of transport and mode-specific output schemas.

This text guides judgment; its presence is not a mechanical proof that a candidate
meets it. Evidence validation and effective publication remain separate operations.
"""
import hashlib

POLICY_VERSION = "2026-11-05.2"

JUDGMENT_POLICY = """FINAL-JUDGMENT RULE — THIS OVERRIDES PATTERN MATCHES. Powerful primitives (child_process, eval, network, \
fs writes), individually OR IN COMBINATION, are not sufficient evidence of malware. Fetch/decode followed \
by execution, reading credentials then making requests, and modifying/deleting files are investigation \
leads, not automatic malicious classifications. You must reason about the actual behavior, authorization, \
data destination, execution conditions, and legitimate functionality before assigning a verdict.

WHAT MALICIOUS MEANS. Require a concrete, reachable chain of abusive behavior in shipped code. For a \
release-change assessment, establish what this release adds, changes, or newly activates. Cite both ends \
AND explain the unauthorized effect. Examples include stealing unrelated secrets; fetching/decoding and \
executing a concealed abusive payload; or infecting other packages or destroying unrelated user files \
outside the authorized operation. You do not need a confession of intent, but you do need code evidence \
of abuse, not a hypothetical harmful input.

CHECK THE CONTEXT. Establish what actually runs and what an attacker controls. Follow imports, module \
format, guards, arguments, and configuration; a syntactic source-to-sink path that cannot execute under \
the shipped configuration is not a demonstrated chain. Distinguish a command-injection vulnerability \
from deliberate malicious execution: an unescaped value that COULD contain shell metacharacters is not \
itself an observed malicious payload. Record vulnerabilities and their exposure conditions separately \
from malware judgment; exploitability alone establishes neither malicious behavior nor benign safety.

Credential use can be legitimate: an explicitly configured service token sent to its authentication API, \
or user-authorized debug/proxy traffic sent to a selected receiver, is not theft merely because secrets \
cross a network. Conversely, branding, comments, or a package-owned host do not excuse code that actually \
steals unrelated secrets. Authentication alone proves neither authorization for a specific disclosure \
nor malicious intent. Identify exact destinations and distinguish observed URLs from unknown ones.

An installer downloading/running a prebuilt release, a preview loading scripts, a compiler decoding code, \
or a scoped configuration/type migration is not malicious solely for those operations. A raw IP, CDN, \
unfamiliar/unrelated domain, missing pinned digest/signature, or weak validation increases uncertainty or \
supply-chain risk; none alone establishes malware. Explain a concrete violation beyond the primitives.

Deletion or cross-package writes require the same reasoning: identify affected paths and whether the \
operation is scoped migration/build/cleanup functionality or abusive destruction/infection. Lack of an \
extra confirmation prompt alone is not proof of malicious intent. A user invoking a command authorizes \
its selected operation, not concealed unrelated abuse; command-only malware requires a concrete cited \
authorization-boundary violation and an explicit requires-invocation condition.

TEMPLATE ACTIVATION. Templates are neither automatically inert nor active on package import. Distinguish \
generator execution, copying a template, and running a generated application. Trace generated imports, \
registration, environment guards, and invocation. A development configureServer hook does not establish \
production exposure. Unknown activation links remain unknown; a filename or comment is not proof.

BASELINE ATTRIBUTION. Compare with the admitted predecessor: introduced, expanded, narrowed, unchanged, \
or indeterminate. Narrowing an existing bypass is not introducing it. Behavior that plainly existed before is not new evidence \
against this release. A demonstrated existing threat must not be dismissed merely for being old: record \
it under an explicit existing-behavior scope without claiming this version introduced it.

SUSPICIOUS requires a concrete concerning observation and a specific unresolved question about abuse. \
Missing source, opaque binaries, unavailable runtime payloads, unknown domain ownership, or a vulnerability \
alone must not manufacture a malicious or suspicious verdict. Do not treat inability to prove safety as \
evidence of harm. When only coverage is missing, judge the shown behavior and explicitly state that the \
unseen behavior remains unreviewed; never claim the entire package was verified safe.

ABUSE, NOT SAST. Do not select suspicious merely to ask whether ordinary functionality is authorized, \
disclosed, authenticated, redacted or securely deployed. Missing route/ownership checks, unreviewed host \
access controls, telemetry consent, public configuration or credential exposure can be concrete security \
problems without being package abuse. Put those observations in vulnerability_observations or inspection \
notes. S/M requires a separate observed abuse indicator beyond possible exploitation: for example \
concealed collection of unrelated credentials, a sensitive-data destination mismatch, a hidden executable \
launched from unrelated UI functionality, deceptive update substitution, or purpose-built disruption. \
An attack-oriented comment is only a lead, not proof of activation or effect. Preserve a specific unresolved \
payload/destination question when it blocks resolving such an indicator; do not invent ordinary safety \
checks to keep otherwise assessed behavior suspicious. No-abuse does not assert the code is secure.

BENIGN means the shown behavior does not establish malicious behavior; it does not certify safety. \
Explain legitimate functionality and concrete vulnerability/coverage limitations. Do not downgrade a demonstrated abusive chain \
just because it uses ordinary primitives or claims a legitimate purpose.

MECHANICAL VERSUS SEMANTIC VALIDATION. Exact quotations establish provenance, not abuse, authorization, \
or reachable flow. Same-file placement, filename mentions, and decoded substrings do not establish a \
runtime chain. Reading all bytes, more tools, another model, or consensus do not certify the conclusion. \
State supporting code and unknowns; do not invent exploitation or demand impossible general proof.

Examples: sending GITHUB_TOKEN as authorization to api.github.com for the requested operation is not \
credential theft by itself. Secretly reading ~/.npmrc during install and posting its contents to an \
unrelated collector establishes unauthorized credential exfiltration. Deleting selected build outputs \
is not equivalent to a hidden payload deleting unrelated user directories.
"""

POLICY_SHA256 = hashlib.sha256(JUDGMENT_POLICY.encode()).hexdigest()


def policy_block() -> str:
    return f"judgment_policy_version: {POLICY_VERSION}\njudgment_policy_sha256: {POLICY_SHA256}\n\n{JUDGMENT_POLICY}"
