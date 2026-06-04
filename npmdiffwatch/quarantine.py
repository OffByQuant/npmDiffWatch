import re


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


# npm-specific quarantine list — confirmed supply-chain malware.
# Populated as confirmed; refetch is always refused.
KNOWN_MALICIOUS = frozenset({
    "eslint-scope",       # 2018: eslint-scope 3.7.2 shipped malware stealing npm credentials
    "event-stream",       # 2018: event-stream 3.3.6 contained flatmap-stream (copay bitcoin theft)
    "node-ipc",           # 2022: peacenotwar protestware that deleted files in Russia/Belarus
})


def is_quarantined(package: str) -> bool:
    return _norm(package) in KNOWN_MALICIOUS
