"""Strings the added code introduces — URLs, raw IPs, secret file paths, credential-like env names — with
where they appear. A list of where to look, never a verdict: legitimate code has all of these."""
import re

_URL = re.compile(r"""\b(?:https?|wss?|ftp)://[^\s'"`<>)\]}]{1,200}""")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SECRET = re.compile(r"""(?:~|\$HOME|%USERPROFILE%)?/\.(?:npmrc|netrc|pypirc|git-credentials|env\b|ssh(?:/[\w.-]+)?|"""
                     r"""aws(?:/[\w.-]+)?|docker/config\.json|kube/config|config/gcloud[\w./-]*|gnupg[\w./-]*)""")
_ENV = re.compile(r"""process\.env\.([A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH|SESSION)[A-Z0-9_]*)"""
                  r"""|process\.env\[\s*['"]([A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH|SESSION)"""
                  r"""[A-Z0-9_]*)['"]\s*\]""")


def introduced(diff, limit: int = 40) -> list[tuple[str, str, str]]:
    out, seen = [], set()
    for fd in diff.changed:
        for h in fd.hunks:
            for j, line in enumerate(h.added):
                loc = f"{fd.path}:{h.new_range[0] + j + 1}"
                found = [("url", m) for m in _URL.findall(line)]
                found += [("ip", m) for m in _IP.findall(line) if all(int(x) < 256 for x in m.split("."))]
                found += [("secret-path", m.group(0)) for m in _SECRET.finditer(line)]
                found += [("credential-env", a or b) for a, b in _ENV.findall(line)]
                for kind, value in found:
                    key = (kind, value[:200])
                    if key not in seen:
                        seen.add(key); out.append((kind, value[:200], loc))
                        if len(out) >= limit:
                            return out
    return out
