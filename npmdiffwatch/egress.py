import logging
import socket
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_REGISTRY_HOST = "registry.npmjs.org"
_ANTHROPIC_HOST = "api.anthropic.com"

_original_getaddrinfo = None


class EgressDenied(Exception):
    pass


def _host_of(url):
    return urlsplit(url).hostname if url else None


_WEB_SCHEMES = frozenset({"http", "https"})


def assert_web_scheme(url) -> None:
    scheme = (urlsplit(url).scheme or "").lower() if url else ""
    if scheme not in _WEB_SCHEMES:
        raise EgressDenied(f"egress to non-web scheme {scheme!r} denied (url={url!r})")


def allowed_hosts(cfg) -> frozenset:
    hosts = {_REGISTRY_HOST}
    npm = _host_of(getattr(cfg, "npm_registry", None))
    if npm:
        hosts.add(npm)
    if getattr(cfg, "reviewer_enabled", True):
        rc = getattr(cfg, "reviewer", None)
        if rc is not None and rc.provider == "openai":
            h = _host_of(rc.base_url)
            if h:
                hosts.add(h)
        elif rc is not None and rc.provider == "anthropic":
            hosts.add(_ANTHROPIC_HOST)
    wh = _host_of(getattr(cfg, "webhook_url", None))
    if wh:
        hosts.add(wh)
    return frozenset(hosts)


def install_guard(cfg) -> None:
    global _original_getaddrinfo
    if _original_getaddrinfo is not None:
        return
    real = socket.getaddrinfo
    allowed = allowed_hosts(cfg)
    logger.info("egress guard installed; allowlist=%s", sorted(allowed))

    def _guarded(host, *args, **kwargs):
        if host is None:
            return real(host, *args, **kwargs)
        if host not in allowed:
            raise EgressDenied(f"egress to {host!r} denied (allowlist: {sorted(allowed)})")
        return real(host, *args, **kwargs)

    _original_getaddrinfo = real
    socket.getaddrinfo = _guarded


def is_installed() -> bool:
    return _original_getaddrinfo is not None


def uninstall_guard() -> None:
    global _original_getaddrinfo
    if _original_getaddrinfo is not None:
        socket.getaddrinfo = _original_getaddrinfo
        _original_getaddrinfo = None
