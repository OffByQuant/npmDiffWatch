"""Default-deny egress guard: scheme gate, host allowlist construction, and the
socket.getaddrinfo wrapper."""
import dataclasses
import socket

import pytest

from npmdiffwatch import egress
from npmdiffwatch.config import Config


def test_assert_web_scheme_allows_http_and_https():
    egress.assert_web_scheme("https://registry.npmjs.org/x")
    egress.assert_web_scheme("http://localhost:8000/v1")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x", "gopher://h", "data:text/plain,hi"])
def test_assert_web_scheme_denies_non_web(url):
    with pytest.raises(egress.EgressDenied):
        egress.assert_web_scheme(url)


def test_allowed_hosts_includes_registry_reviewer_and_webhook():
    cfg = dataclasses.replace(
        Config(),
        npm_registry="https://registry.npmjs.org",
        webhook_url="https://hooks.example.com/notify",
    )
    hosts = egress.allowed_hosts(cfg)
    assert "registry.npmjs.org" in hosts
    assert "hooks.example.com" in hosts
    # default reviewer is openai at localhost:8000
    assert "localhost" in hosts


def test_allowed_hosts_includes_replication_feed():
    # ingest polls cfg.npm_replicate (the _changes feed + root update_seq); its host
    # is distinct from cfg.npm_registry, so the guard must allow it or polling is dead.
    cfg = dataclasses.replace(
        Config(),
        npm_registry="https://registry.npmjs.org",
        npm_replicate="https://replicate.npmjs.com/registry",
    )
    hosts = egress.allowed_hosts(cfg)
    assert "replicate.npmjs.com" in hosts


def test_guard_blocks_disallowed_host_and_uninstalls_cleanly():
    cfg = Config()
    assert not egress.is_installed()
    egress.install_guard(cfg)
    try:
        assert egress.is_installed()
        with pytest.raises(egress.EgressDenied):
            socket.getaddrinfo("evil.example.com", 443)
    finally:
        egress.uninstall_guard()
    assert not egress.is_installed()


def test_guard_is_idempotent_and_restores_original():
    cfg = Config()
    original = socket.getaddrinfo
    egress.install_guard(cfg)
    egress.install_guard(cfg)  # second call is a no-op
    egress.uninstall_guard()
    assert socket.getaddrinfo is original
