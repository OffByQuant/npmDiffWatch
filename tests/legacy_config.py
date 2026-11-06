"""Explicit compatibility profile for tests of the retired text/rules adapters.

New-workflow tests must use npmdiffwatch.config.Config directly. The old RSS
setting keeps legacy subprocess mocks focused on their original launcher.
"""
from dataclasses import replace

from npmdiffwatch.config import Config as CurrentConfig


def Config(**kwargs):
    cfg = CurrentConfig(**{"parse_rss_max_bytes": 0, **kwargs})
    return replace(cfg, reviewer=replace(cfg.reviewer, workflow="legacy"))
