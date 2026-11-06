from npmdiffwatch.config import Config, ReviewerConfig, load_config
from npmdiffwatch import orchestrator
from tests.legacy_config import Config as LegacyConfig

import pytest


def test_real_defaults_select_abuse_and_enforce_sampled_rss(tmp_path):
    path = tmp_path / "default.toml"
    path.write_text("")
    for cfg in (Config(), load_config(path)):
        assert cfg.reviewer.workflow == "abuse"
        assert cfg.parse_rss_max_bytes == 4 * 1024**3
        assert cfg.reviewer.extension is None
        assert cfg.reviewer.queue_max_jobs == 10000
    assert ReviewerConfig().workflow == "abuse"
    assert LegacyConfig().reviewer.workflow == "legacy"


def test_abuse_default_rejects_cached_text_review_adapters():
    with pytest.raises(ValueError, match="legacy cached-text"):
        orchestrator._attempt_review(Config(), None, None, 1, "p", "1", 0, [], "text")
    with pytest.raises(ValueError, match="legacy pending-text"):
        orchestrator.drain_pending(Config(), None, None, auto=True)


def test_legacy_remains_an_explicit_operator_choice(tmp_path):
    path = tmp_path / "legacy.toml"
    path.write_text('[reviewer]\nworkflow = "legacy"\n')
    assert load_config(path).reviewer.workflow == "legacy"
