"""--model / --endpoint point the reviewer at an OpenAI-compatible server without a config file."""
import argparse

import pytest

from npmdiffwatch import __main__ as cli


def _args(**kw):
    return argparse.Namespace(**{"config": None, "model": None, "endpoint": None, **kw})


def test_model_alone_uses_the_default_local_endpoint():
    cfg = cli._cfg(_args(model="gemma-singleshot"))
    rc = cfg.reviewer
    assert (rc.provider, rc.model, rc.base_url) == ("openai", "gemma-singleshot", "http://localhost:8000/v1")
    assert cfg.reviewer_enabled


def test_endpoint_points_at_a_model_on_another_machine():
    rc = cli._cfg(_args(model="gemma-singleshot", endpoint="http://192.168.68.63:8000/v1")).reviewer
    assert (rc.model, rc.base_url) == ("gemma-singleshot", "http://192.168.68.63:8000/v1")


def test_flags_override_the_config_file(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[reviewer]\nprovider = "openai"\nbase_url = "http://localhost:9999/v1"\nmodel = "old"\n'
                 'timeout = 120.0\n')
    rc = cli._cfg(_args(config=str(p), model="new")).reviewer
    assert (rc.model, rc.base_url, rc.timeout) == ("new", "http://localhost:9999/v1", 120.0)


def test_no_flags_leaves_the_config_alone():
    rc = cli._cfg(_args()).reviewer
    assert rc.model == "qwen-singleshot"


def test_a_missing_config_file_stops_instead_of_using_the_default_database(tmp_path, capsys):
    missing = tmp_path / "typo.toml"
    try:
        cli._cfg(_args(config=str(missing)))
    except SystemExit as e:
        assert e.code == 2
    else:
        raise AssertionError("a missing -c file must not fall back to the built-in defaults")
    assert str(missing) in capsys.readouterr().err


def test_load_config_refuses_a_missing_file(tmp_path):
    from npmdiffwatch.config import load_config
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "typo.toml")
