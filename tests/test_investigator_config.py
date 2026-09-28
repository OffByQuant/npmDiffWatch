import dataclasses

from npmdiffwatch import egress, sandbox
from npmdiffwatch.config import Config, load_config


def test_the_step_limit_defaults_to_30():
    assert Config().investigator.max_steps == 30


def test_investigator_is_off_by_default():
    assert Config().investigator.enabled is False


def test_investigator_table_loads(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[investigator]\nenabled = true\nbase_url = "http://10.0.0.5:8080/v1"\nmodel = "m"\n'
                 'also_allow = ["api.osv.dev"]\nmax_steps = 9\n')
    inv = load_config(p).investigator
    assert inv.enabled and inv.model == "m" and inv.max_steps == 9 and inv.also_allow == ("api.osv.dev",)


def test_investigator_hosts_are_the_allowlist_plus_the_endpoint():
    inv = dataclasses.replace(Config().investigator, base_url="http://10.0.0.5:8080/v1", also_allow=("api.osv.dev",))
    hosts = egress.investigator_hosts(dataclasses.replace(Config(), investigator=inv))
    assert hosts == frozenset({"registry.npmjs.org", "api.github.com", "10.0.0.5", "api.osv.dev"})


def test_anthropic_investigator_allows_the_api_host():
    inv = dataclasses.replace(Config().investigator, provider="anthropic")
    assert "api.anthropic.com" in egress.investigator_hosts(dataclasses.replace(Config(), investigator=inv))


def test_the_parse_worker_config_has_no_investigator_block():
    d = sandbox._cfg_to_dict(Config())
    assert "investigator" not in d and "reviewer" not in d
    sandbox._cfg_from_dict(d)          # must not raise
