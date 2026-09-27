from pathlib import Path

from npmdiffwatch.config import load_config


def test_every_example_config_loads_and_leaves_the_investigator_off():
    for p in Path("examples").glob("*.toml"):
        assert load_config(p).investigator.enabled is False, p
