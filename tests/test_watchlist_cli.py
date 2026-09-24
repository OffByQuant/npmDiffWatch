# tests/test_watchlist_cli.py
import argparse
import dataclasses

import pytest

from npmdiffwatch import __main__ as cli, dashboard, orchestrator
from npmdiffwatch.config import Config


def _args(**kw):
    return argparse.Namespace(**{"config": None, "model": None, "endpoint": None, "watchlist": None, **kw})


def test_flag_sets_the_watchlist_and_beats_the_config(tmp_path):
    p = tmp_path / "c.toml"; p.write_text('watchlist = "from-config.txt"\n')
    assert cli._cfg(_args(config=str(p))).watchlist == "from-config.txt"
    assert cli._cfg(_args(config=str(p), watchlist="flag.txt")).watchlist == "flag.txt"


def test_an_unusable_watchlist_stops_the_run_with_a_message(tmp_path, capsys):
    cfg = dataclasses.replace(Config(), watchlist=str(tmp_path / "missing.txt"))
    with pytest.raises(SystemExit) as e:
        cli._watchlist_or_exit(cfg)
    assert e.value.code == 2 and "missing.txt" in capsys.readouterr().out


def test_no_watchlist_means_none():
    assert cli._watchlist_or_exit(Config()) is None


def test_dashboard_shows_the_watchlist_and_baseline(tmp_path):
    lst = tmp_path / "deps.txt"; lst.write_text("a\nb\n")
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", watchlist=str(lst))
    out = orchestrator.export_dashboard(cfg, out_path=tmp_path / "d.html")
    assert "watchlist: deps.txt · 2 packages · baseline 0/2" in out.read_text()
    assert "watchlist:" not in dashboard.render_dashboard([], status={}, generated_at="")


def test_pending_takes_a_watchlist_flag_and_survives_a_broken_list(tmp_path, monkeypatch, capsys):
    import sys
    lst = tmp_path / "deps.txt"; lst.write_text("a\n")
    base = ["npmdiffwatch", "-c", str(_paths(tmp_path)), "pending"]
    monkeypatch.setattr(sys, "argv", base + ["--watchlist", str(lst)])
    cli.main()
    assert "watchlist: deps.txt · 1 package · baseline 0/1" in capsys.readouterr().out
    lst.write_text("")
    monkeypatch.setattr(sys, "argv", base + ["--watchlist", str(lst)])
    cli.main()
    assert "has no packages" in capsys.readouterr().out


def _paths(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(f'db_path = "{tmp_path}/db.sqlite"\nlock_path = "{tmp_path}/l"\nreviewer_enabled = false\n')
    return p
