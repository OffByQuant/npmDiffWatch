"""Dependency screening must actually run.

The inner fetch closure in fetcher._screen_added_deps used to shadow the
module-level _fetch_json and call itself with the wrong arity, raising
TypeError for any added dep that needed a registry lookup -> screening never
completed and the release was retried forever.
"""
import dataclasses

from npmdiffwatch import fetcher
from npmdiffwatch.config import Config


def _cfg(tmp_path):
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("react\nlodash\nexpress\n")
    return dataclasses.replace(Config(), top_npm_path=corpus)


def test_screen_added_deps_looks_up_novel_dep_without_crashing(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    calls = []

    def fake_fetch_json(url, c):
        calls.append(url)
        return None  # registry 404 -> dep does not exist

    monkeypatch.setattr(fetcher, "_fetch_json", fake_fetch_json)

    new_ver = {"dependencies": {"totally-novel-package-xyz": "^1.0.0"}}
    findings = fetcher._screen_added_deps(new_ver, "host-pkg", None, None, cfg)

    # The closure must delegate to the module-level _fetch_json (with the
    # registry URL), not recurse into itself.
    assert calls and calls[0].endswith("/totally-novel-package-xyz")
    assert findings == [{"name": "totally-novel-package-xyz", "reason": "nonexistent"}]
