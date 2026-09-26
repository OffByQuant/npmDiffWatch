import io
import json
import tarfile

from npmdiffwatch import orchestrator, reviewer
from npmdiffwatch.config import Config
from npmdiffwatch.models import Download


def _tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for n, b in files.items():
            ti = tarfile.TarInfo(f"package/{n}"); ti.size = len(b); t.addfile(ti, io.BytesIO(b))
    return buf.getvalue()


class _B:
    primary_model, escalation_model, last_usage = "m", None, None
    def complete(self, **kw):
        return json.dumps({"decision": "clear"})


_PUB = {"publishing": {"provenance_now": False, "provenance_before": False, "trusted_publisher_now": None,
                       "trusted_publisher_before": None}}


def _dl(new_extra):
    pj0, pj1 = b'{"name":"p","version":"1.0.0"}', b'{"name":"p","version":"1.0.1"}'
    return Download("p", "1.0.1", "1.0.0", False, _tgz({"package.json": pj1, "index.js": b"1", **new_extra}),
                    _tgz({"package.json": pj0, "index.js": b"1", "README.md": b"# a\n"}), maintainer_metadata=_PUB)


def test_docs_only_is_tier_fact():
    got = orchestrator.evaluate_release(Config(), _dl({"README.md": b"# b\n"}), None,
                                        reviewer.Reviewer(Config(), backend=_B()), "off")
    assert got["tier"] == "fact" and got.get("verdict") is None


def test_small_code_change_is_short_checked():
    got = orchestrator.evaluate_release(Config(), _dl({"index.js": b"2"}), None,
                                        reviewer.Reviewer(Config(), backend=_B()), "off")
    assert got["tier"] == "short" and got["verdict"] == "benign"
