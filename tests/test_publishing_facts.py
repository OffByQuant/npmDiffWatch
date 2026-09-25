import io
import tarfile

from npmdiffwatch import fetcher, sandbox
from npmdiffwatch.config import Config
from npmdiffwatch.models import Download


_ATT = {"url": "https://registry.npmjs.org/-/npm/v1/attestations/p@1.0.1",
        "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}


def test_provenance_and_trusted_publisher_dropped():
    versions = {"1.0.0": {"dist": {"attestations": _ATT}, "_npmUser": {"name": "ci", "trustedPublisher": {"id": "github"}},
                          "repository": {"url": "git+https://github.com/o/p.git"}},
                "1.0.1": {"dist": {}, "_npmUser": {"name": "someone"}, "repository": {"url": "git+https://github.com/o/p.git"}}}
    times = {"1.0.0": "2026-09-01T00:00:00.000Z", "1.0.1": "2026-09-11T12:00:00.000Z"}
    p = fetcher._publishing(versions, "1.0.1", "1.0.0", times)
    assert p == {"provenance_now": False, "provenance_before": True, "trusted_publisher_now": None,
                 "trusted_publisher_before": "github", "days_since_prior": 10.5,
                 "repository": "git+https://github.com/o/p.git"}


def test_first_release_has_no_before():
    p = fetcher._publishing({"1.0.0": {"dist": {}}}, "1.0.0", None, {})
    assert p["provenance_before"] is None and p["days_since_prior"] is None and p["repository"] is None


def test_the_parent_sets_publishing_not_the_worker():
    def tgz(files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            for n, b in files.items():
                ti = tarfile.TarInfo(f"package/{n}"); ti.size = len(b); t.addfile(ti, io.BytesIO(b))
        return buf.getvalue()
    pub = {"provenance_now": True, "provenance_before": True, "trusted_publisher_now": "github",
           "trusted_publisher_before": "github", "days_since_prior": 1.0, "repository": None}
    dl = Download("p", "1.0.1", "1.0.0", False, tgz({"package.json": b'{"name":"p","version":"1.0.1"}', "a.js": b"1"}),
                  tgz({"package.json": b'{"name":"p","version":"1.0.0"}', "a.js": b"0"}),
                  maintainer_metadata={"maintainers": ["m"], "publishing": pub})
    _, d, _ = sandbox.analyze(Config(), dl, None, backend="off")
    assert d.publishing == pub
