"""urlopen's timeout bounds each socket read, not the download: a registry connection that trickles bytes
never trips it, and one stuck download froze a whole scan tick for 15+ minutes (live, 2026-09-24).
Every registry download gets a total deadline."""
import dataclasses

from npmdiffwatch import fetcher, ingest
from npmdiffwatch.config import Config


class _Trickle:
    """A response that sends 1 byte every 10 s, forever."""
    def __init__(self, clock):
        self.clock = clock

    def read1(self, n=-1):
        self.clock[0] += 10.0
        return b"x"

    def read(self, n=-1):
        return self.read1(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _trickling(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(fetcher.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(fetcher.urllib.request, "urlopen", lambda *a, **k: _Trickle(clock))
    return dataclasses.replace(Config(), fetch_deadline_s=120.0, packument_deadline_s=300.0), clock


def test_tarball_download_gives_up_at_the_deadline(monkeypatch):
    cfg, clock = _trickling(monkeypatch)
    try:
        fetcher._fetch_url("https://registry.npmjs.org/x/-/x-1.0.0.tgz", cfg)
        raise AssertionError("should have timed out")
    except TimeoutError:
        pass
    assert clock[0] <= 130.0


def test_packument_fetch_gives_up_at_the_deadline(monkeypatch):
    cfg, clock = _trickling(monkeypatch)
    assert fetcher._fetch_json("https://registry.npmjs.org/x", cfg) == {}
    assert clock[0] <= 310.0          # package metadata gets packument_deadline_s


def test_feed_packument_fetch_gives_up_at_the_deadline(monkeypatch):
    cfg, clock = _trickling(monkeypatch)
    monkeypatch.setattr(ingest.urllib.request, "urlopen", lambda *a, **k: _Trickle(clock))
    assert ingest._fetch_json("https://registry.npmjs.org/x", cfg) == {}
    assert clock[0] <= 310.0
