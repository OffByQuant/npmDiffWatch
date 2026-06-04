import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field

from .config import Config
from .models import NewRelease
from . import egress

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ChangesPage:
    """One window of the replication feed.

    `releases` are the new versions discovered in the window. `watermark` is the
    highest `seq` consumed (the feed's last_seq), so the cursor can advance past
    windows that contained only deletes / non-release changes — otherwise the
    poller would re-read the same release-less page forever.
    """
    releases: list[NewRelease] = field(default_factory=list)
    watermark: int = 0


def _fetch_json(url: str, cfg: Config) -> dict | None:
    egress.assert_web_scheme(url)
    req = urllib.request.Request(url, headers={"User-Agent": "npmdiffwatch/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        logger.warning("HTTP %d fetching %s", e.code, url)
        return {}
    except Exception as e:
        logger.warning("fetch failed %s: %s", url, e)
        return {}


def _packument_url(package: str, cfg: Config) -> str:
    return f"{cfg.npm_registry.rstrip('/')}/{package}"


def _root_url(cfg: Config) -> str:
    return f"{cfg.npm_replicate.rstrip('/')}/"


def _changes_url(cfg: Config, since: int, limit: int) -> str:
    return f"{cfg.npm_replicate.rstrip('/')}/_changes?since={since}&limit={limit}"


def current_serial(cfg: Config) -> int | None:
    """Head of the replication feed (registry root `update_seq`)."""
    data = _fetch_json(_root_url(cfg), cfg)
    if data and isinstance(data.get("update_seq"), int):
        return data["update_seq"]
    return None


def _known_versions(conn, package: str) -> set[str]:
    rows = conn.execute("SELECT version FROM releases WHERE package=?", (package,)).fetchall()
    return {r[0] for r in rows}


def _newest_unseen_version(cfg: Config, package: str, conn) -> str | None:
    """The version a `_changes` row most likely refers to: the newest-by-publish
    version not already recorded. The feed row carries only a rev, not a version,
    so we resolve it from the packument's time map (falling back to dist-tags)."""
    packument = _fetch_json(_packument_url(package, cfg), cfg)
    if not packument or "versions" not in packument:
        return None
    versions = packument.get("versions", {})
    known = _known_versions(conn, package) if conn is not None else set()
    unseen = [v for v in versions if v not in known]
    if not unseen:
        return None
    times = packument.get("time", {}) or {}
    timed = [(times[v], v) for v in unseen if v in times]
    if timed:
        # npm timestamps are zero-padded UTC ISO-8601, so lexicographic == chronological.
        return max(timed)[1]
    latest = packument.get("dist-tags", {}).get("latest")
    return latest if latest in unseen else unseen[0]


def changes_since(cfg: Config, since_serial: int, conn=None, *, limit: int | None = None) -> ChangesPage:
    limit = limit or cfg.max_releases_per_run
    data = _fetch_json(_changes_url(cfg, since_serial, limit), cfg)
    watermark = since_serial
    releases: list[NewRelease] = []
    if not data or "results" not in data:
        return ChangesPage(releases, watermark)

    for row in data.get("results", []):
        seq = row.get("seq")
        if isinstance(seq, int) and seq > watermark:
            watermark = seq
        if row.get("deleted"):
            continue
        name = row.get("id")
        if not name or not isinstance(seq, int):
            continue
        version = _newest_unseen_version(cfg, name, conn)
        if version is None:
            continue
        releases.append(NewRelease(package=name, version=version, serial=seq))

    last_seq = data.get("last_seq")
    if isinstance(last_seq, int) and last_seq > watermark:
        watermark = last_seq

    releases.sort(key=lambda r: r.serial)
    return ChangesPage(releases, watermark)
