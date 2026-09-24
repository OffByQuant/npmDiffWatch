import json
import logging
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .config import Config
from .models import NewRelease
from . import egress, store
from .fetcher import read_body

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
            return json.loads(read_body(r, cfg, deadline=cfg.packument_deadline_s))
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


def _newest_unseen_version(packument: dict | None, package: str, conn) -> str | None:
    """The version a `_changes` row most likely refers to: the newest-by-publish
    version not already recorded. The feed row carries only a rev, not a version,
    so we resolve it from the packument's time map (falling back to dist-tags)."""
    if not packument or "versions" not in packument:
        return None
    versions = packument.get("versions", {})
    known = _known_versions(conn, package) if conn is not None else set()
    times = packument.get("time", {}) or {}
    known_timed = [(times[v], v) for v in known if v in times and v in versions]
    if known_timed:
        # Only versions published after the newest recorded one are candidates. A re-read row
        # (retry after review_failed, or a metadata-only change) resolves to that recorded version,
        # so run_once skips it (terminal) or retries it — never walks back into years-old history.
        newest_known_time, newest_known = max(known_timed)
        unseen = [v for v in versions if v not in known and times.get(v, "") > newest_known_time]
        if not unseen:
            return newest_known
    else:
        unseen = [v for v in versions if v not in known]
    if not unseen:
        return None
    timed = [(times[v], v) for v in unseen if v in times]
    if timed:
        # npm timestamps are zero-padded UTC ISO-8601, so lexicographic == chronological.
        return max(timed)[1]
    latest = packument.get("dist-tags", {}).get("latest")
    return latest if latest in unseen else unseen[0]


def changes_since(cfg: Config, since_serial: int, conn=None, *, limit: int | None = None, watch=None) -> ChangesPage:
    limit = limit or cfg.max_releases_per_run
    data = _fetch_json(_changes_url(cfg, since_serial, limit), cfg)
    watermark = since_serial
    releases: list[NewRelease] = []
    if not data or "results" not in data:
        return ChangesPage(releases, watermark)

    rows = []
    page_names = set()
    for row in data.get("results", []):
        seq = row.get("seq")
        if isinstance(seq, int) and seq > watermark:
            watermark = seq
        if row.get("deleted"):
            continue
        name = row.get("id")
        if not name or not isinstance(seq, int):
            continue
        if watch is not None and not watch.matches(name):
            continue          # watchlist mode: never download anything for an unlisted package
        rows.append((name, seq))
        page_names.add(name)
    if conn is not None:
        # Packages whose metadata failed to download on an earlier tick. The page may already carry them.
        rows += [(r["package"], since_serial) for r in store.feed_retries_due(conn)
                 if r["package"] not in page_names and (watch is None or watch.matches(r["package"]))]

    # Packument fetches dominate a tick (~1s each); run them concurrently. Version resolution reads
    # the DB, so it stays on this thread. Each packument is resolved and dropped as it arrives rather
    # than collected: some are tens of MB parsed, and a page holds up to max_releases_per_run of them.
    with ThreadPoolExecutor(max_workers=max(1, cfg.fetch_concurrency)) as ex:
        fetched = ex.map(lambda r: _fetch_json(_packument_url(r[0], cfg), cfg), rows)
        for (name, seq), packument in zip(rows, fetched):
            if conn is not None:
                if packument == {}:   # download failed (a 404 is None): keep it for the next tick, never drop it
                    store.note_feed_failure(conn, name, seq)
                    continue
                store.clear_feed_retry(conn, name)
            version = _newest_unseen_version(packument, name, conn)
            if version is None:
                continue
            releases.append(NewRelease(package=name, version=version, serial=seq))

    last_seq = data.get("last_seq")
    if isinstance(last_seq, int) and last_seq > watermark:
        watermark = last_seq

    releases.sort(key=lambda r: r.serial)
    return ChangesPage(releases, watermark)
