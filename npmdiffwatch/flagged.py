"""The tarballs of releases the reviewer called malicious, kept for the investigator after npm removes them.
Plain files beside the database (the database is VACUUMed daily), mode 0600, never unpacked here."""
import datetime
import logging
import os
from pathlib import Path

from . import fetcher, store
from .models import Download, NewRelease

logger = logging.getLogger(__name__)


def blob_dir(cfg) -> Path:
    return cfg.db_path.parent / "flagged"


def _write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def capture(cfg, conn, rid, download=fetcher.download) -> str:
    if store.flagged_get(conn, rid) is not None:
        return "exists"
    row = conn.execute("SELECT package, version, serial FROM releases WHERE id=?", (rid,)).fetchone()
    try:
        dl = download(cfg, NewRelease(row["package"], row["version"], row["serial"] or 0))
    except Exception as e:                       # the scan must never fail because of this
        logger.warning("could not store flagged %s==%s: %s", row["package"], row["version"], e)
        return f"failed: {type(e).__name__}: {e}"
    if not isinstance(dl, Download):
        return "gone"
    d = blob_dir(cfg)
    d.mkdir(parents=True, exist_ok=True)
    new_path = d / f"{rid}-new.tgz"
    _write(new_path, dl.new_blob)
    prior_path = None
    if dl.prior_blob is not None:
        prior_path = d / f"{rid}-prior.tgz"
        _write(prior_path, dl.prior_blob)
    store.flagged_put(conn, rid, dl.package, dl.version, dl.prior_version, str(new_path),
                      str(prior_path) if prior_path else None, len(dl.new_blob) + len(dl.prior_blob or b""))
    return "stored"


def load(cfg, conn, rid) -> Download | None:
    row = store.flagged_get(conn, rid)
    if row is None:
        return None
    try:
        new = Path(row["new_path"]).read_bytes()
        prior = Path(row["prior_path"]).read_bytes() if row["prior_path"] else None
    except OSError:
        return None
    return Download(row["package"], row["version"], row["prior_version"], row["prior_version"] is None, new, prior)


def _drop(conn, row) -> None:
    for k in ("new_path", "prior_path"):
        if row[k]:
            Path(row[k]).unlink(missing_ok=True)
    store.flagged_delete(conn, row["release_id"])


def prune(cfg, conn, now=None) -> int:
    """Keep while labelled malicious; drop on a benign label, or after keep_flagged_days if not labelled
    malicious; then evict the oldest not labelled malicious until under flagged_max_gb."""
    inv = cfg.investigator
    now = now or datetime.datetime.now(datetime.UTC)
    cutoff = (now - datetime.timedelta(days=inv.keep_flagged_days)).isoformat()
    dropped = 0
    for r in store.flagged_all(conn):
        label = (r["human_label"] or "").lower()
        if label == "malicious":
            continue
        if label == "benign" or r["stored_at"] < cutoff:
            _drop(conn, r)
            dropped += 1
    rows = store.flagged_all(conn)
    total = sum(r["bytes"] or 0 for r in rows)
    for r in rows:
        if total <= inv.flagged_max_gb * 1e9:
            break
        if (r["human_label"] or "").lower() == "malicious":
            continue
        total -= r["bytes"] or 0
        _drop(conn, r)
        dropped += 1
    return dropped
