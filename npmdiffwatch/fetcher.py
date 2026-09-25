import gzip
import hashlib
import io
import json
import os
import posixpath
import tarfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import Config
from .models import NewRelease, ArtifactSet, Download
from . import quarantine, deps, egress, differ


class RefusedToExtract(Exception): ...
class RefusedToFetch(Exception): ...
class MetadataUnavailable(Exception): ...


@dataclass(frozen=True)
class Removed:
    """The registry no longer serves this release. `kind` is "unpublished" when npm marks the whole package
    removed (`time.unpublished`, with its time in `at`), "version_gone" when the package is live but this
    version is missing (no marker, no time)."""
    kind: str
    at: str | None = None


class _BoundedReader:
    def __init__(self, raw, limit: int):
        self._raw = raw; self._limit = limit; self._n = 0
    def read(self, size=-1):
        chunk = self._raw.read(size)
        self._n += len(chunk)
        if self._n > self._limit:
            raise RefusedToExtract("decompressed-size")
        return chunk


_SRC_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
_JSON_NAMES = {"package.json", "package-lock.json", "npm-shrinkwrap.json"}
_BIN_EXT = {".node", ".wasm"}
_FOREIGN_EXT = {".php", ".phtml", ".rb", ".pl", ".pm", ".go", ".java", ".class", ".jar",
                ".exe", ".dll", ".dylib", ".so", ".ps1", ".bat", ".cmd"}


def _is_source(name): return any(name.endswith(e) for e in _SRC_EXT) or name in _JSON_NAMES
def _is_strict_binary(name): return any(name.endswith(e) for e in _BIN_EXT)
def _foreign_ext(name):
    low = name.lower()
    return next((e for e in _FOREIGN_EXT if low.endswith(e)), None)
def _strip_top(name): return name.split("/", 1)[1] if "/" in name else name
def _unsafe(name): return name.startswith("/") or ".." in name.split("/")


def _sha256_of(fileobj) -> str:
    """Fingerprint a member without holding it in memory (an oversized source can be up to max_member_bytes)."""
    h = hashlib.sha256()
    while chunk := fileobj.read(1 << 20):
        h.update(chunk)
    return h.hexdigest()


def _is_text(data: bytes) -> bool:
    """Text by content, not by name: no NUL byte near the start and valid UTF-8."""
    if b"\x00" in data[:8192]:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def extract_tgz(blob: bytes, cfg: Config):
    files: dict[str, bytes] = {}
    binaries: list[dict] = []
    has_lockfile = False
    has_shrinkwrap = False
    total = 0
    count = 0
    foreign = 0

    stream = _BoundedReader(gzip.GzipFile(fileobj=io.BytesIO(blob)), cfg.max_decompressed_bytes)
    try:
        tar = tarfile.open(fileobj=stream, mode="r|")
    except (tarfile.ReadError, OSError, EOFError) as e:
        raise RefusedToExtract(f"bad-archive: {e}") from e

    with tar:
        for m in tar:
            count += 1
            if count > cfg.max_members:
                raise RefusedToExtract("members")
            if len(m.name) > cfg.max_name_bytes or not m.name.isprintable():
                raise RefusedToExtract("member-name")     # control characters in a path: never legitimate
            if not m.isfile():
                continue
            if _unsafe(m.name):
                continue
            total += m.size
            if total > cfg.max_total_bytes:
                raise RefusedToExtract("total-size")
            rel = _strip_top(m.name)

            if rel == "package-lock.json":
                has_lockfile = True
            if rel == "npm-shrinkwrap.json":
                has_shrinkwrap = True

            if m.size > cfg.max_member_bytes:
                # Too big to read, so it is fingerprinted and skipped; whatever runs it (an install script, the
                # code that loads it) is still scanned.
                entry = {"path": rel, "size": m.size, "sha256": _sha256_of(tar.extractfile(m))}
                if not _is_strict_binary(m.name):
                    entry["reason"] = "source-too-large" if _is_source(rel) else "file-too-large"
                binaries.append(entry)
            elif _is_source(rel) and m.size <= cfg.max_source_file_bytes:
                files[rel] = tar.extractfile(m).read(cfg.max_source_file_bytes + 1)
            elif _is_source(rel):
                binaries.append({"path": rel, "size": m.size, "reason": "source-too-large",
                                 "sha256": _sha256_of(tar.extractfile(m))})
            elif _is_strict_binary(m.name):
                data = tar.extractfile(m).read()
                binaries.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest(),
                                 "size": m.size})
            elif (fext := _foreign_ext(m.name)) and foreign < cfg.max_foreign_files:
                binaries.append({"path": rel, "size": m.size, "ext": fext,
                                 "reason": "foreign-language-source", "sha256": _sha256_of(tar.extractfile(m))})
                foreign += 1
            elif m.size <= cfg.max_source_file_bytes:
                # Any other text file (shell or Python scripts, extensionless commands, data files): what an
                # install hook runs or shipped code reads can carry the payload, whatever its name.
                data = tar.extractfile(m).read(cfg.max_source_file_bytes + 1)
                if _is_text(data):
                    files[rel] = data

    return files, binaries, has_lockfile, has_shrinkwrap


def read_body(r, cfg: Config, limit: int | None = None, deadline: float | None = None) -> bytes:
    """A response body within a total deadline (seconds; default fetch_deadline_s). urlopen's timeout bounds
    each socket read only, so a connection that trickles bytes would otherwise hold a scan tick forever."""
    budget = deadline or cfg.fetch_deadline_s
    deadline = time.monotonic() + budget
    buf = bytearray()
    while chunk := r.read1(65536):
        buf += chunk
        if limit is not None and len(buf) > limit:
            raise RefusedToFetch("download-size")
        if time.monotonic() > deadline:
            raise TimeoutError(f"download took longer than {budget:.0f}s")
    return bytes(buf)


def _fetch_url(url: str, cfg: Config) -> bytes:
    egress.assert_web_scheme(url)
    req = urllib.request.Request(url, headers={"User-Agent": "npmdiffwatch/0.1"})
    with urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s) as r:
        return read_body(r, cfg, cfg.max_download_bytes)


def _fetch_json(url: str, cfg: Config) -> dict | None:
    egress.assert_web_scheme(url)
    req = urllib.request.Request(url, headers={"User-Agent": "npmdiffwatch/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s) as r:
            return json.loads(read_body(r, cfg, deadline=cfg.packument_deadline_s))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return {}
    except Exception:
        return {}


_SURFACE_NAMES = {"package.json", "index.js", "main.js", "cli.js",
                  "preinstall.js", "install.js", "postinstall.js"}


def _is_surface(path: str) -> bool:
    base = posixpath.basename(path)
    return base in _SURFACE_NAMES or "/bin/" in path


def _packument(package: str, cfg: Config) -> dict | None:
    url = f"{cfg.npm_registry.rstrip('/')}/{package}"
    return _fetch_json(url, cfg)


def _pick_predecessor(meta: dict, version: str):
    versions = meta.get("versions", {})
    tgt = versions.get(version)
    if not tgt:
        return None
    tgt_time = None
    time_map = meta.get("time", {})
    for v, ts in time_map.items():
        if v == version:
            tgt_time = ts
            break
    best = None
    for ver, vdata in versions.items():
        if ver == version:
            continue
        if vdata.get("deprecated"):
            continue
        ts = time_map.get(ver)
        if not ts or (tgt_time is not None and ts >= tgt_time):
            continue
        if best is None or ts > best[0]:
            dist = vdata.get("dist", {})
            best = (ts, ver, dist.get("tarball"))
    return (best[1], best[2]) if best else None


_DEP_FIELDS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")


def _parse_deps(version_data: dict) -> set[str]:
    result = set()
    for field in _DEP_FIELDS:
        deps_dict = version_data.get(field, {}) or {}
        for name in deps_dict:
            result.add(deps.normalize_name(name))
    return result


def _screen_added_deps(new_ver: dict, package: str, pred_ver: str | None,
                       pred_ver_data: dict | None, cfg: Config) -> list[dict]:
    new_deps = _parse_deps(new_ver)
    if not new_deps:
        return []
    prior_deps: set[str] = set()
    if pred_ver_data is not None:
        prior_deps = _parse_deps(pred_ver_data)
    added = new_deps - prior_deps
    if not added:
        return []

    corpus_path = cfg.top_npm_path
    if corpus_path is None:
        corpus_path = os.path.join(os.path.dirname(__file__), "data", "top_npm_names.txt")
    corpus = deps.load_corpus(str(corpus_path))

    def _lookup(name):
        url = f"{cfg.npm_registry.rstrip('/')}/{name}"
        return _fetch_json(url, cfg)

    return deps.screen_added_deps(added, corpus, fetch_json=_lookup,
                                  now=datetime.now(timezone.utc),
                                  brandnew_days=cfg.dep_brandnew_days,
                                  cap=cfg.max_dep_lookups)


def _publisher_of(version_data: dict | None) -> str | None:
    return ((version_data or {}).get("_npmUser") or {}).get("name")


def _publisher_changed(versions: dict, new_version: str, prior_version: str | None) -> bool:
    """True when the new version was published by a different npm account than its
    predecessor. Fails closed (False) if either publisher is unknown, so a missing
    _npmUser never produces a false positive."""
    if not prior_version:
        return False
    new_pub = _publisher_of(versions.get(new_version))
    prior_pub = _publisher_of(versions.get(prior_version))
    return bool(new_pub and prior_pub and new_pub != prior_pub)


def _publisher_footprint(name: str, cfg: Config, fetch_json=_fetch_json) -> int | None:
    """How many packages the npm account `name` maintains, via the registry
    search API. None if the lookup fails or the registry doesn't support search
    (e.g. a private mirror) — callers must fail closed on None."""
    from urllib.parse import quote
    url = f"{cfg.npm_registry.rstrip('/')}/-/v1/search?text=maintainer:{quote(name)}&size=1"
    data = fetch_json(url, cfg)
    if isinstance(data, dict) and isinstance(data.get("total"), int):
        return data["total"]
    return None


def _low_footprint_publisher(version_data: dict | None, cfg: Config,
                             fetch_json=_fetch_json) -> bool:
    """True when the version's publisher maintains <= publisher_footprint_max
    packages — npm exposes no account-creation date, so footprint proxies a
    fresh/throwaway account. Fails closed if the publisher is unknown or the
    footprint can't be resolved. Only meaningful when the publisher changed;
    the caller gates the (networked) lookup on that."""
    name = _publisher_of(version_data)
    if not name:
        return False
    footprint = _publisher_footprint(name, cfg, fetch_json)
    if footprint is None:
        return False
    return footprint <= cfg.publisher_footprint_max


def _maintainer_metadata(meta: dict) -> dict:
    maintainers = meta.get("maintainers", []) or []
    time_map = meta.get("time", {})
    return {
        "author": None,
        "maintainers": [m.get("name") for m in maintainers if m.get("name")],
        "created": time_map.get("created"),
    }


def _publishing(versions: dict, new_version: str, prior_version: str | None, times: dict) -> dict:
    """How this version and the one before it were published. Facts only: a long CI-published package
    suddenly published from a personal token is worth a look, but it is never a verdict."""
    def rec(v):
        r = versions.get(v)
        return r if isinstance(r, dict) else {}
    def prov(v):
        dist = rec(v).get("dist")
        att = dist.get("attestations") if isinstance(dist, dict) else None
        return bool(att.get("provenance")) if isinstance(att, dict) else False
    def trusted(v):
        user = rec(v).get("_npmUser")
        tp = user.get("trustedPublisher") if isinstance(user, dict) else None
        return tp.get("id") if isinstance(tp, dict) and isinstance(tp.get("id"), str) else None
    def when(v):
        try:
            return datetime.fromisoformat(str(times.get(v)).replace("Z", "+00:00"))
        except ValueError:
            return None
    def _days(a, b):
        try:
            return round((a - b).total_seconds() / 86400, 1) if a and b else None
        except TypeError:          # one timestamp without a timezone: no fact rather than no scan
            return None
    repo = rec(new_version).get("repository")
    repo = repo.get("url") if isinstance(repo, dict) else repo if isinstance(repo, str) else None
    t_new, t_old = when(new_version), when(prior_version) if prior_version else None
    return {"provenance_now": prov(new_version),
            "provenance_before": prov(prior_version) if prior_version else None,
            "trusted_publisher_now": trusted(new_version),
            "trusted_publisher_before": trusted(prior_version) if prior_version else None,
            "days_since_prior": _days(t_new, t_old),
            "repository": repo[:300] if isinstance(repo, str) else None}


def download(cfg, rel: NewRelease, meta: dict | None = None) -> "Download | ArtifactSet | Removed | None":
    """Everything that needs the network, and nothing that opens the tarballs. Returns an ArtifactSet (with no
    files) when the release is a new package the config skips, since there is nothing to unpack."""
    if quarantine.is_quarantined(rel.package):
        raise RefusedToFetch(f"quarantined: {rel.package}")

    meta = meta if meta is not None else _packument(rel.package, cfg)
    if meta == {}:        # a failed download, not a missing package: retry, don't mark it "nothing to scan"
        raise MetadataUnavailable(f"could not download package metadata for {rel.package}")
    times = (meta or {}).get("time")
    unpublished = times.get("unpublished") if isinstance(times, dict) else None
    if isinstance(unpublished, dict):
        return Removed("unpublished", unpublished.get("time"))
    if not meta or "versions" not in meta:
        return None

    versions = meta.get("versions", {})
    if rel.version not in versions:
        return Removed("version_gone")
    new_ver_data = versions[rel.version]
    if not new_ver_data:
        return None

    dist = new_ver_data.get("dist", {})
    tarball_url = dist.get("tarball")
    if not tarball_url:
        return None

    pred = _pick_predecessor(meta, rel.version)
    is_new = pred is None
    mtmeta = _maintainer_metadata(meta)
    pub_changed = _publisher_changed(versions, rel.version, pred[0] if pred else None)
    mtmeta["publisher_changed"] = pub_changed
    # Footprint lookup is one extra request; only do it when the publisher changed.
    mtmeta["low_footprint_publisher"] = bool(
        pub_changed and _low_footprint_publisher(new_ver_data, cfg))
    mtmeta["publishing"] = _publishing(versions, rel.version, pred[0] if pred else None,
                                       meta.get("time") if isinstance(meta.get("time"), dict) else {})
    scripts = new_ver_data.get("scripts", {}) or {}

    if is_new and cfg.new_package_policy == "skip":
        return ArtifactSet(rel.package, rel.version, None, "tgz", {}, {}, {},
                           is_new_package=True, maintainer_metadata=mtmeta,
                           scripts_field=scripts,
                           has_lockfile=False)

    tgz_bytes = _fetch_url(tarball_url, cfg)
    prior_ver = prior_tgz = None
    dep_findings: list[dict] = []
    if not is_new:
        prior_ver, prior_url = pred
        try:
            prior_tgz = _fetch_url(prior_url, cfg)
        except Exception:
            prior_tgz = None
        pred_ver_data = versions.get(prior_ver)
        dep_findings = _screen_added_deps(new_ver_data, rel.package, prior_ver, pred_ver_data, cfg)

    return Download(rel.package, rel.version, prior_ver, is_new, tgz_bytes, prior_tgz,
                    maintainer_metadata=mtmeta, added_dep_findings=dep_findings, scripts_field=scripts,
                    manifest=differ.manifest_fields(new_ver_data),
                    prior_manifest=differ.manifest_fields(versions.get(prior_ver)) if prior_ver else None)


def extract_download(cfg, dl: Download) -> ArtifactSet:
    """Unpack a Download's tarballs. No network: this is the part that runs in the parse sandbox."""
    new_files, new_bins, has_lockfile, has_shrinkwrap = extract_tgz(dl.new_blob, cfg)

    prior_files: dict[str, bytes] = {}
    prior_bins = None
    if dl.is_new_package:
        if cfg.new_package_policy == "surface":
            new_files = {p: b for p, b in new_files.items() if _is_surface(p)}
    elif dl.prior_blob is not None:
        try:
            prior_files, prior_bins, _, _ = extract_tgz(dl.prior_blob, cfg)
        except Exception:
            prior_files, prior_bins = {}, None
    if prior_bins is not None:
        # Only what this release adds or changes is a signal; an unchanged bundle republished by CI is not.
        same = {(b["path"], b.get("sha256")) for b in prior_bins if b.get("sha256")}
        new_bins = [b for b in new_bins if (b["path"], b.get("sha256")) not in same]

    return ArtifactSet(dl.package, dl.version, dl.prior_version, "tgz",
                       new_files, prior_files, {}, new_bins,
                       is_new_package=dl.is_new_package, maintainer_metadata=dl.maintainer_metadata,
                       added_dep_findings=list(dl.added_dep_findings),
                       scripts_field=dl.scripts_field,
                       has_lockfile=has_lockfile, has_shrinkwrap=has_shrinkwrap)


def fetch_artifacts(cfg, rel: NewRelease, meta: dict | None = None) -> "ArtifactSet | Removed | None":
    dl = download(cfg, rel, meta)
    return extract_download(cfg, dl) if isinstance(dl, Download) else dl
