import dataclasses
import datetime
import fcntl
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor

from . import ingest, fetcher, differ, engine, rules, notifier, store, reviewer, egress
from .config import Config
from .models import Verdict, NewRelease, FiredRule

logger = logging.getLogger(__name__)

TERMINAL = {"triaged", "alerted", "reviewed", "new_package_skipped", "needs_adjudication",
            "refused_to_extract", "no_sdist", "refused_to_fetch"}


def _load_ruleset(cfg):
    return rules.load_rules(cfg.rules_dir)


def _build_reviewer(cfg):
    if not cfg.reviewer_enabled:
        logger.info("reviewer disabled; heuristic-only this run")
        return None
    if cfg.reviewer.provider == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        logger.info("anthropic reviewer backend selected but no ANTHROPIC_API_KEY; heuristic-only this run")
        return None
    return reviewer.Reviewer(cfg)


def _review_escalated(cfg, conn, rvw, d, tr, rid):
    if rvw is None:
        notifier.emit(cfg, conn, Verdict(d.package, d.version, "suspicious-heuristic",
                                         tr.score, tr.fired_rules, False), rid)
        store.update_stage(conn, rid, "alerted", tr.score, None)
        return
    try:
        verdict = rvw.review(d, tr)
    except reviewer.ReviewUnavailable:
        logger.warning("LLM unavailable for %s==%s; heuristic fallback, will retry", d.package, d.version)
        notifier.emit(cfg, conn, Verdict(d.package, d.version, "suspicious-heuristic",
                                         tr.score, tr.fired_rules, False), rid)
        store.update_stage(conn, rid, "review_failed", tr.score, None)
        return
    store.record_verdict(conn, rid, verdict)
    if verdict.classification == "benign":
        store.update_stage(conn, rid, "reviewed", tr.score, None)
    elif verdict.classification == "suspicious":
        store.update_stage(conn, rid, "needs_adjudication", tr.score, None)
    else:
        notifier.emit(cfg, conn, verdict, rid)
        store.update_stage(conn, rid, "reviewed", tr.score, None)


def _fetch_one(cfg, rel):
    try:
        return fetcher.fetch_artifacts(cfg, rel)
    except Exception as e:
        return e


def _process_fetched(cfg, conn, rvw, ruleset, rel, result) -> bool:
    rid = store.record_release(conn, rel.package, rel.version, rel.serial, False, None, "tgz")
    if isinstance(result, fetcher.RefusedToFetch):
        store.update_stage(conn, rid, "refused_to_fetch")
        return True
    if isinstance(result, fetcher.RefusedToExtract):
        store.update_stage(conn, rid, "refused_to_extract")
        notifier.emit(cfg, conn, Verdict(rel.package, rel.version,
                      "suspicious-heuristic", 0.0, [], False), rid)
        return True
    if isinstance(result, Exception):
        logger.warning("fetch_failed for %s==%s; will retry next tick", rel.package, rel.version)
        store.update_stage(conn, rid, "fetch_failed")
        return False
    if result is None:
        store.update_stage(conn, rid, "no_sdist")
        return True

    store.set_baseline(conn, rid, result.prior_version, result.is_new_package)
    if result.maintainer_metadata is not None:
        store.update_release_metadata(conn, rid, json.dumps(result.maintainer_metadata))
    if result.packument_json is not None or result.scripts_field is not None:
        store.update_npm_metadata(conn, rid,
                                  packument_json=result.packument_json,
                                  scripts_json=json.dumps(result.scripts_field) if result.scripts_field else None,
                                  has_lockfile=result.has_lockfile,
                                  has_shrinkwrap=result.has_shrinkwrap)
    if result.is_new_package and cfg.new_package_policy == "skip":
        store.update_stage(conn, rid, "new_package_skipped")
        return True

    try:
        d = differ.build_diff(result)
        store.update_stage(conn, rid, "diffed")
        prior_meta = (store.get_release_metadata(conn, rel.package, result.prior_version)
                      if result.prior_version else None)
        tr = engine.triage(d, cfg, ruleset, {"current": result.maintainer_metadata, "prior": prior_meta})
        store.update_stage(conn, rid, "triaged", tr.score,
                           json.dumps([r.__dict__ for r in tr.fired_rules]))
        ev = reviewer.build_evidence(d, tr, max_chars=cfg.evidence_max_chars)
        if ev:
            store.update_evidence(conn, rid, ev)
        if tr.escalate:
            _review_escalated(cfg, conn, rvw, d, tr, rid)
        return True
    except Exception:
        logger.exception("processing failed for %s==%s; will retry next tick", rel.package, rel.version)
        store.update_stage(conn, rid, "fetch_failed")
        return False


def seed_now(cfg: Config):
    conn = store.connect(cfg); store.init_schema(conn)
    s = ingest.current_serial(cfg)
    if s is not None:
        store.set_last_serial(conn, s)
    return s


def run_once(cfg: Config, *, seed_if_fresh: bool = True) -> int:
    if not egress.is_installed():
        logger.warning("egress guard not installed; this process has no in-process host allowlist "
                       "(see docs/hardening/egress-allowlist.md or call egress.install_guard(cfg))")
    cfg.lock_path.parent.mkdir(parents=True, exist_ok=True)
    # "a+" (not "w"): opening must NOT truncate, so a run that loses the lock can still read the holder
    # info the winner wrote below and report who's running.
    lock = open(cfg.lock_path, "a+")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.seek(0)
        holder = lock.read().strip()
        lock.close()
        who = f" ({holder})" if holder else ""
        print(
            f"[npmdiffwatch] a scan is already running{who}; this invocation is exiting so the two "
            f"don't collide.\n"
            f"  lock file: {cfg.lock_path}\n"
            f"  - If that's your scheduled run (cron/systemd/CI), this is expected: space the schedule "
            f"so one tick finishes before the next starts.\n"
            f"  - If you're sure nothing is running, a previous run was likely killed or hung mid-fetch "
            f"and still holds the lock. Kill the reported pid and re-run. The lock is an OS-level "
            f"advisory lock that frees automatically when the holding process exits, so deleting the "
            f"lock file does NOT release a live lock — leave it in place.")
        return 0
    # Lock held. Record who holds it so a colliding run can report it above; flock frees on close/exit.
    lock.seek(0); lock.truncate()
    lock.write(f"pid={os.getpid()} since={datetime.datetime.now(datetime.UTC).isoformat()}"); lock.flush()
    try:
        conn = store.connect(cfg); store.init_schema(conn)
        last = store.get_last_serial(conn)

        if seed_if_fresh and last == 0:
            now_serial = ingest.current_serial(cfg)
            if now_serial is None:
                logger.warning("fresh cursor but npm registry unavailable; skipping run "
                               "(retry next tick). Use 'run --backfill' to process from genesis.")
                return 0
            store.set_last_serial(conn, now_serial)
            logger.info("fresh cursor seeded to npm serial %d; monitoring starts now", now_serial)
            return 0

        rvw = _build_reviewer(cfg)
        ruleset = _load_ruleset(cfg)
        page = ingest.changes_since(cfg, last, conn, limit=cfg.max_releases_per_run)
        releases = page.releases
        prepared = [(rel, store.get_stage(conn, rel.package, rel.version)) for rel in releases]

        advance_to = last
        blocked = False
        W = max(1, cfg.fetch_concurrency)
        with ThreadPoolExecutor(max_workers=W) as ex:
            for start in range(0, len(prepared), W):
                window = prepared[start:start + W]
                futs = {i: ex.submit(_fetch_one, cfg, rel)
                        for i, (rel, stg) in enumerate(window) if stg not in TERMINAL}
                for i, (rel, stg) in enumerate(window):
                    if stg in TERMINAL:
                        terminal = True
                    else:
                        terminal = _process_fetched(cfg, conn, rvw, ruleset, rel, futs[i].result())
                    if terminal and not blocked:
                        advance_to = rel.serial
                    else:
                        blocked = True
        # Nothing stuck: advance past the whole window, including release-less
        # tail changes, so the cursor never stalls on a page that yields no work.
        if not blocked:
            advance_to = max(advance_to, page.watermark)
        store.set_last_serial(conn, advance_to)
        return len(releases)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN); lock.close()


def _rules_from_json(s):
    return [FiredRule(r["rule"], r["weight"], r["file"], tuple(r["lines"])) for r in json.loads(s or "[]")]


def list_pending(cfg: Config):
    conn = store.connect(cfg); store.init_schema(conn)
    ruleset = _load_ruleset(cfg)
    items = []
    for row in store.pending_adjudication(conn):
        stored = row["evidence"]
        diff_text, err = stored, None
        if not stored:
            try:
                art = fetcher.fetch_artifacts(cfg, NewRelease(row["package"], row["version"], row["serial"]))
                if art is not None:
                    d = differ.build_diff(art)
                    tr = engine.triage(d, cfg, ruleset)
                    diff_text = reviewer.build_review_input(d, tr, max_chars=cfg.reviewer.max_input_chars)
            except Exception as e:
                err = f"{type(e).__name__}: {e}"
        items.append({"release_id": row["release_id"], "package": row["package"], "version": row["version"],
                      "classification": row["classification"], "confidence": row["confidence"],
                      "attack_type": row["attack_type"], "reasoning": row["reasoning"],
                      "cited_hunk": row["cited_hunk"], "diff_text": diff_text, "fetch_error": err,
                      "evidence_stored": stored is not None})
    conn.close()
    return items


def get_evidence(cfg: Config, release_id: int):
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        return store.get_evidence(conn, release_id)
    finally:
        conn.close()


def backfill_evidence(cfg: Config, release_id: int | None = None, all_flagged: bool = False):
    conn = store.connect(cfg); store.init_schema(conn)
    ruleset = _load_ruleset(cfg)
    results = []
    try:
        for row in store.releases_needing_evidence(conn, release_id, all_flagged):
            pkg, ver = row["package"], row["version"]
            try:
                art = fetcher.fetch_artifacts(cfg, NewRelease(pkg, ver, row["serial"]))
                if art is None:
                    results.append({"package": pkg, "version": ver, "captured": False, "error": "no tgz"})
                    continue
                if row["is_first_release"]:
                    art = dataclasses.replace(art, prior_files={}, prior_version=None, is_new_package=True)
                d = differ.build_diff(art)
                tr = engine.triage(d, cfg, ruleset)
                ev = reviewer.build_evidence(d, tr, max_chars=cfg.evidence_max_chars)
                if not ev:
                    results.append({"package": pkg, "version": ver, "captured": False,
                                    "error": "no code payload to render"})
                    continue
                store.update_evidence(conn, row["release_id"], ev)
                results.append({"package": pkg, "version": ver, "captured": True, "error": None})
            except Exception as e:
                results.append({"package": pkg, "version": ver, "captured": False,
                                "error": f"{type(e).__name__}: {e}"})
    finally:
        conn.close()
    return results


def adjudicate(cfg: Config, release_id: int, label: str, note: str = ""):
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        rel = store.adjudicate(conn, release_id, label, note)
        if rel is None:
            return None
        alerted = False
        if label != "benign":
            v = Verdict(rel["package"], rel["version"], label, rel["triage_score"] or 0.0,
                        _rules_from_json(rel["triage_rules"]), label == "malicious",
                        reasoning=note or None, model="human-adjudicator")
            alerted = notifier.emit(cfg, conn, v, release_id)
        return {"package": rel["package"], "version": rel["version"], "label": label, "alerted": alerted}
    finally:
        conn.close()
