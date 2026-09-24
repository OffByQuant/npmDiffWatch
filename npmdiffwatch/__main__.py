import argparse
import dataclasses
import sys
from . import egress, store
from .config import Config, load_config
from .orchestrator import (run_once, seed_now, list_pending, adjudicate, get_evidence,
                           backfill_evidence, export_dashboard, watch, review_pending,
                           pending_review_counts, prune, guard_status, feed_retry_counts)
from .guard import describe


def _cfg(args):
    cfg = load_config(args.config) if args.config else Config()
    if args.model or args.endpoint:       # an OpenAI-compatible server (llama.cpp, llama-swap, Ollama, vLLM)
        rc = dataclasses.replace(cfg.reviewer, provider="openai", model=args.model or cfg.reviewer.model,
                                 base_url=args.endpoint or cfg.reviewer.base_url)
        cfg = dataclasses.replace(cfg, reviewer=rc, reviewer_enabled=True)
    if getattr(args, "watchlist", None):
        cfg = dataclasses.replace(cfg, watchlist=args.watchlist)
    return cfg


def _watchlist_or_exit(cfg):
    if not cfg.watchlist:
        return None
    from .orchestrator import WatchlistFile
    from .watchlist import WatchlistError
    try:
        wf = WatchlistFile(cfg.watchlist)
    except WatchlistError as e:
        print(f"[npmdiffwatch] {e}"); sys.exit(2)
    print(f"[npmdiffwatch] watchlist: {wf.current().describe()}"
          + (f" ({wf.current().skipped} invalid entries skipped)" if wf.current().skipped else ""))
    return wf


def _reach(host):
    """Human note about who can reach a given bind address."""
    if host in ("127.0.0.1", "localhost"):
        return "localhost only"
    return "exposed to the local network — anyone who can reach this host"


def _file_server(directory, port, host="127.0.0.1"):
    """A read-only static file server (no control endpoints). Binds 127.0.0.1 by
    default; pass host="0.0.0.0" to expose it to the local network."""
    import functools
    from http.server import SimpleHTTPRequestHandler, HTTPServer
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(directory))
    return HTTPServer((host, port), handler)


def main():
    p = argparse.ArgumentParser(prog="npmdiffwatch")
    p.add_argument("-c", "--config", default=None,
                   help="path to a npmdiffwatch.toml config file (see examples/); defaults to built-ins")
    p.add_argument("--model", default=None,
                   help="reviewer model name on an OpenAI-compatible server (llama.cpp, llama-swap, Ollama, "
                        "vLLM); no API key needed. Overrides the config file")
    p.add_argument("--endpoint", default=None,
                   help="that server's URL (default: http://localhost:8000/v1), e.g. "
                        "http://192.168.1.20:8000/v1 for a model on another machine")
    sub = p.add_subparsers(dest="cmd", required=True)
    runp = sub.add_parser("run", help="process new releases since the cursor (one tick)")
    runp.add_argument("--backfill", action="store_true",
                      help="process from the cursor as-is (npm genesis on a fresh DB) instead of "
                           "seeding a fresh cursor to now")
    runp.add_argument("--watchlist", default=None, metavar="PATH",
                      help="scan only these packages: a names file (name or @scope/* per line), "
                           "package-lock.json, or a CycloneDX / SPDX JSON SBOM")
    runp.add_argument("--recent", type=int, default=None, metavar="N",
                      help="on a fresh database, start N npm changes back instead of now")
    sub.add_parser("seed-now",
                   help="set the cursor to now and exit (start monitoring from now)")
    sub.add_parser("pending",
                   help="list suspicious verdicts awaiting adjudication, each with its diff")
    sub.add_parser("prune", help="shrink the database now (run/watch also do it daily): compress evidence, drop "
                                 "it for benign releases, apply retention_days, compact; findings and queues stay")
    rpp = sub.add_parser("review-pending",
                         help="review releases queued for LLM review (by default: too_large and exhausted "
                              "retries) — e.g. with -c pointing at a larger-context model")
    rpp.add_argument("--reason", action="append",
                     choices=["too_large", "review_failed", "endpoint_unreachable"],
                     help="only this queue reason (repeatable)")
    rpp.add_argument("--limit", type=int, default=None, help="review at most N releases")
    adjp = sub.add_parser("adjudicate", help="record your verdict on a queued suspicious release")
    adjp.add_argument("release_id", type=int)
    adjp.add_argument("label", choices=["benign", "malicious", "suspicious"])
    adjp.add_argument("--note", default="")
    evp = sub.add_parser("evidence", help="print the stored flagged payload code for a release")
    evp.add_argument("release_id", type=int)
    capp = sub.add_parser("capture-evidence",
                          help="backfill stored payload code for flagged releases captured before "
                               "evidence existed (re-fetches from npm while still available)")
    capp.add_argument("--release-id", type=int, default=None,
                      help="capture just this release id (default: all reportable rows missing evidence)")
    capp.add_argument("--all", action="store_true",
                      help="widen from the reportable set (malicious/suspicious verdicts + non-benign "
                           "alerts) to EVERY release with a fired rule (far more re-fetches)")
    dshp = sub.add_parser("dashboard",
                          help="render persisted verdicts to a self-contained HTML page with npm "
                               "links and one-click 'Report malware' actions for flagged packages")
    dshp.add_argument("--out", default=None,
                      help="output HTML path (default: <db dir>/dashboard.html)")
    dshp.add_argument("--serve", action="store_true",
                      help="serve the dashboard on 127.0.0.1 (localhost only) until Ctrl-C")
    dshp.add_argument("--port", type=int, default=8787, help="port for --serve (default: 8787)")
    dshp.add_argument("--host", default="127.0.0.1",
                      help="bind address for --serve (default: 127.0.0.1, localhost only; "
                           "use 0.0.0.0 to expose it to the local network)")
    wp = sub.add_parser("watch",
                        help="daemon loop: scan for new releases on an interval, refresh the "
                             "dashboard each tick, and (with --serve) serve it on localhost")
    wp.add_argument("--interval", type=int, default=300,
                    help="seconds between scans (default: 300)")
    wp.add_argument("--out", default=None, help="dashboard HTML path (default: <db dir>/dashboard.html)")
    wp.add_argument("--watchlist", default=None, metavar="PATH",
                    help="scan only these packages: a names file (name or @scope/* per line), "
                         "package-lock.json, or a CycloneDX / SPDX JSON SBOM")
    wp.add_argument("--recent", type=int, default=None, metavar="N",
                    help="on a fresh database, start N npm changes back instead of now, so the dashboard "
                         "fills within minutes (ignored once scanning has started)")
    wp.add_argument("--serve", action="store_true",
                    help="also serve the dashboard on 127.0.0.1 (localhost only) while watching")
    wp.add_argument("--port", type=int, default=8787, help="port for --serve (default: 8787)")
    wp.add_argument("--host", default="127.0.0.1",
                    help="bind address for --serve (default: 127.0.0.1, localhost only; "
                         "use 0.0.0.0 to expose it to the local network)")
    args = p.parse_args()
    cfg = _cfg(args)
    egress.install_guard(cfg)
    if args.cmd == "run":
        wf = _watchlist_or_exit(cfg)
        n = run_once(cfg, seed_if_fresh=not args.backfill, recent=args.recent, watch=wf.current() if wf else None)
        print(f"[npmdiffwatch] processed {n} releases")
    elif args.cmd == "seed-now":
        s = seed_now(cfg)
        print(f"[npmdiffwatch] cursor seeded to serial {s}" if s is not None
              else "[npmdiffwatch] could not reach npm registry to read the current serial")
    elif args.cmd == "prune":
        print(f"[npmdiffwatch] pruned {cfg.db_path}: freed {prune(cfg) / 1048576:.1f} MB")
    elif args.cmd == "review-pending":
        n, remaining = review_pending(cfg, reasons=args.reason, limit=args.limit)
        left = ", ".join(f"{k}: {v}" for k, v in sorted(remaining.items())) or "none"
        print(f"[npmdiffwatch] reviewed {n} queued release(s); still queued: {left}")
    elif args.cmd == "pending":
        gs = guard_status(cfg)
        if gs:
            print(f"[npmdiffwatch] reviewer: {describe(gs)}")
        if cfg.watchlist:
            from .orchestrator import WatchlistFile, baseline_status
            s = baseline_status(cfg, WatchlistFile(cfg.watchlist).current())
            print(f"[npmdiffwatch] watchlist: {s['describe']} · baseline {s['done']:,}/{s['total']:,}")
        fr = feed_retry_counts(cfg)
        if fr["retrying"] or fr["gave_up"]:
            print(f"[npmdiffwatch] package metadata failed to download: {fr['retrying']} release(s) being retried, "
                  f"{fr['gave_up']} given up on after {1 + store.FEED_RETRIES} attempts (not scanned)")
        queued = pending_review_counts(cfg)
        if queued:
            print(f"[npmdiffwatch] {sum(queued.values())} release(s) queued for LLM review ("
                  + ", ".join(f"{k}: {v}" for k, v in sorted(queued.items()))
                  + ") — see `review-pending`")
        items = list_pending(cfg)
        if not items:
            print("[npmdiffwatch] no suspicious verdicts awaiting adjudication"); return
        print(f"[npmdiffwatch] {len(items)} suspicious verdict(s) awaiting adjudication:\n")
        for it in items:
            print(f"=== release_id={it['release_id']}  {it['package']}=={it['version']}  "
                  f"(model: {it['classification']} conf={it['confidence']} attack={it['attack_type']}) ===")
            print(f"  model reason: {it['reasoning']}")
            print(f"  cited_hunk: {it['cited_hunk']}")
            if it["diff_text"] is not None:
                label = "stored payload evidence" if it["evidence_stored"] else "diff under review (re-fetched)"
                print(f"  --- {label} ---")
                print(it["diff_text"])
            else:
                print(f"  (diff unavailable: {it['fetch_error']})")
            print()
    elif args.cmd == "evidence":
        ev = get_evidence(cfg, args.release_id)
        if ev is None:
            print(f"[npmdiffwatch] no stored evidence for release_id {args.release_id}")
        else:
            print(ev)
    elif args.cmd == "capture-evidence":
        res = backfill_evidence(cfg, release_id=args.release_id, all_flagged=args.all)
        if not res:
            print("[npmdiffwatch] no flagged releases missing evidence"); return
        ok = sum(1 for r in res if r["captured"])
        print(f"[npmdiffwatch] captured {ok}/{len(res)} flagged release(s):")
        for r in res:
            status = "captured" if r["captured"] else f"FAILED ({r['error']})"
            print(f"  {r['package']}=={r['version']}: {status}")
    elif args.cmd == "dashboard":
        out = export_dashboard(cfg, out_path=args.out)
        print(f"[npmdiffwatch] dashboard written to {out}")
        if args.serve:
            httpd = _file_server(out.parent, args.port, args.host)
            print(f"[npmdiffwatch] serving on http://{args.host}:{args.port}/{out.name} "
                  f"({_reach(args.host)}) — Ctrl-C to stop")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\n[npmdiffwatch] stopped")
            finally:
                httpd.server_close()
    elif args.cmd == "watch":
        wf = _watchlist_or_exit(cfg)        # stop before serving anything if the list is unusable
        out = export_dashboard(cfg, out_path=args.out)  # initial snapshot for the server
        httpd = None
        if args.serve:
            import threading
            httpd = _file_server(out.parent, args.port, args.host)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            print(f"[npmdiffwatch] serving http://{args.host}:{args.port}/{out.name} ({_reach(args.host)})")
        print(f"[npmdiffwatch] watching — scanning every {args.interval}s, Ctrl-C to stop")
        n = watch(cfg, interval=args.interval, out_path=args.out, recent=args.recent, watchlist=wf)
        if httpd:
            httpd.server_close()
        print(f"\n[npmdiffwatch] stopped after {n} scan(s)")
    elif args.cmd == "adjudicate":
        res = adjudicate(cfg, args.release_id, args.label, args.note)
        if res is None:
            print(f"[npmdiffwatch] release_id {args.release_id} not found")
        else:
            print(f"[npmdiffwatch] {res['package']}=={res['version']} adjudicated {res['label']}"
                  + ("  (alert emitted)" if res["alerted"] else "  (no alert)"))


if __name__ == "__main__":
    main()
