"""Command-line interface: init, serve, deploy, decoys, alerts, test-alert."""
from __future__ import annotations

import argparse
import os
import secrets
import sys
from typing import List, Optional

from . import __version__
from .alerts import Notifier
from .config import DEFAULT_CONFIG_PATH, Config, load_config, save_config
from .db import Store
from .generator import KINDS, deploy
from .server import make_server


def cmd_init(args) -> int:
    path = args.config
    if os.path.exists(path) and not args.force:
        print("%s already exists (use --force to overwrite)" % path, file=sys.stderr)
        return 1
    cfg = Config(
        base_url=args.base_url,
        port=args.port,
        webhook_url=args.webhook or "",
        dashboard_key=secrets.token_urlsafe(24),
    )
    cfg.validate()
    save_config(cfg, path)
    print("Wrote %s (owner-readable only)." % path)
    print("Dashboard: %s/_dg/?key=%s" % (cfg.base_url, cfg.dashboard_key))
    print("Next: `decoyguard serve`, then `decoyguard deploy <folder>`.")
    return 0


def cmd_serve(args) -> int:
    cfg = load_config(args.config)
    store = Store(cfg.db_path)
    notifier = Notifier(cfg)
    server = make_server(cfg, store, notifier)
    print("DecoyGuard %s listening on %s:%d" % (__version__, cfg.host, server.server_address[1]))
    print("Dashboard: %s/_dg/?key=%s" % (cfg.base_url, cfg.dashboard_key))
    if not notifier.configured():
        print("Warning: no webhook/SMTP configured; alerts will only appear in the dashboard.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()
        store.close()
    return 0


def cmd_deploy(args) -> int:
    cfg = load_config(args.config)
    store = Store(cfg.db_path)
    kinds: Optional[List[str]] = args.kinds.split(",") if args.kinds else None
    try:
        created = deploy(store, cfg, args.directory, count=args.count, kinds=kinds)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    finally:
        store.close()
    if not created:
        print("Nothing created (all candidate filenames already exist there).")
        return 1
    for d in created:
        print("  %-14s %s" % (d["kind"], d["path"]))
    print("Deployed %d decoy(s). Make sure `decoyguard serve` is reachable at %s" % (len(created), cfg.base_url))
    return 0


def cmd_decoys(args) -> int:
    cfg = load_config(args.config)
    store = Store(cfg.db_path)
    rows = store.list_decoys()
    store.close()
    if not rows:
        print("No decoys deployed yet.")
    for d in rows:
        print("%-24s %-14s triggers=%-3d %s" % (d["label"], d["kind"], d["triggers"], d["path"]))
    return 0


def cmd_alerts(args) -> int:
    cfg = load_config(args.config)
    store = Store(cfg.db_path)
    rows = store.list_alerts(args.limit)
    store.close()
    if not rows:
        print("No alerts. All quiet.")
    for a in rows:
        print("%s  %-22s %-15s %s %s %s" % (
            a["ts"], a.get("label") or a["token"], a["source_ip"], a["method"], a["path"], a["detail"]))
    return 0


def cmd_test_alert(args) -> int:
    cfg = load_config(args.config)
    errors = Notifier(cfg, sync=True).send_test()
    if errors:
        print("Test alert failed:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1
    print("Test alert delivered.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="decoyguard", description="Deception tripwires for small businesses.")
    p.add_argument("--version", action="version", version="decoyguard " + __version__)
    p.add_argument("-c", "--config", default=None, help="config file (default: %s or $DG_CONFIG)" % DEFAULT_CONFIG_PATH)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create a config file with a random dashboard key")
    s.add_argument("--base-url", default="http://localhost:8080", help="public URL decoys will point to")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--webhook", help="Slack/Teams/Discord incoming webhook URL")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("serve", help="run the tripwire server and dashboard")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("deploy", help="plant decoy files in a folder")
    s.add_argument("directory")
    s.add_argument("--count", type=int, help="how many decoys (default: one of each kind)")
    s.add_argument("--kinds", help="comma-separated subset of: " + ", ".join(KINDS))
    s.set_defaults(func=cmd_deploy)

    s = sub.add_parser("decoys", help="list deployed decoys")
    s.set_defaults(func=cmd_decoys)

    s = sub.add_parser("alerts", help="show recent alerts")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(func=cmd_alerts)

    s = sub.add_parser("test-alert", help="send a test notification to your webhook/email")
    s.set_defaults(func=cmd_test_alert)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.config is None:
        args.config = os.environ.get("DG_CONFIG", DEFAULT_CONFIG_PATH)
    try:
        return args.func(args)
    except (ValueError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
