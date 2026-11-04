"""Command line: ``python -m msscan scan|rules|serve``.

The same commands exist in the standalone ``msscan`` binary; this entry point exists so that a
``pip install`` is enough to use the scanner.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from msscan import __version__, msscan_rs
from msscan.api import SEVERITIES, render, scan_path


def _severity(value: str) -> str:
    if value not in (*SEVERITIES, "none"):
        raise argparse.ArgumentTypeError(f"unknown severity {value!r}")
    return value


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="msscan", description="Scan ML model files before loading.")
    p.add_argument("--version", action="version", version=f"msscan {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan files or directories")
    s.add_argument("paths", nargs="+", type=Path)
    s.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("-o", "--output", type=Path, help="write the report to a file")
    s.add_argument("--fail-on", type=_severity, default="high")
    s.add_argument("--min-severity", type=_severity, default="low")
    s.add_argument("--hash", action="store_true", help="include SHA-256 digests")

    r = sub.add_parser("rules", help="list the rules")
    r.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text")

    v = sub.add_parser("serve", help="run the HTTP service")
    v.add_argument("--addr", default="127.0.0.1:8080")
    v.add_argument("--max-body", type=int, default=512 << 20)
    v.add_argument("--threads", type=int, default=4)
    return p


def _scan(args: argparse.Namespace) -> int:
    min_sev = "info" if args.min_severity == "none" else args.min_severity
    reports = [r for p in args.paths for r in scan_path(p, hash=args.hash)]
    text = render(reports, args.format, min_severity=min_sev)
    if args.output:
        args.output.write_text(text)
    else:
        sys.stdout.write(text)
    if any(r.error for r in reports):
        return 2
    if args.fail_on != "none" and any(r.flagged(args.fail_on) for r in reports):
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "scan":
        return _scan(args)
    if args.cmd == "rules":
        if args.format == "markdown":
            sys.stdout.write(msscan_rs.rules_markdown())
        elif args.format == "json":
            sys.stdout.write(json.dumps(json.loads(msscan_rs.rules()), indent=2) + "\n")
        else:
            for rule in json.loads(msscan_rs.rules()):
                sev, name = rule["severity"], rule["name"]
                sys.stdout.write(f"{rule['id']:<7} {sev:<9} {name:<32} {rule['summary']}\n")
        return 0
    print(f"msscan {__version__} listening on http://{args.addr}", file=sys.stderr)
    msscan_rs.serve(args.addr, args.max_body, args.threads)
    return 0  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
