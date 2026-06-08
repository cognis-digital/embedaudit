"""Command-line interface for EMBEDAUDIT."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import TOOL_NAME, TOOL_VERSION
from .core import AuditError, AuditResult, audit_store, drift_report, load_jsonl


def _print_table(result: AuditResult, title: str) -> None:
    print(f"== {title} ==")
    print(f"records   : {result.record_count}")
    print(f"dimension : {result.dimension}")
    print(f"status    : {'OK' if result.ok else 'FAIL'}")
    if result.stats:
        print("stats     :")
        for k, v in result.stats.items():
            if isinstance(v, float):
                print(f"  {k:<22} {v:.4f}")
            else:
                print(f"  {k:<22} {v}")
    if not result.findings:
        print("findings  : none")
        return
    print("findings  :")
    order = {"critical": 0, "warning": 1, "info": 2}
    for f in sorted(result.findings, key=lambda x: order.get(x.severity, 9)):
        print(f"  [{f.severity.upper():<8}] {f.code}: {f.message}")


def _emit(result: AuditResult, fmt: str, title: str) -> None:
    if fmt == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_table(result, title)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Embedding / vector-store drift and poisoning audit.",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    parser.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="output format (default: table)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser(
        "audit", help="audit a single store snapshot (JSONL of vectors)")
    p_audit.add_argument("snapshot", help="path to JSONL embedding snapshot")
    p_audit.add_argument("--dup-threshold", type=float, default=0.999)
    p_audit.add_argument("--domination-share", type=float, default=0.30)

    p_drift = sub.add_parser(
        "drift", help="compare a baseline snapshot against a current snapshot")
    p_drift.add_argument("baseline", help="trusted baseline JSONL snapshot")
    p_drift.add_argument("current", help="current JSONL snapshot to compare")
    p_drift.add_argument("--drift-threshold", type=float, default=0.15)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fmt: str = args.format

    try:
        if args.command == "audit":
            records = load_jsonl(args.snapshot)
            result = audit_store(
                records,
                dup_threshold=args.dup_threshold,
                domination_share=args.domination_share,
            )
            _emit(result, fmt, f"AUDIT {args.snapshot}")
        elif args.command == "drift":
            baseline = load_jsonl(args.baseline)
            current = load_jsonl(args.current)
            result = drift_report(
                baseline, current, drift_threshold=args.drift_threshold)
            _emit(result, fmt, "DRIFT baseline -> current")
        else:  # pragma: no cover - argparse guards this
            parser.error(f"unknown command {args.command!r}")
            return 2
    except (AuditError, FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
