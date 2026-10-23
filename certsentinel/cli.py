"""Command-line interface for inspecting public HTTPS TLS certificates."""

import argparse
import json

from .core import check_target, parse_target


def _nonnegative(value: str) -> int:
    try:
        number = int(value)
        if number >= 0:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("expected a nonnegative integer")


def _positive(value: str) -> float:
    try:
        number = float(value)
        if 0 < number < float("inf"):
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("expected a positive finite number")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check verified HTTPS certificate expirations")
    parser.add_argument("targets", nargs="+", help="HTTPS URL or hostname[:port]")
    parser.add_argument("--warn-days", type=_nonnegative, default=30, metavar="N")
    parser.add_argument("--timeout", type=_positive, default=5.0, metavar="SECONDS")
    parser.add_argument("--json", action="store_true", help="print a JSON array for automation")
    args = parser.parse_args(argv)
    for target in args.targets:
        try:
            parse_target(target)
        except ValueError as exc:
            parser.error(str(exc))
    results = [check_target(t, warn_days=args.warn_days, timeout=args.timeout) for t in args.targets]
    if args.json:
        print(json.dumps(results, ensure_ascii=False))
    else:
        for result in results:
            summary = result.get("error") or result["expires_at"]
            print(f"{result['status'].upper():7} {result['target']}: {summary}")
    return 2 if any(r["status"] == "error" for r in results) else (1 if any(r["status"] == "warning" for r in results) else 0)
