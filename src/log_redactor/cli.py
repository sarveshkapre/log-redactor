from __future__ import annotations

import argparse
from pathlib import Path

from .redactor import redact_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="log-redactor")
    parser.add_argument("--version", action="version", version="0.1.0")

    sub = parser.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("redact", help="Redact a log file")
    p_run.add_argument("--input", required=True, help="Input log file")
    p_run.add_argument("--out", required=True, help="Output redacted log")
    p_run.set_defaults(func=_run)

    args = parser.parse_args(argv)
    return int(args.func(args))


def _run(args: argparse.Namespace) -> int:
    return redact_file(Path(args.input), Path(args.out))


if __name__ == "__main__":
    raise SystemExit(main())
