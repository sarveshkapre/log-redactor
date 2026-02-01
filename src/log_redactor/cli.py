from __future__ import annotations

import argparse
import json
import gzip
import os
import sys
from contextlib import ExitStack
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TextIO, cast

from .redactor import (
    DEFAULT_RULES,
    RedactionRule,
    RedactionStats,
    load_rules_json,
    preset_names,
    preset_rules,
    redact_stream,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="log-redactor")
    parser.add_argument("--version", action="version", version=_version())

    sub = parser.add_subparsers(dest="cmd", required=True)
    p_rules = sub.add_parser("rules", help="List redaction rules as JSON")
    p_rules.add_argument(
        "--rules",
        action="append",
        default=[],
        help="Path to JSON rules file to include (repeatable).",
    )
    p_rules.add_argument(
        "--no-defaults",
        action="store_true",
        help="Do not include built-in redaction rules.",
    )
    p_rules.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    p_rules.add_argument(
        "--preset",
        default="default",
        help="Built-in preset to use (default: default).",
    )
    p_rules.add_argument(
        "--list-presets",
        action="store_true",
        help="List built-in presets and exit.",
    )
    p_rules.set_defaults(func=_rules)

    p_run = sub.add_parser("redact", help="Redact a log file")
    p_run.add_argument("--input", required=True, help="Input log file path or '-' for stdin")
    p_run.add_argument("--out", default="-", help="Output log path or '-' for stdout")
    p_run.add_argument(
        "--rules",
        action="append",
        default=[],
        help="Path to JSON rules file (repeatable).",
    )
    p_run.add_argument(
        "--no-defaults",
        action="store_true",
        help="Do not include built-in redaction rules.",
    )
    p_run.add_argument(
        "--preset",
        default="default",
        help="Built-in preset to use (default: default).",
    )
    p_run.add_argument(
        "--in-place",
        action="store_true",
        help="Overwrite the input file using an atomic replace (requires --input not '-').",
    )
    p_run.add_argument(
        "--backup-suffix",
        help="When used with --in-place, move original file to <input><suffix> first.",
    )
    p_run.add_argument(
        "--backup-overwrite",
        action="store_true",
        help="Allow overwriting an existing backup file (when used with --backup-suffix).",
    )
    p_run.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write redacted output (stats/report still emitted).",
    )
    p_run.add_argument("--quiet", action="store_true", help="Do not emit stats.")
    p_run.add_argument(
        "--stats-out",
        help="Write stats JSON to this path (still prints to stderr unless --quiet).",
    )
    p_run.add_argument(
        "--report-out",
        help="Write JSONL redaction report to this path (line + rule pattern + count).",
    )
    p_run.add_argument(
        "--fail-on-redaction",
        action="store_true",
        help="Exit non-zero if any redactions occurred.",
    )
    p_run.set_defaults(func=_run)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as e:
        print(f"log-redactor: error: {e}", file=sys.stderr)
        return 2


def _version() -> str:
    try:
        return version("log-redactor")
    except PackageNotFoundError:
        return "0.0.0"


def _run(args: argparse.Namespace) -> int:
    if args.no_defaults and args.preset != "default":
        raise ValueError("--no-defaults cannot be combined with --preset")

    rules: list[RedactionRule]
    if args.no_defaults:
        rules = []
    elif args.preset == "default":
        rules = list(DEFAULT_RULES)
    else:
        rules = preset_rules(args.preset)
    for path_str in args.rules:
        rules.extend(load_rules_json(Path(path_str)))

    if args.in_place:
        if args.input == "-":
            raise ValueError("--in-place does not support --input '-'")
        if args.out != "-":
            raise ValueError("--in-place cannot be used with --out (omit it or use '-')")
        if args.dry_run:
            raise ValueError("--dry-run cannot be combined with --in-place")
        stats = _redact_in_place(
            Path(args.input),
            rules=rules,
            report_out=args.report_out,
            backup_suffix=args.backup_suffix,
            backup_overwrite=bool(args.backup_overwrite),
        )
    else:
        stats = _redact_to_output(
            args.input,
            args.out,
            rules=rules,
            report_out=args.report_out,
            dry_run=bool(args.dry_run),
        )

    if args.stats_out:
        stats_path = Path(args.stats_out)
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        stats_path.write_text(stats.to_json() + "\n", encoding="utf-8")

    if not args.quiet:
        print(stats.to_json(), file=sys.stderr)

    if args.fail_on_redaction and stats.redactions:
        return 1

    return 0


def _rules(args: argparse.Namespace) -> int:
    if args.list_presets:
        print(json.dumps({"presets": preset_names()}, separators=(",", ":"), sort_keys=True))
        return 0

    if args.no_defaults and args.preset != "default":
        raise ValueError("--no-defaults cannot be combined with --preset")

    rules: list[RedactionRule]
    if args.no_defaults:
        rules = []
    elif args.preset == "default":
        rules = list(DEFAULT_RULES)
    else:
        rules = preset_rules(args.preset)
    for path_str in args.rules:
        rules.extend(load_rules_json(Path(path_str)))

    payload = {
        "rules": [
            {"pattern": r.pattern, "replacement": r.replacement, "rule_id": r.rule_id}
            for r in rules
        ]
    }
    if args.pretty:
        print(json.dumps(payload, indent=2, sort_keys=True), file=sys.stdout)
    else:
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True), file=sys.stdout)
    return 0


def _redact_to_output(
    input_arg: str,
    out_arg: str,
    *,
    rules: list[RedactionRule],
    report_out: str | None,
    dry_run: bool,
) -> RedactionStats:
    with ExitStack() as stack:
        if input_arg == "-":
            inp = sys.stdin
            input_path = None
        else:
            input_path = Path(input_arg).resolve()
            if input_path.suffix == ".gz":
                inp = stack.enter_context(
                    gzip.open(input_path, "rt", encoding="utf-8", errors="ignore")
                )
            else:
                inp = stack.enter_context(input_path.open("r", encoding="utf-8", errors="ignore"))

        out: TextIO
        out_path: Path | None

        if dry_run:
            if out_arg != "-":
                raise ValueError("--dry-run requires --out '-' (default)")
            out = stack.enter_context(open(os.devnull, "w", encoding="utf-8"))
            out_path = None
        else:
            if out_arg == "-":
                out = sys.stdout
                out_path = None
            else:
                out_path = Path(out_arg).resolve()
                if input_path is not None and out_path == input_path:
                    raise ValueError(
                        "Output path equals input path; use --in-place for safe overwrite"
                    )
                out_path.parent.mkdir(parents=True, exist_ok=True)
                if out_path.suffix == ".gz":
                    out = stack.enter_context(gzip.open(out_path, "wt", encoding="utf-8"))
                else:
                    out = stack.enter_context(out_path.open("w", encoding="utf-8"))

        report_stream = None
        if report_out:
            report_path = Path(report_out).resolve()
            if input_path is not None and report_path == input_path:
                raise ValueError("--report-out cannot be the same path as --input")
            if out_path is not None and report_path == out_path:
                raise ValueError("--report-out cannot be the same path as --out")
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_stream = stack.enter_context(report_path.open("w", encoding="utf-8"))

        return redact_stream(inp, out, rules=rules, report_out=report_stream)


def _redact_in_place(
    input_path: Path,
    *,
    rules: list[RedactionRule],
    report_out: str | None,
    backup_suffix: str | None,
    backup_overwrite: bool,
) -> RedactionStats:
    input_path = input_path.resolve()
    if not input_path.exists():
        raise FileNotFoundError(str(input_path))

    st = input_path.stat()
    report_path = Path(report_out).resolve() if report_out else None
    if report_path is not None and report_path == input_path:
        raise ValueError("--report-out cannot be the same path as --input when using --in-place")

    backup_path = None
    if backup_suffix is not None:
        if backup_suffix == "":
            raise ValueError("--backup-suffix cannot be empty")
        backup_path = input_path.with_name(input_path.name + backup_suffix)
        if report_path is not None and report_path == backup_path:
            raise ValueError("--report-out cannot be the same path as the backup file")
        if backup_path.exists() and not backup_overwrite:
            raise FileExistsError(str(backup_path))

    temp_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=str(input_path.parent),
            prefix=input_path.name + ".",
            suffix=".tmp",
        ) as tmp:
            temp_path = Path(tmp.name)
            os.chmod(temp_path, st.st_mode)
            tmp_text = cast(TextIO, tmp)

            if input_path.suffix == ".gz":
                inp_ctx = gzip.open(input_path, "rt", encoding="utf-8", errors="ignore")
            else:
                inp_ctx = input_path.open("r", encoding="utf-8", errors="ignore")

            with inp_ctx as inp:
                if report_path is None:
                    stats = redact_stream(inp, tmp_text, rules=rules)
                else:
                    report_path.parent.mkdir(parents=True, exist_ok=True)
                    with report_path.open("w", encoding="utf-8") as report:
                        stats = redact_stream(inp, tmp_text, rules=rules, report_out=report)

        if backup_path is not None:
            os.replace(str(input_path), str(backup_path))

        assert temp_path is not None
        os.replace(str(temp_path), str(input_path))
        return stats
    finally:
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
