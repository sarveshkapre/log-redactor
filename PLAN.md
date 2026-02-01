# PLAN.md

## Product pitch

Log Redactor is a tiny, safe-by-default CLI that redacts secrets/PII from log files and reports what it changed.

## Features

- Redact common secrets/PII using built-in regex rules.
- Redact files via CLI (`python -m log_redactor redact ...` / `log-redactor redact ...`).
- Emit redaction stats as JSON.

## Top risks / unknowns

- Regex redaction can miss edge-case secrets (false negatives) or over-redact (false positives).
- Large files: performance and memory usage need validation on multi-GB logs.
- Rule quality: safe defaults need continuous tuning and real-world feedback.

## Commands

See `PROJECT.md` for canonical commands.

- Setup: `make setup`
- Quality gate: `make check`
- Tests: `make test`
- Lint: `make lint`
- Typecheck: `make typecheck`

## Shipped (latest)

- v0.1.0: Regex-based redaction + CLI + stats output.
- Unreleased: JSON rules config, stream-friendly I/O, JSON stats/report, CI gating, atomic in-place overwrite.

## Next

- Add richer built-in rules (tokens, cookies, URLs with creds) with tests.
- Configurable rule packs (presets) and docs for safe defaults.

- Redaction rules for secrets/PII.
- CLI to redact files.
