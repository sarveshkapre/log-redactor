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

- v0.1.6: Add gzip input/output support (`.gz`).
- v0.1.5: Add built-in rule presets (`--preset`) and preset listing (`rules --list-presets`).
- v0.1.4: Add stable `rule_id` for rules/report.
- v0.1.3: Add cookie/token redaction patterns; add `rules` subcommand.
- v0.1.2: Expand built-in token/key patterns (GitHub/Slack/Stripe/Google/JWT, URL basic-auth, private key header).
- v0.1.1: JSON rules config, stream-friendly I/O, JSON stats/report, CI gating, atomic in-place overwrite.
- v0.1.0: Regex-based redaction + CLI + stats output.

## Next

- Configurable rule packs (presets) and docs for safe defaults.
- Structured report improvements (include matched text hash + rule id).
