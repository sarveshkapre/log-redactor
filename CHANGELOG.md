# CHANGELOG

## Unreleased

## v0.1.7 - 2026-02-01

- Add `--dry-run` to compute stats/report without writing redacted output.

## v0.1.6 - 2026-02-01

- Support gzip input/output when paths end with `.gz`.

## v0.1.5 - 2026-02-01

- Add built-in rule presets (`--preset`) and preset listing (`rules --list-presets`).

## v0.1.4 - 2026-02-01

- Add stable `rule_id` to `rules` output and JSONL reports.

## v0.1.3 - 2026-02-01

- Add `rules` subcommand to export the effective ruleset as JSON.
- Add cookie / set-cookie / token query redaction patterns.

## v0.1.2 - 2026-02-01

- Expand built-in redaction rules (GitHub/Slack/Stripe/Google tokens, JWTs, URL basic-auth, private key header).

## v0.1.1 - 2026-02-01

- Add configurable JSON rule files via `--rules` and `--no-defaults`.
- Add stream-friendly `--input -` / `--out -` (stats always written to stderr).
- Add JSONL redaction report via `--report-out`.
- Add `--fail-on-redaction` for CI/policy gating.
- Add atomic in-place overwrite via `--in-place` with optional `--backup-suffix`.
- Fix stats output to be valid JSON; add `--stats-out` and `--quiet`.

## v0.1.0 - 2026-01-31

- Regex-based redaction with safe defaults.
- Stats output.
