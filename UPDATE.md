# Update (2026-02-01)

## Shipped

- CLI now outputs redacted logs to stdout by default (`--out` defaults to `-`), and prints stats JSON to stderr.
- Configurable rule files via `--rules path.json` and `--no-defaults`.
- Optional JSONL redaction report via `--report-out report.jsonl` (line number + rule pattern + count).
- CI/policy gating via `--fail-on-redaction` (exit code `1` when any redactions occur).
- Atomic in-place overwrite via `--in-place` with optional backup via `--backup-suffix .bak`.
- Expanded built-in token/key patterns (GitHub/Slack/Stripe/Google tokens, JWTs, URL basic-auth, private key header).
- Added cookie/set-cookie and token query redaction patterns; added `rules` subcommand to export the effective ruleset.
- Added stable `rule_id` values to rule export and JSONL reports.
- Added built-in presets (`--preset`) and preset listing (`rules --list-presets`).
- Added transparent gzip support when paths end with `.gz`.
- Added `--dry-run` to compute stats/report without writing redacted output.
- Added `--out-suffix` for easy sibling-file output.
- Repo hygiene: ignore local caches (`.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`).

## Verify

```bash
make check
```

## Examples

```bash
# stdout redaction (stats on stderr)
python -m log_redactor redact --input app.log > app.redacted.log

# in-place with backup (no stats)
python -m log_redactor redact --input app.log --in-place --backup-suffix .bak --quiet

# custom rules + report
python -m log_redactor redact --input app.log --out app.redacted.log --rules rules.json --report-out report.jsonl
```
