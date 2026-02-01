# RELEASE

This repo uses SemVer. `v0.x` may include breaking changes.

## v0.1.1 - 2026-02-01

- Configurable JSON rule files (`--rules`, `--no-defaults`).
- Stream-friendly I/O (`--input -`, `--out -`), stats JSON on stderr.
- JSONL redaction report output (`--report-out`).
- CI/policy gating (`--fail-on-redaction`).
- Atomic in-place overwrite with optional backup (`--in-place`, `--backup-suffix`).

## v0.1.0 - 2026-01-31

- Regex-based redaction with safe defaults.
- Stats output.
