# Log Redactor

Redact secrets/PII from logs with safe defaults.

## Scope (v0.1.0)

- Regex-based redaction for common secrets and PII.
- Output stats (lines + redactions).

## Quickstart

```bash
make setup
make check
```

## Usage

```bash
python -m log_redactor redact --input app.log --out app.redacted.log
```
