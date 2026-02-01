# Log Redactor

Redact secrets/PII from logs with safe defaults.

## Scope (v0.1.12)

- Regex-based redaction for common secrets and PII.
- Optional configurable rule files.
- JSON stats output (stderr) and optional JSONL redaction report.

Built-in rules currently cover common patterns like AWS keys, bearer auth headers, email, SSNs, plus additional
tokens/keys (e.g. GitHub tokens, Slack tokens, Stripe keys, Google API keys, JWTs), and URL basic-auth.

## Quickstart

```bash
make setup
make check
```

## Usage

```bash
python -m log_redactor redact --input app.log --out app.redacted.log
```

Stats are emitted as JSON on stderr (so stdout can be used for redacted output when `--out -`).
If `--out` is omitted, output defaults to stdout.

Write to a sibling file without specifying a full output path:

```bash
python -m log_redactor redact --input app.log --out-suffix .redacted.log
```

### List rules

Dump the effective rule set as JSON (useful for auditing and building a custom rule file):

```bash
python -m log_redactor rules --pretty
```

List available built-in presets:

```bash
python -m log_redactor rules --list-presets
```

### Stream mode

```bash
python -m log_redactor redact --input - --out - < app.log > app.redacted.log
```

### Gzip support

If the input or output path ends with `.gz`, it is read/written as gzip automatically:

```bash
python -m log_redactor redact --input app.log.gz --out app.redacted.log.gz
```

### Dry run

Compute stats (and optionally a report) without writing any redacted output:

```bash
python -m log_redactor redact --input app.log --dry-run
```

### Encoding

Override how files are decoded (defaults: `--encoding utf-8` and `--errors ignore`):

```bash
python -m log_redactor redact --input app.log --out app.redacted.log --errors replace
```

### In-place redaction (atomic)

Overwrite the input file safely (writes a temp file and atomically replaces the original):

```bash
python -m log_redactor redact --input app.log --in-place --backup-suffix .bak --quiet
```

### Atomic output file writes

When writing to a file, you can avoid partially-written outputs by writing to a temp file and atomically
replacing the destination:

```bash
python -m log_redactor redact --input app.log --out app.redacted.log --atomic
```

### Custom rules

Provide one or more JSON rule files:

```bash
python -m log_redactor redact --input app.log --out app.redacted.log --rules rules.json
```

Rules file format:

```json
[
  {"pattern": "secret", "replacement": "[REDACTED]"}
]
```

### Redaction report (JSONL)

Write a per-line, per-rule report:

```bash
python -m log_redactor redact --input app.log --out app.redacted.log --report-out report.jsonl
```

Write the report to stderr (requires `--quiet` to avoid mixing with stats):

```bash
python -m log_redactor redact --input app.log --out - --report-out - --quiet
```

### CI / policy gate

Exit non-zero if anything was redacted:

```bash
python -m log_redactor redact --input app.log --out app.redacted.log --fail-on-redaction --quiet
```

Exit non-zero if redactions exceed a threshold:

```bash
python -m log_redactor redact --input app.log --dry-run --max-redactions 0 --quiet
```

### Presets

Use a built-in preset as the baseline ruleset (then optionally add `--rules` files):

```bash
python -m log_redactor redact --input app.log --out app.redacted.log --preset secrets
```
