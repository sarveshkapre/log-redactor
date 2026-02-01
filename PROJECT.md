# PROJECT.md

Exact commands for working in this repo.

## Setup

```bash
make setup
```

## Quality gate

```bash
make check
```

## Run

```bash
python -m log_redactor --help
```

## Example

```bash
python -m log_redactor redact --input app.log --out app.redacted.log
```
