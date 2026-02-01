from __future__ import annotations

import json
from pathlib import Path

from log_redactor.redactor import load_rules_json, redact_file, redact_line


def test_redact_line() -> None:
    line = "email alice@example.com token AKIA1234567890ABCDE"
    out, count = redact_line(line)
    assert "REDACTED_EMAIL" in out
    assert count >= 1


def test_redact_file(tmp_path: Path) -> None:
    inp = tmp_path / "in.log"
    out = tmp_path / "out.log"
    inp.write_text("password=secret\\n", encoding="utf-8")
    redact_file(inp, out)
    assert out.read_text(encoding="utf-8").strip() == "password=[REDACTED]"


def test_rules_json(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        json.dumps([{"pattern": "secret", "replacement": "[X]"}]),
        encoding="utf-8",
    )
    rules = load_rules_json(rules_path)
    out, count = redact_line("a secret b", rules=rules)
    assert out == "a [X] b"
    assert count == 1


def test_additional_builtin_rules_smoke() -> None:
    out, count = redact_line("tok=ghp_" + ("a" * 36) + " url=https://user:pass@example.com/x\n")
    assert "[REDACTED_GITHUB_TOKEN]" in out
    assert "https://[REDACTED_USER]:[REDACTED_PASS]@example.com" in out
    assert count >= 2


def test_cookie_header_redaction() -> None:
    out, count = redact_line("Cookie: a=1; sessionid=abc; theme=dark\n")
    assert out == "Cookie: [REDACTED]\n"
    assert count == 1


def test_set_cookie_redaction_preserves_attributes() -> None:
    out, count = redact_line("Set-Cookie: sessionid=abc123; Path=/; HttpOnly\n")
    assert out == "Set-Cookie: [REDACTED]\n"
    assert count == 1


def test_query_token_redaction() -> None:
    out, count = redact_line("GET /cb?access_token=abc&x=1\n")
    assert "access_token=[REDACTED]" in out
    assert count == 1
