from __future__ import annotations

from pathlib import Path

from log_redactor.redactor import redact_line, redact_file


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
