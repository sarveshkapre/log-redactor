from __future__ import annotations

import gzip
import json
import subprocess
import sys
from pathlib import Path


def test_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "log_redactor", "--help"], check=False)
    assert proc.returncode == 0


def test_rules_command_outputs_json() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "log_redactor", "rules"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stderr == ""
    payload = json.loads(proc.stdout)
    assert isinstance(payload["rules"], list)
    assert "rule_id" in payload["rules"][0]


def test_rules_list_presets() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "log_redactor", "rules", "--list-presets"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stderr == ""
    payload = json.loads(proc.stdout)
    assert "default" in payload["presets"]
    assert "secrets" in payload["presets"]
    assert "pii" in payload["presets"]


def test_cli_redact_emits_json_stats(tmp_path: Path) -> None:
    inp = tmp_path / "in.log"
    out = tmp_path / "out.log"
    inp.write_text("email alice@example.com\\n", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_redactor",
            "redact",
            "--input",
            str(inp),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == ""
    stats = json.loads(proc.stderr.strip())
    assert stats["lines"] == 1
    assert stats["redactions"] >= 1


def test_cli_preset_secrets_does_not_redact_email(tmp_path: Path) -> None:
    inp = tmp_path / "in.log"
    out = tmp_path / "out.log"
    inp.write_text("email alice@example.com\n", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_redactor",
            "redact",
            "--input",
            str(inp),
            "--out",
            str(out),
            "--preset",
            "secrets",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert proc.stderr == ""
    assert out.read_text(encoding="utf-8").strip() == "email alice@example.com"


def test_cli_streaming_stdio(tmp_path: Path) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_redactor",
            "redact",
            "--input",
            "-",
            "--out",
            "-",
        ],
        input="password=secret\n",
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "password=[REDACTED]"
    stats = json.loads(proc.stderr.strip())
    assert stats["lines"] == 1
    assert stats["redactions"] >= 1


def test_cli_report_out(tmp_path: Path) -> None:
    inp = tmp_path / "in.log"
    out = tmp_path / "out.log"
    report = tmp_path / "report.jsonl"
    inp.write_text("password=secret\\n", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_redactor",
            "redact",
            "--input",
            str(inp),
            "--out",
            str(out),
            "--report-out",
            str(report),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert report.exists()
    lines = report.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["line"] == 1
    assert event["count"] == 1
    assert isinstance(event["rule_id"], str)
    assert event["rule_id"]


def test_cli_fail_on_redaction(tmp_path: Path) -> None:
    inp = tmp_path / "in.log"
    out = tmp_path / "out.log"
    inp.write_text("password=secret\\n", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_redactor",
            "redact",
            "--input",
            str(inp),
            "--out",
            str(out),
            "--fail-on-redaction",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert proc.stderr == ""


def test_cli_in_place_with_backup(tmp_path: Path) -> None:
    inp = tmp_path / "in.log"
    inp.write_text("password=secret\\n", encoding="utf-8")
    backup = tmp_path / "in.log.bak"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_redactor",
            "redact",
            "--input",
            str(inp),
            "--in-place",
            "--backup-suffix",
            ".bak",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert proc.stderr == ""
    assert inp.read_text(encoding="utf-8").strip() == "password=[REDACTED]"
    assert backup.read_text(encoding="utf-8") == "password=secret\\n"


def test_cli_gzip_roundtrip(tmp_path: Path) -> None:
    inp = tmp_path / "in.log.gz"
    out = tmp_path / "out.log.gz"
    with gzip.open(inp, "wt", encoding="utf-8") as f:
        f.write("password=secret\n")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_redactor",
            "redact",
            "--input",
            str(inp),
            "--out",
            str(out),
            "--quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert proc.stderr == ""
    with gzip.open(out, "rt", encoding="utf-8") as f:
        assert f.read().strip() == "password=[REDACTED]"


def test_cli_dry_run_does_not_write_stdout(tmp_path: Path) -> None:
    inp = tmp_path / "in.log"
    inp.write_text("password=secret\n", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_redactor",
            "redact",
            "--input",
            str(inp),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == ""
    stats = json.loads(proc.stderr.strip())
    assert stats["redactions"] >= 1


def test_cli_out_suffix(tmp_path: Path) -> None:
    inp = tmp_path / "app.log"
    inp.write_text("password=secret\n", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_redactor",
            "redact",
            "--input",
            str(inp),
            "--out-suffix",
            ".redacted",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert proc.stderr == ""
    out = Path(str(inp) + ".redacted")
    assert out.read_text(encoding="utf-8").strip() == "password=[REDACTED]"


def test_cli_encoding_errors_replace(tmp_path: Path) -> None:
    inp = tmp_path / "bad.log"
    out = tmp_path / "out.log"
    inp.write_bytes(b"bad:\xff\npassword=secret\n")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_redactor",
            "redact",
            "--input",
            str(inp),
            "--out",
            str(out),
            "--encoding",
            "utf-8",
            "--errors",
            "replace",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert proc.stderr == ""
    text = out.read_text(encoding="utf-8")
    assert "bad:\ufffd" in text
    assert "password=[REDACTED]" in text
