from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_PATTERNS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
    (r"(?i)authorization: bearer [a-z0-9\-_.=]+", "authorization: bearer [REDACTED]"),
    (r"(?i)api[_-]?key=([a-z0-9\-_.]+)", "api_key=[REDACTED]"),
    (r"(?i)password=([^\s&]+)", "password=[REDACTED]"),
    (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
]


@dataclass(frozen=True)
class RedactionStats:
    lines: int
    redactions: int

    def to_dict(self) -> dict[str, Any]:
        return {"lines": self.lines, "redactions": self.redactions}


def redact_line(line: str) -> tuple[str, int]:
    redactions = 0
    out = line
    for pattern, repl in DEFAULT_PATTERNS:
        new_out, count = re.subn(pattern, repl, out)
        if count:
            redactions += count
        out = new_out
    return out, redactions


def redact_file(input_path: Path, out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    redactions = 0
    lines = 0
    with (
        input_path.open("r", encoding="utf-8", errors="ignore") as inp,
        out_path.open("w", encoding="utf-8") as out,
    ):
        for line in inp:
            lines += 1
            redacted, count = redact_line(line)
            redactions += count
            out.write(redacted)
    stats = RedactionStats(lines=lines, redactions=redactions)
    print(stats.to_dict())
    return 0
