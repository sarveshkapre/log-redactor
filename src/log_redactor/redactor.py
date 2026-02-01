from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence, TextIO


SECRETS_PATTERNS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
    (r"ghp_[A-Za-z0-9]{36}", "[REDACTED_GITHUB_TOKEN]"),
    (r"github_pat_[A-Za-z0-9_]{22,255}", "[REDACTED_GITHUB_TOKEN]"),
    (r"xox[aboprs]-[0-9A-Za-z-]{10,200}", "[REDACTED_SLACK_TOKEN]"),
    (r"sk_(?:live|test)_[0-9A-Za-z]{16,}", "[REDACTED_STRIPE_KEY]"),
    (r"AIza[0-9A-Za-z_-]{35}", "[REDACTED_GOOGLE_API_KEY]"),
    (
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "[REDACTED_JWT]",
    ),
    (
        r"(https?://)([^\s:/?#]+):([^\s@]+)@",
        r"\1[REDACTED_USER]:[REDACTED_PASS]@",
    ),
    (r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
]

HEADERS_PATTERNS: list[tuple[str, str]] = [
    (
        r"(?i)^(cookie:\s*)[^\r\n]+",
        r"\1[REDACTED]",
    ),
    (
        r"(?i)^(set-cookie:\s*)[^\r\n]+",
        r"\1[REDACTED]",
    ),
    (r"(?i)authorization: basic [a-z0-9+/=]+", "authorization: basic [REDACTED]"),
    (r"(?i)authorization: bearer [a-z0-9\-_.=]+", "authorization: bearer [REDACTED]"),
    (r"(?i)x-api-key:\s*[^\s]+", "x-api-key: [REDACTED]"),
]

PARAM_PATTERNS: list[tuple[str, str]] = [
    (
        r"(?i)\b(access_token|refresh_token|id_token|session(?:id)?|session_id|csrf(?:_token)?|auth_token|session_token|token)=((?!\[REDACTED)[^\s&;]+)",
        r"\1=[REDACTED]",
    ),
    (r"(?i)api[_-]?key=([a-z0-9\-_.]+)", "api_key=[REDACTED]"),
    (r"(?i)password=([^\s&]+)", "password=[REDACTED]"),
]

PII_PATTERNS: list[tuple[str, str]] = [
    (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
]

DEFAULT_PATTERNS: list[tuple[str, str]] = [
    *SECRETS_PATTERNS,
    *HEADERS_PATTERNS,
    *PARAM_PATTERNS,
    *PII_PATTERNS,
]

PRESET_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "default": DEFAULT_PATTERNS,
    "secrets": [*SECRETS_PATTERNS, *HEADERS_PATTERNS, *PARAM_PATTERNS],
    "pii": PII_PATTERNS,
}


@dataclass(frozen=True)
class RedactionStats:
    lines: int
    redactions: int

    def to_dict(self) -> dict[str, Any]:
        return {"lines": self.lines, "redactions": self.redactions}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class RedactionRule:
    rule_id: str
    pattern: str
    regex: re.Pattern[str]
    replacement: str


def _rule_id(pattern: str, replacement: str) -> str:
    h = hashlib.sha256()
    h.update(pattern.encode("utf-8"))
    h.update(b"\0")
    h.update(replacement.encode("utf-8"))
    return h.hexdigest()[:12]


def _compile_rules(patterns: Iterable[tuple[str, str]]) -> list[RedactionRule]:
    rules: list[RedactionRule] = []
    for pattern, replacement in patterns:
        rules.append(
            RedactionRule(
                rule_id=_rule_id(pattern, replacement),
                pattern=pattern,
                regex=re.compile(pattern),
                replacement=replacement,
            )
        )
    return rules


DEFAULT_RULES: list[RedactionRule] = _compile_rules(DEFAULT_PATTERNS)


def preset_names() -> list[str]:
    return sorted(PRESET_PATTERNS.keys())


def preset_rules(name: str) -> list[RedactionRule]:
    try:
        patterns = PRESET_PATTERNS[name]
    except KeyError as e:
        raise ValueError(f"Unknown preset: {name}") from e
    return _compile_rules(patterns)


def load_rules_json(path: Path) -> list[RedactionRule]:
    """
    Load redaction rules from a JSON file.

    Supported formats:
      - [{"pattern": "...", "replacement": "..."}]
      - {"rules": [{"pattern": "...", "replacement": "..."}]}
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("rules")
    if not isinstance(raw, list):
        msg = "Rules JSON must be a list or an object with a 'rules' list"
        raise ValueError(msg)

    rules: list[RedactionRule] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"Rule #{idx} must be an object")
        pattern = item.get("pattern")
        replacement = item.get("replacement")
        if not isinstance(pattern, str) or not isinstance(replacement, str):
            raise ValueError(f"Rule #{idx} must have string 'pattern' and 'replacement'")
        try:
            rules.append(
                RedactionRule(
                    rule_id=_rule_id(pattern, replacement),
                    pattern=pattern,
                    regex=re.compile(pattern),
                    replacement=replacement,
                )
            )
        except re.error as e:
            raise ValueError(f"Invalid regex in rule #{idx}: {e}") from e
    return rules


def redact_line(line: str, rules: Sequence[RedactionRule] = DEFAULT_RULES) -> tuple[str, int]:
    redactions = 0
    out = line
    for rule in rules:
        new_out, count = rule.regex.subn(rule.replacement, out)
        if count:
            redactions += count
        out = new_out
    return out, redactions


def redact_stream(
    inp: TextIO,
    out: TextIO,
    *,
    rules: Sequence[RedactionRule] = DEFAULT_RULES,
    report_out: TextIO | None = None,
) -> RedactionStats:
    redactions = 0
    lines = 0
    for line in inp:
        lines += 1
        line_out = line
        for rule in rules:
            line_out, count = rule.regex.subn(rule.replacement, line_out)
            if count:
                redactions += count
                if report_out is not None:
                    report_out.write(
                        json.dumps(
                            {
                                "count": count,
                                "line": lines,
                                "pattern": rule.pattern,
                                "rule_id": rule.rule_id,
                            },
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    )
        redacted = line_out
        out.write(redacted)
    return RedactionStats(lines=lines, redactions=redactions)


def redact_file(
    input_path: Path,
    out_path: Path,
    *,
    rules: Sequence[RedactionRule] = DEFAULT_RULES,
    report_path: Path | None = None,
) -> RedactionStats:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report_out: TextIO | None = None
    with (
        input_path.open("r", encoding="utf-8", errors="ignore") as inp,
        out_path.open("w", encoding="utf-8") as out,
    ):
        if report_path is None:
            return redact_stream(inp, out, rules=rules)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("w", encoding="utf-8") as report:
            report_out = report
            return redact_stream(inp, out, rules=rules, report_out=report_out)
