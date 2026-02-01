from __future__ import annotations

import subprocess
import sys


def test_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "log_redactor", "--help"], check=False)
    assert proc.returncode == 0
