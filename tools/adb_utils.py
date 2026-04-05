"""
adb_utils.py — Low-level ADB wrappers used throughout the server.
"""

import subprocess
from typing import Optional


def run_adb(args: list[str], timeout: int = 30, device: Optional[str] = None) -> tuple[str, str, int]:
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", "adb not found. Install Android SDK platform-tools.", 1


def run_adb_shell(command: str, device: Optional[str] = None, timeout: int = 30) -> tuple[str, str, int]:
    return run_adb(["shell", command], timeout=timeout, device=device)


def fmt_error(msg: str) -> str:
    return f"❌ Error: {msg}"
