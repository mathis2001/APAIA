"""
jadx_utils.py — JADX binary helpers and APK/output-path utilities.
"""

import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .config import WORK_DIR, JADX_BIN


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def jadx_available() -> bool:
    return bool(shutil.which(JADX_BIN)) or Path(JADX_BIN).exists()


def apk_work_dir(package: str) -> Path:
    return WORK_DIR / package


def apk_path(package: str) -> Optional[Path]:
    p = apk_work_dir(package) / f"{package}.apk"
    return p if p.exists() else None


def jadx_out_dir(package: str) -> Path:
    return apk_work_dir(package) / "jadx_out"


def manifest_path(package: str) -> Optional[Path]:
    p = jadx_out_dir(package) / "resources" / "AndroidManifest.xml"
    return p if p.exists() else None


# ---------------------------------------------------------------------------
# JADX runner
# ---------------------------------------------------------------------------

def run_jadx(package: str, apk: Path, decompile_java: bool = True, timeout: int = 600) -> tuple[bool, str]:
    if not jadx_available():
        return False, f"jadx not found at '{JADX_BIN}'. Set JADX_PATH env var or install jadx."
    out = jadx_out_dir(package)
    out.mkdir(parents=True, exist_ok=True)
    if decompile_java:
        cmd = [JADX_BIN, str(apk), "-d", str(out)]
    else:
        cmd = [JADX_BIN, "--no-src", str(apk), "-d", str(out)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 and "error" in r.stderr.lower():
            return False, f"jadx failed:\n{r.stderr[:2000]}"
        return True, f"jadx completed. Output: {out}"
    except subprocess.TimeoutExpired:
        return False, f"jadx timed out after {timeout}s"
    except FileNotFoundError:
        return False, f"jadx binary not found at: {JADX_BIN}"


# ---------------------------------------------------------------------------
# Python fallback grep (used when system grep is unavailable)
# ---------------------------------------------------------------------------

def python_grep(
    sources: Path,
    pattern: str,
    case_sensitive: bool,
    file_filter: str,
    max_results: int,
    context_lines: int,
) -> str:
    ext = file_filter.lstrip("*.")
    flags = 0 if case_sensitive else re.IGNORECASE
    results, count = [], 0
    for f in sources.rglob(f"*.{ext}"):
        try:
            file_lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for i, line in enumerate(file_lines):
            if re.search(pattern, line, flags):
                s, e = max(0, i - context_lines), min(len(file_lines), i + context_lines + 1)
                rel = str(f.relative_to(sources))
                ctx = "\n".join(
                    f"{rel}:{j+1}:{'>' if j == i else ' '}{file_lines[j]}" for j in range(s, e)
                )
                results.append(ctx)
                count += 1
                if count >= max_results:
                    return "\n--\n".join(results)
    return "\n--\n".join(results)
