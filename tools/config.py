"""
config.py — Global configuration and shared constants.
"""

import os
import shutil
from pathlib import Path

WORK_DIR = Path(os.environ.get("ANDROID_PENTEST_WORKDIR", Path.home() / ".android-pentest"))
JADX_BIN = os.environ.get("JADX_PATH", shutil.which("jadx") or "jadx")

WORK_DIR.mkdir(parents=True, exist_ok=True)
