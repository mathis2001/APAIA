"""
tools_runtime.py — Tool implementations for runtime monitoring:
                   logcat capture, app file listing, and file pulling.
"""

import subprocess
import time
from typing import Optional

from .adb_utils import run_adb, run_adb_shell, fmt_error


def tool_capture_logcat(args: dict, device: Optional[str]) -> str:
    dur   = args.get("duration_seconds", 5)
    tag   = args.get("filter_tag", "")
    pkg   = args.get("package", "")
    level = args.get("level", "D")
    run_adb(["logcat", "-c"], device=device)
    time.sleep(0.2)
    log_filter = f"{tag}:{level} *:S" if tag else f"*:{level}"
    cmd = ["adb"] + (["-s", device] if device else []) + ["logcat", "-d", "-v", "time", log_filter]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(dur)
        proc.terminate()
        stdout, _ = proc.communicate(timeout=3)
    except Exception as e:
        return f"Logcat error: {e}"
    lines = stdout.splitlines()
    if pkg:
        pid_out, _, _ = run_adb_shell(f"pidof {pkg}", device)
        pids = pid_out.split()
        if pids:
            lines = [l for l in lines if any(p in l for p in pids)]
    out = "\n".join(lines[:500])
    if len(lines) > 500:
        out += f"\n… [{len(lines)-500} more]"
    return f"📋 Logcat ({dur}s):\n{out or '(empty)'}"


def tool_list_app_files(args: dict, device: Optional[str]) -> str:
    pkg  = args["package"]
    path = args.get("path", "/")
    root = args.get("use_root", False)
    base = f"/data/data/{pkg}{path}"
    cmd  = f"su -c 'ls -la {base}'" if root else f"run-as {pkg} ls -la {base}"
    out, err, _ = run_adb_shell(cmd, device)
    if not out and err:
        return fmt_error(f"{err}\nTip: use use_root=true or ensure app is debuggable.")
    return f"📁 {base}:\n{out}"


def tool_pull_app_file(args: dict, device: Optional[str]) -> str:
    pkg  = args.get("package")
    rem  = args["remote_path"]
    loc  = args["local_path"]
    root = args.get("use_root", False)
    tmp  = "/sdcard/_mcp_pull"
    if root:
        run_adb_shell(f"su -c 'cp {rem} {tmp}'", device)
        _, err, rc = run_adb(["pull", tmp, loc], device=device)
        run_adb_shell(f"rm {tmp}", device)
    elif pkg:
        run_adb_shell(f"run-as {pkg} cat {rem} > {tmp}", device)
        _, err, rc = run_adb(["pull", tmp, loc], device=device)
        run_adb_shell(f"rm {tmp}", device)
    else:
        _, err, rc = run_adb(["pull", rem, loc], device=device)
    return f"✅ → {loc}" if rc == 0 else fmt_error(err)
