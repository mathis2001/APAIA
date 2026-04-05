"""
tools_device.py — Tool implementations for device info and package management.
"""

import re
from typing import Optional

from .adb_utils import run_adb, run_adb_shell, fmt_error
from .jadx_utils import apk_path, manifest_path, jadx_out_dir


def tool_list_devices() -> str:
    stdout, stderr, rc = run_adb(["devices", "-l"])
    if rc != 0:
        return fmt_error(stderr)
    lines = [l for l in stdout.splitlines()[1:] if l.strip() and "offline" not in l]
    return (
        "Connected devices:\n" + "\n".join(f"  • {l}" for l in lines)
    ) if lines else "No online devices."


def tool_device_info(device: Optional[str]) -> str:
    props = [
        ("Model",        "ro.product.model"),
        ("Manufacturer", "ro.product.manufacturer"),
        ("Android",      "ro.build.version.release"),
        ("SDK",          "ro.build.version.sdk"),
        ("Build",        "ro.build.display.id"),
        ("ABI",          "ro.product.cpu.abi"),
    ]
    lines = ["📱 Device Info"]
    for label, prop in props:
        out, _, _ = run_adb_shell(f"getprop {prop}", device)
        lines.append(f"  {label}: {out or 'N/A'}")
    se, _, _ = run_adb_shell("getenforce", device)
    lines.append(f"  SELinux: {se or 'N/A'}")
    root, _, _ = run_adb_shell("which su", device)
    lines.append(f"  Root: {'✅ Found' if root else '❌ Not found'}")
    return "\n".join(lines)


def tool_list_packages(args: dict, device: Optional[str]) -> str:
    ftype = args.get("filter", "third-party")
    kw    = args.get("keyword", "")
    flag  = {"all": "", "system": "-s", "third-party": "-3", "enabled": "-e", "disabled": "-d"}.get(ftype, "-3")
    stdout, stderr, rc = run_adb_shell(f"pm list packages {flag}".strip(), device)
    if rc != 0:
        return fmt_error(stderr)
    pkgs = sorted(l.replace("package:", "").strip() for l in stdout.splitlines() if l.startswith("package:"))
    if kw:
        pkgs = [p for p in pkgs if kw.lower() in p.lower()]
    return f"📦 {ftype} ({len(pkgs)}):\n" + "\n".join(f"  • {p}" for p in pkgs)


def tool_app_info(package: str, device: Optional[str]) -> str:
    stdout, stderr, rc = run_adb_shell(f"dumpsys package {package}", device)
    if rc != 0 or not stdout:
        return fmt_error(stderr or "Package not found")
    lines = [f"📋 {package}"]
    for label, pat in [
        ("Version",     r"versionName=(\S+)"),
        ("VersionCode", r"versionCode=(\d+)"),
        ("TargetSDK",   r"targetSdk=(\d+)"),
        ("MinSDK",      r"minSdk=(\d+)"),
        ("Path",        r"codePath=(\S+)"),
        ("DataDir",     r"dataDir=(\S+)"),
        ("UID",         r"userId=(\d+)"),
    ]:
        m = re.search(pat, stdout)
        if m:
            lines.append(f"  {label}: {m.group(1)}")
    debuggable = "debuggable=true" in stdout
    lines.append(f"  Debuggable: {'⚠️  YES' if debuggable else 'NO'}")
    if apk_path(package):
        lines.append(f"  APK: ✅ {apk_path(package)}")
    if manifest_path(package):
        lines.append(f"  JADX: ✅ {jadx_out_dir(package)}")
    return "\n".join(lines)
