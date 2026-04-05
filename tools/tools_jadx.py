"""
tools_jadx.py — Tool implementations for APK pulling, JADX decompilation,
                 and static analysis (file listing, reading, searching).
"""

import re
import shutil
import subprocess
from pathlib import Path

from .adb_utils import run_adb, run_adb_shell, fmt_error
from .config import WORK_DIR, JADX_BIN
from .jadx_utils import (
    apk_work_dir, apk_path, jadx_out_dir, manifest_path,
    jadx_available, run_jadx, python_grep,
)


def tool_pull_apk(package: str, device) -> str:
    work = apk_work_dir(package)
    work.mkdir(parents=True, exist_ok=True)
    stdout, stderr, rc = run_adb_shell(f"pm path {package}", device)
    if rc != 0 or not stdout:
        return fmt_error(f"Cannot find APK: {stderr}")
    apk_paths = [l.replace("package:", "").strip() for l in stdout.splitlines() if l.startswith("package:")]
    results = []
    base_apk = None
    for remote in apk_paths:
        fname = Path(remote).name
        local = work / fname
        _, stderr, rc = run_adb(["pull", remote, str(local)], timeout=120, device=device)
        if rc != 0:
            results.append(f"  ❌ {fname}: {stderr}")
        else:
            size = local.stat().st_size / 1_048_576
            results.append(f"  ✅ {fname} ({size:.1f} MB)")
            if "base.apk" in fname or len(apk_paths) == 1:
                base_apk = local
    if base_apk:
        canonical = work / f"{package}.apk"
        if not canonical.exists():
            shutil.copy2(str(base_apk), str(canonical))
        results.append(f"  📎 Canonical: {canonical}")
    lines = [f"📦 pull_apk — {package} ({len(apk_paths)} file(s)):"] + results
    lines.append(f"\nNext: jadx_decompile('{package}', mode='manifest_only')  ← fast recon")
    lines.append(f"   or jadx_decompile('{package}', mode='full')           ← full source")
    return "\n".join(lines)


def tool_jadx_decompile(args: dict) -> str:
    package = args["package"]
    mode    = args.get("mode", "full")
    apk = apk_path(package)
    if not apk:
        return fmt_error(f"No APK for {package}. Run pull_apk first.")
    if not jadx_available():
        return fmt_error(
            f"jadx not found at '{JADX_BIN}'.\n"
            "Install: https://github.com/skylot/jadx/releases\n"
            "Or set env var: JADX_PATH=/path/to/jadx"
        )
    lines = [f"⚙️  jadx ({mode}) on {apk.name} …"]
    if mode == "full":
        lines.append("   May take 30–300s depending on APK size.")
    ok, msg = run_jadx(package, apk, decompile_java=(mode == "full"))
    if not ok:
        return "\n".join(lines) + f"\n\n❌ {msg}"
    out = jadx_out_dir(package)
    java_count = len(list((out / "sources").rglob("*.java"))) if (out / "sources").exists() else 0
    xml_count  = len(list(out.rglob("*.xml")))
    lines += [
        f"\n✅ Done:",
        f"   Java files:   {java_count}" if mode == "full" else "",
        f"   XML files:    {xml_count}",
        f"   Manifest:     {'✅' if manifest_path(package) else '⚠️  not found'}",
        f"\nReady to use: list_exported_components, list_deeplinks, list_content_providers, jadx_get_manifest"
        + (", jadx_list_files, jadx_search, jadx_read_file" if mode == "full" else ""),
    ]
    return "\n".join(l for l in lines if l)


def tool_jadx_get_manifest(package: str) -> str:
    mp = manifest_path(package)
    if not mp:
        return fmt_error(f"No manifest for {package}. Run jadx_decompile first.")
    content = mp.read_text(encoding="utf-8", errors="replace")
    if len(content) > 30000:
        content = content[:30000] + "\n... [TRUNCATED]"
    return f"📄 AndroidManifest.xml ({package}):\n\n{content}"


def tool_jadx_list_files(args: dict) -> str:
    package     = args["package"]
    path_filter = args.get("path_filter", "")
    extension   = args.get("extension", "")
    max_results = args.get("max_results", 100)
    out = jadx_out_dir(package)
    if not out.exists():
        return fmt_error(f"No jadx output for {package}. Run jadx_decompile first.")
    base = out / path_filter if path_filter else out
    files = sorted(f for f in base.rglob("*") if f.is_file())
    if extension:
        files = [f for f in files if f.suffix.lstrip(".") == extension]
    truncated = max(0, len(files) - max_results)
    files = files[:max_results]
    lines = [f"📁 {package} jadx files:"]
    for f in files:
        lines.append(f"  {f.relative_to(out)}  ({f.stat().st_size:,} B)")
    if truncated:
        lines.append(f"\n  … {truncated} more (use path_filter/extension to narrow)")
    return "\n".join(lines)


def tool_jadx_read_file(args: dict) -> str:
    package       = args["package"]
    relative_path = args["relative_path"]
    max_chars     = args.get("max_chars", 8000)
    target = jadx_out_dir(package) / relative_path
    if not target.exists():
        parent = target.parent
        if parent.exists():
            matches = [f for f in parent.iterdir() if f.name.lower() == target.name.lower()]
            if matches:
                target = matches[0]
            else:
                return fmt_error(f"File not found: {relative_path}")
        else:
            return fmt_error(f"Path not found: {relative_path}")
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return fmt_error(str(e))
    truncated = ""
    if len(content) > max_chars:
        truncated = f"\n\n… [TRUNCATED — {len(content)-max_chars} chars remaining]"
        content = content[:max_chars]
    return f"📄 {relative_path}\n{'─'*60}\n{content}{truncated}"


def tool_jadx_search(args: dict) -> str:
    package       = args["package"]
    pattern       = args["pattern"]
    case_sens     = args.get("case_sensitive", False)
    file_filter   = args.get("file_filter", "*.java")
    max_results   = args.get("max_results", 50)
    context_lines = args.get("context_lines", 3)
    out = jadx_out_dir(package)
    if not out.exists():
        return fmt_error(f"No jadx output for {package}. Run jadx_decompile first.")
    sources = out / "sources"
    if not sources.exists():
        return fmt_error("No Java sources. Run jadx_decompile(mode='full') first.")
    grep_flags = ["-r", "-n", "--include", file_filter, f"-C{context_lines}"]
    if not case_sens:
        grep_flags.append("-i")
    grep_flags += [pattern, str(sources)]
    try:
        r = subprocess.run(["grep"] + grep_flags, capture_output=True, text=True, timeout=30)
        output = r.stdout
    except FileNotFoundError:
        output = python_grep(sources, pattern, case_sens, file_filter, max_results, context_lines)
    except subprocess.TimeoutExpired:
        return fmt_error("Search timed out — use a more specific pattern.")
    if not output.strip():
        return f"🔍 No matches for '{pattern}' in {package}."
    lines = [l.replace(str(sources) + "/", "") for l in output.splitlines()]
    match_count = sum(1 for l in lines if re.match(r".+:\d+:.+", l))
    if match_count > max_results:
        trimmed, count = [], 0
        for l in lines:
            trimmed.append(l)
            if re.match(r".+:\d+:.+", l):
                count += 1
                if count >= max_results:
                    trimmed.append(f"\n… [{match_count-max_results} more matches]")
                    break
        lines = trimmed
    return f"🔍 '{pattern}' in {package} — {match_count} matches\n{'─'*60}\n" + "\n".join(lines)


def tool_jadx_status() -> str:
    if not WORK_DIR.exists() or not any(WORK_DIR.iterdir()):
        return f"📂 Work dir: {WORK_DIR}\nNo packages pulled yet."
    lines = [f"📂 {WORK_DIR}\n"]
    for pkg_dir in sorted(WORK_DIR.iterdir()):
        if not pkg_dir.is_dir():
            continue
        pkg  = pkg_dir.name
        apk  = apk_path(pkg)
        mf   = manifest_path(pkg)
        src  = jadx_out_dir(pkg) / "sources"
        java = len(list(src.rglob("*.java"))) if src.exists() else 0
        lines += [
            f"  📦 {pkg}",
            f"      APK:      {'✅ ' + f'{apk.stat().st_size/1_048_576:.1f} MB' if apk else '❌'}",
            f"      Manifest: {'✅' if mf else '❌ (run jadx_decompile)'}",
            f"      Sources:  {'✅ ' + str(java) + ' java files' if java else '❌ (run jadx_decompile mode=full)'}",
        ]
    return "\n".join(lines)
