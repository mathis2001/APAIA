"""
tools_ui.py — Tool implementations for UI interaction, intents, and screenshots.
"""

import time
from typing import Optional

from .adb_utils import run_adb, run_adb_shell, fmt_error


def tool_send_intent(args: dict, device: Optional[str]) -> str:
    action = args["action"]
    am_cmd = action if action in ("start", "broadcast", "startservice") else "start"
    intent_action = None if action in ("start", "broadcast", "startservice") else action
    parts = [f"am {am_cmd}"]
    if intent_action:          parts.append(f"-a {intent_action}")
    if args.get("component"):  parts.append(f"-n {args['component']}")
    if args.get("uri"):        parts.append(f"-d '{args['uri']}'")
    if args.get("flags"):      parts.append(f"-f {args['flags']}")
    for k, v in args.get("extras", {}).items():
        if v.startswith("int:"):    parts.append(f"--ei {k} {v[4:]}")
        elif v.startswith("bool:"): parts.append(f"--ez {k} {v[5:]}")
        elif v.startswith("long:"): parts.append(f"--el {k} {v[5:]}")
        else:                       parts.append(f"--es {k} '{v}'")
    cmd = " ".join(parts)
    stdout, stderr, rc = run_adb_shell(cmd, device)
    return f"📤 `{cmd}`\n{stdout or stderr or '(no output)'}"


def tool_open_deeplink(uri: str, device: Optional[str]) -> str:
    out, err, _ = run_adb_shell(f"am start -a android.intent.action.VIEW -d '{uri}'", device)
    return f"🔗 {uri}\n{out or err}"


def tool_ui_tap(x, y, device: Optional[str]) -> str:
    run_adb_shell(f"input tap {x} {y}", device)
    return f"👆 ({x},{y})"


def tool_ui_swipe(args: dict, device: Optional[str]) -> str:
    d = args.get("duration_ms", 300)
    run_adb_shell(f"input swipe {args['x1']} {args['y1']} {args['x2']} {args['y2']} {d}", device)
    return "👆 swipe done"


def tool_ui_input_text(text: str, device: Optional[str]) -> str:
    e = text.replace("\\", "\\\\").replace("'", "\\'").replace(" ", "%s").replace("&", "\\&").replace(";", "\\;")
    run_adb_shell(f"input text '{e}'", device)
    return f"⌨️  Typed: {text}"


def tool_ui_keyevent(keycode, device: Optional[str]) -> str:
    run_adb_shell(f"input keyevent {keycode}", device)
    return f"🔑 keyevent {keycode}"


def tool_ui_clear_field(device: Optional[str]) -> str:
    run_adb_shell("input keyevent 277", device)
    time.sleep(0.1)
    run_adb_shell("input keyevent 67", device)
    return "🧹 cleared"


def tool_take_screenshot(args: dict, device: Optional[str]) -> str:
    local = args.get("output_path", "/tmp/screen.png")
    run_adb_shell("screencap -p /sdcard/_mcp_sc.png", device)
    time.sleep(0.4)
    _, err, rc = run_adb(["pull", "/sdcard/_mcp_sc.png", local], device=device)
    run_adb_shell("rm /sdcard/_mcp_sc.png", device)
    return f"📸 {local}" if rc == 0 else fmt_error(err)


def tool_dump_ui_hierarchy(device: Optional[str]) -> str:
    run_adb_shell("uiautomator dump /sdcard/_mcp_ui.xml", device)
    time.sleep(0.8)
    out, err, _ = run_adb(["shell", "cat /sdcard/_mcp_ui.xml"], device=device)
    run_adb_shell("rm /sdcard/_mcp_ui.xml", device)
    if not out:
        return fmt_error(err or "Empty dump")
    if len(out) > 25000:
        out = out[:25000] + "\n... [TRUNCATED]"
    return f"🗺️ UI:\n{out}"
