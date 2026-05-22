#!/usr/bin/env python3
"""
server.py — Android Pentesting MCP Server entry point.

Registers all tools with the MCP framework and dispatches incoming calls
to the appropriate tool-implementation modules.

Module layout
─────────────
config.py           Global config (WORK_DIR, JADX_BIN)
adb_utils.py        Low-level ADB wrappers (run_adb, run_adb_shell, fmt_error)
jadx_utils.py       JADX path helpers, run_jadx, python_grep fallback
manifest_parser.py  AndroidManifest.xml parser and formatter
tools_device.py     list_devices, device_info, list_packages, app_info
tools_jadx.py       pull_apk, jadx_decompile/get_manifest/list_files/read_file/search/status
tools_components.py list_exported_components, list_deeplinks, list_permissions, list_content_providers
tools_ui.py         send_intent, open_deeplink, ui_tap/swipe/input_text/keyevent/clear_field, take_screenshot, dump_ui_hierarchy
tools_poc.py        poc_bruteforce_login, poc_fuzz_deeplinks, poc_intent_fuzzer, poc_query_content_provider
tools_runtime.py    capture_logcat, list_app_files, pull_app_file
"""

import asyncio
from typing import Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from tools.tools_device import (
    tool_list_devices, tool_device_info, tool_list_packages, tool_app_info,
)
from tools.tools_jadx import (
    tool_pull_apk, tool_jadx_decompile, tool_jadx_get_manifest,
    tool_jadx_list_files, tool_jadx_read_file, tool_jadx_search, tool_jadx_status,
)
from tools.tools_components import (
    tool_list_exported_components, tool_list_deeplinks,
    tool_list_permissions, tool_list_content_providers,
    tool_audit_manifest,
)
from tools.tools_ui import (
    tool_send_intent, tool_open_deeplink,
    tool_ui_tap, tool_ui_swipe, tool_ui_input_text, tool_ui_keyevent,
    tool_ui_clear_field, tool_take_screenshot, tool_dump_ui_hierarchy,
)
from tools.tools_poc import (
    tool_poc_bruteforce, tool_poc_fuzz_deeplinks,
    tool_poc_intent_fuzzer, tool_poc_query_provider,
)
from tools.tools_runtime import tool_capture_logcat, tool_list_app_files, tool_pull_app_file

from tools.poc_deeplink_hijacking import tool_run_deeplink_poc

app = Server("APAIA")

# ---------------------------------------------------------------------------
# Tool definitions (schema registry)
# ---------------------------------------------------------------------------

TOOLS = [
    # Device / Package
    Tool(name="list_devices", description="List all connected Android devices/emulators.",
         inputSchema={"type": "object", "properties": {}, "required": []}),
    Tool(name="device_info", description="Device OS, arch, SELinux, root status.",
         inputSchema={"type": "object", "properties": {"device": {"type": "string"}}, "required": []}),
    Tool(name="list_packages",
         description="List installed packages (all|system|third-party|enabled|disabled). Optional keyword filter.",
         inputSchema={"type": "object", "properties": {
             "filter":  {"type": "string", "enum": ["all", "system", "third-party", "enabled", "disabled"]},
             "keyword": {"type": "string"},
             "device":  {"type": "string"},
         }, "required": []}),
    Tool(name="app_info", description="App version, SDK, paths, debuggable flag.",
         inputSchema={"type": "object", "properties": {
             "package": {"type": "string"}, "device": {"type": "string"},
         }, "required": ["package"]}),

    # JADX
    Tool(name="pull_apk",
         description="Pull the installed APK(s) from device to local work dir. Handles split APKs. Required before jadx_decompile.",
         inputSchema={"type": "object", "properties": {
             "package": {"type": "string"}, "device": {"type": "string"},
         }, "required": ["package"]}),
    Tool(name="jadx_decompile",
         description=(
             "Decompile a pulled APK with jadx. "
             "mode='manifest_only' is fast (~5s, enough for component recon). "
             "mode='full' decompiles Java source (slow, needed for jadx_search/jadx_read_file)."
         ),
         inputSchema={"type": "object", "properties": {
             "package": {"type": "string"},
             "mode": {"type": "string", "enum": ["full", "manifest_only"],
                      "description": "full=Java+resources, manifest_only=resources only"},
         }, "required": ["package"]}),
    Tool(name="jadx_get_manifest",
         description="Return the decoded AndroidManifest.xml. Requires jadx_decompile to have run.",
         inputSchema={"type": "object", "properties": {"package": {"type": "string"}}, "required": ["package"]}),
    Tool(name="jadx_list_files",
         description="List decompiled source and resource files. Filter by path prefix or extension.",
         inputSchema={"type": "object", "properties": {
             "package":     {"type": "string"},
             "path_filter": {"type": "string", "description": "Subdirectory filter (optional)"},
             "extension":   {"type": "string", "description": "e.g. 'java' or 'xml'"},
             "max_results": {"type": "integer"},
         }, "required": ["package"]}),
    Tool(name="jadx_read_file",
         description="Read a specific decompiled file. Use jadx_list_files first to find the path.",
         inputSchema={"type": "object", "properties": {
             "package":       {"type": "string"},
             "relative_path": {"type": "string", "description": "Path relative to jadx output dir"},
             "max_chars":     {"type": "integer", "description": "Max chars (default 8000)"},
         }, "required": ["package", "relative_path"]}),
    Tool(name="jadx_search",
         description=(
             "Grep across all decompiled Java sources. Find hardcoded secrets, API keys, URLs, "
             "crypto, SQL, WebView flags, exported method calls, etc. Requires mode=full decompilation."
         ),
         inputSchema={"type": "object", "properties": {
             "package":       {"type": "string"},
             "pattern":       {"type": "string", "description": "Search string or regex"},
             "case_sensitive":{"type": "boolean"},
             "file_filter":   {"type": "string", "description": "Glob, default '*.java'"},
             "max_results":   {"type": "integer"},
             "context_lines": {"type": "integer", "description": "Context lines per match (default 3)"},
         }, "required": ["package", "pattern"]}),
    Tool(name="jadx_status",
         description="Show which packages have been pulled/decompiled in the work directory.",
         inputSchema={"type": "object", "properties": {}, "required": []}),

    # Component enumeration
    Tool(name="list_exported_components",
         description=(
             "List exported components parsed from the decoded AndroidManifest.xml. "
             "Far more reliable than dumpsys. Requires jadx_decompile (manifest_only is enough)."
         ),
         inputSchema={"type": "object", "properties": {
             "package":           {"type": "string"},
             "include_unexported":{"type": "boolean", "description": "Also show non-exported components (default false)"},
         }, "required": ["package"]}),
    Tool(name="list_deeplinks",
         description="List deep link URI schemes and intent filter data from manifest. Requires jadx_decompile, falls back to dumpsys.",
         inputSchema={"type": "object", "properties": {
             "package": {"type": "string"}, "device": {"type": "string"},
         }, "required": ["package"]}),
    Tool(name="list_permissions",
         description="Permissions declared in manifest and granted at runtime.",
         inputSchema={"type": "object", "properties": {
             "package": {"type": "string"}, "device": {"type": "string"},
         }, "required": ["package"]}),
    Tool(name="list_content_providers",
         description="Content providers with authorities, export status, permissions. Uses manifest if available, falls back to dumpsys.",
         inputSchema={"type": "object", "properties": {
             "package": {"type": "string"}, "device": {"type": "string"},
         }, "required": ["package"]}),
    Tool(name="audit_manifest",
         description=(
             "Scan the decoded AndroidManifest.xml for security misconfigurations: "
             "debuggable, allowBackup, cleartext traffic, exported components without permissions, "
             "dangerous permissions, grantUriPermissions abuse, testOnly flag, and more. "
             "Returns a severity-ranked report (CRITICAL / HIGH / MEDIUM / INFO). "
             "Requires jadx_decompile to have run first."
         ),
         inputSchema={"type": "object", "properties": {"package": {"type": "string"}}, "required": ["package"]}),

    # Intent
    Tool(name="send_intent",
         description="Send an intent via adb am start/broadcast/startservice. Prefix extra values with 'int:'/'bool:'/'long:' to cast types.",
         inputSchema={"type": "object", "properties": {
             "action":    {"type": "string"},
             "component": {"type": "string"},
             "uri":       {"type": "string"},
             "extras":    {"type": "object", "additionalProperties": {"type": "string"}},
             "flags":     {"type": "string"},
             "device":    {"type": "string"},
         }, "required": ["action"]}),
    Tool(name="open_deeplink",
         description="Open a URI on the device via am start VIEW intent.",
         inputSchema={"type": "object", "properties": {
             "uri": {"type": "string"}, "device": {"type": "string"},
         }, "required": ["uri"]}),

    # UI
    Tool(name="ui_tap", description="Tap a screen coordinate.",
         inputSchema={"type": "object", "properties": {
             "x": {"type": "integer"}, "y": {"type": "integer"}, "device": {"type": "string"},
         }, "required": ["x", "y"]}),
    Tool(name="ui_swipe", description="Swipe gesture.",
         inputSchema={"type": "object", "properties": {
             "x1": {"type": "integer"}, "y1": {"type": "integer"},
             "x2": {"type": "integer"}, "y2": {"type": "integer"},
             "duration_ms": {"type": "integer"}, "device": {"type": "string"},
         }, "required": ["x1", "y1", "x2", "y2"]}),
    Tool(name="ui_input_text", description="Type text into the focused field.",
         inputSchema={"type": "object", "properties": {
             "text": {"type": "string"}, "device": {"type": "string"},
         }, "required": ["text"]}),
    Tool(name="ui_keyevent",
         description="Send a keyevent. Common: ENTER=66 DEL=67 BACK=4 TAB=61 HOME=3.",
         inputSchema={"type": "object", "properties": {
             "keycode": {"type": "integer"}, "device": {"type": "string"},
         }, "required": ["keycode"]}),
    Tool(name="ui_clear_field", description="Clear focused input (select-all + delete).",
         inputSchema={"type": "object", "properties": {"device": {"type": "string"}}, "required": []}),
    Tool(name="take_screenshot", description="Capture screen to a local PNG.",
         inputSchema={"type": "object", "properties": {
             "output_path": {"type": "string"}, "device": {"type": "string"},
         }, "required": []}),
    Tool(name="dump_ui_hierarchy",
         description="Dump current UI XML (uiautomator) to find element coordinates and resource IDs.",
         inputSchema={"type": "object", "properties": {"device": {"type": "string"}}, "required": []}),

    # PoC
    Tool(name="poc_bruteforce_login",
         description="PoC: UI-driven login bruteforce. Iterates a password list, fills credentials via tap+type, detects success/failure in UI dump.",
         inputSchema={"type": "object", "properties": {
             "username":          {"type": "string"},
             "passwords":         {"type": "array", "items": {"type": "string"}},
             "username_coords":   {"type": "array", "items": {"type": "integer"}, "minItems": 2, "maxItems": 2},
             "password_coords":   {"type": "array", "items": {"type": "integer"}, "minItems": 2, "maxItems": 2},
             "submit_coords":     {"type": "array", "items": {"type": "integer"}, "minItems": 2, "maxItems": 2},
             "success_indicator": {"type": "string"},
             "failure_indicator": {"type": "string"},
             "delay_seconds":     {"type": "number"},
             "max_attempts":      {"type": "integer"},
             "device":            {"type": "string"},
         }, "required": ["username", "passwords", "username_coords", "password_coords", "submit_coords", "success_indicator"]}),
    Tool(name="poc_fuzz_deeplinks",
         description="PoC: Fuzz a deep link template ({FUZZ} placeholder) with a wordlist.",
         inputSchema={"type": "object", "properties": {
             "uri_template":      {"type": "string"},
             "wordlist":          {"type": "array", "items": {"type": "string"}},
             "success_indicator": {"type": "string"},
             "delay_seconds":     {"type": "number"},
             "device":            {"type": "string"},
         }, "required": ["uri_template", "wordlist"]}),
    Tool(name="poc_intent_fuzzer",
         description="PoC: Send batch intents to an exported component varying one extra key.",
         inputSchema={"type": "object", "properties": {
             "component":    {"type": "string"},
             "action":       {"type": "string"},
             "extra_key":    {"type": "string"},
             "fuzz_values":  {"type": "array", "items": {"type": "string"}},
             "static_extras":{"type": "object", "additionalProperties": {"type": "string"}},
             "delay_seconds":{"type": "number"},
             "device":       {"type": "string"},
         }, "required": ["component", "action", "extra_key", "fuzz_values"]}),
    Tool(name="poc_query_content_provider",
         description="PoC: Query a content provider URI. Tests unauth access and SQLi.",
         inputSchema={"type": "object", "properties": {
             "uri":        {"type": "string"},
             "projection": {"type": "string"},
             "selection":  {"type": "string", "description": "WHERE clause — try: 1=1 OR '1'='1'"},
             "device":     {"type": "string"},
         }, "required": ["uri"]}),
    Tool(name="poc_deeplink_hijacking",
     description=(
         "Generate a PoC APK that registers for a given deeplink scheme/host "
         "to test deeplink hijacking, then install it on the connected device via adb."
     ),
     inputSchema={"type": "object", "properties": {
         "deeplink":        {"type": "string", "description": "Deeplink URI to hijack — set by Claude (e.g. 'aep://com.smart.hellosmart'). REQUIRED."},
         "output_path":     {"type": "string", "description": "Full path for the generated APK. Optional."},
         "install":         {"type": "boolean", "description": "Install via adb after build. Default: true."},
         "attacker_domain": {"type": "string", "description": "Domain to exfiltrate intercepted intent data. Optional."},
     }, "required": ["deeplink"]}),

    # Runtime
    Tool(name="capture_logcat",
         description="Capture logcat for N seconds, filtered by tag or package.",
         inputSchema={"type": "object", "properties": {
             "duration_seconds": {"type": "integer"},
             "filter_tag":       {"type": "string"},
             "package":          {"type": "string"},
             "level":            {"type": "string", "enum": ["V", "D", "I", "W", "E"]},
             "device":           {"type": "string"},
         }, "required": []}),
    Tool(name="list_app_files",
         description="List files in app data dir (run-as for debuggable apps, or root).",
         inputSchema={"type": "object", "properties": {
             "package":  {"type": "string"},
             "path":     {"type": "string"},
             "use_root": {"type": "boolean"},
             "device":   {"type": "string"},
         }, "required": ["package"]}),
    Tool(name="pull_app_file",
         description="Pull a file from device to local machine.",
         inputSchema={"type": "object", "properties": {
             "package":     {"type": "string"},
             "remote_path": {"type": "string"},
             "local_path":  {"type": "string"},
             "use_root":    {"type": "boolean"},
             "device":      {"type": "string"},
         }, "required": ["remote_path", "local_path"]}),
]


# ---------------------------------------------------------------------------
# MCP handlers
# ---------------------------------------------------------------------------

@app.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    device = arguments.get("device")
    result = dispatch(name, arguments, device)
    return [TextContent(type="text", text=result)]


def dispatch(name: str, args: dict, device: Optional[str]) -> str:
    match name:
        # Device / Package
        case "list_devices":               return tool_list_devices()
        case "device_info":                return tool_device_info(device)
        case "list_packages":              return tool_list_packages(args, device)
        case "app_info":                   return tool_app_info(args["package"], device)
        # JADX
        case "pull_apk":                   return tool_pull_apk(args["package"], device)
        case "jadx_decompile":             return tool_jadx_decompile(args)
        case "jadx_get_manifest":          return tool_jadx_get_manifest(args["package"])
        case "jadx_list_files":            return tool_jadx_list_files(args)
        case "jadx_read_file":             return tool_jadx_read_file(args)
        case "jadx_search":                return tool_jadx_search(args)
        case "jadx_status":                return tool_jadx_status()
        # Component enumeration
        case "list_exported_components":   return tool_list_exported_components(args)
        case "list_deeplinks":             return tool_list_deeplinks(args, device)
        case "list_permissions":           return tool_list_permissions(args["package"], device)
        case "list_content_providers":     return tool_list_content_providers(args, device)
        case "audit_manifest":             return tool_audit_manifest(args["package"])
        # Intent / UI
        case "send_intent":                return tool_send_intent(args, device)
        case "open_deeplink":              return tool_open_deeplink(args["uri"], device)
        case "ui_tap":                     return tool_ui_tap(args["x"], args["y"], device)
        case "ui_swipe":                   return tool_ui_swipe(args, device)
        case "ui_input_text":              return tool_ui_input_text(args["text"], device)
        case "ui_keyevent":                return tool_ui_keyevent(args["keycode"], device)
        case "ui_clear_field":             return tool_ui_clear_field(device)
        case "take_screenshot":            return tool_take_screenshot(args, device)
        case "dump_ui_hierarchy":          return tool_dump_ui_hierarchy(device)
        # PoC
        case "poc_bruteforce_login":       return tool_poc_bruteforce(args, device)
        case "poc_fuzz_deeplinks":         return tool_poc_fuzz_deeplinks(args, device)
        case "poc_intent_fuzzer":          return tool_poc_intent_fuzzer(args, device)
        case "poc_query_content_provider": return tool_poc_query_provider(args, device)
        case "poc_deeplink_hijacking":     return tool_run_deeplink_poc(args, device)

        # Runtime
        case "capture_logcat":             return tool_capture_logcat(args, device)
        case "list_app_files":             return tool_list_app_files(args, device)
        case "pull_app_file":              return tool_pull_app_file(args, device)
        case _:                            return f"Unknown tool: {name}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
