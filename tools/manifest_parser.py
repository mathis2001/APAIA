"""
manifest_parser.py — Parse and format decoded AndroidManifest.xml files.
"""

import xml.etree.ElementTree as ET
from typing import Optional

from .jadx_utils import manifest_path

ANDROID_NS = "http://schemas.android.com/apk/res/android"


# ---------------------------------------------------------------------------
# Low-level XML helpers
# ---------------------------------------------------------------------------

def _attr(elem, name: str) -> Optional[str]:
    return elem.get(f"{{{ANDROID_NS}}}{name}") or elem.get(name)


def _is_exported(elem, has_intent_filter: bool) -> bool:
    val = _attr(elem, "exported")
    if val is None:
        return has_intent_filter
    return val.lower() in ("true", "1")


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_manifest(package: str) -> Optional[dict]:
    mp = manifest_path(package)
    if not mp:
        return None
    try:
        tree = ET.parse(str(mp))
    except ET.ParseError as e:
        return {"error": f"XML parse error: {e}"}

    root = tree.getroot()
    app_elem = root.find("application")
    if app_elem is None:
        return {"error": "No <application> element found"}

    result = {
        "package": root.get("package", package),
        "activities": [], "services": [], "receivers": [], "providers": [],
        "uses_permissions": [], "deeplinks": [],
    }

    for perm in root.findall("uses-permission"):
        n = _attr(perm, "name")
        if n:
            result["uses_permissions"].append(n)

    def parse_intent_filters(elem) -> list[dict]:
        filters = []
        for ifilter in elem.findall("intent-filter"):
            f = {"actions": [], "categories": [], "data": []}
            for action in ifilter.findall("action"):
                n = _attr(action, "name")
                if n:
                    f["actions"].append(n)
            for cat in ifilter.findall("category"):
                n = _attr(cat, "name")
                if n:
                    f["categories"].append(n)
            for data in ifilter.findall("data"):
                d = {
                    a: _attr(data, a)
                    for a in ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType")
                    if _attr(data, a)
                }
                if d:
                    f["data"].append(d)
            filters.append(f)
        return filters

    def comp_info(elem, tag: str) -> dict:
        name = _attr(elem, "name") or ""
        pkg = result["package"]
        if name.startswith("."):
            name = pkg + name
        elif "." not in name and name:
            name = pkg + "." + name
        filters = parse_intent_filters(elem)
        exported = _is_exported(elem, bool(filters))
        info = {
            "name": name,
            "exported": exported,
            "permission": _attr(elem, "permission"),
            "intent_filters": filters,
        }
        if tag == "provider":
            info["authorities"]           = _attr(elem, "authorities")
            info["read_permission"]       = _attr(elem, "readPermission")
            info["write_permission"]      = _attr(elem, "writePermission")
            info["grant_uri_permissions"] = _attr(elem, "grantUriPermissions")
        return info

    for el in app_elem.findall("activity") + app_elem.findall("activity-alias"):
        result["activities"].append(comp_info(el, "activity"))
    for el in app_elem.findall("service"):
        result["services"].append(comp_info(el, "service"))
    for el in app_elem.findall("receiver"):
        result["receivers"].append(comp_info(el, "receiver"))
    for el in app_elem.findall("provider"):
        result["providers"].append(comp_info(el, "provider"))

    for comp in result["activities"] + result["services"] + result["receivers"]:
        for f in comp.get("intent_filters", []):
            for d in f.get("data", []):
                scheme = d.get("scheme", "")
                host   = d.get("host", "")
                path   = d.get("path") or d.get("pathPrefix") or d.get("pathPattern") or ""
                if scheme:
                    uri = f"{scheme}://{host}{path}" if host else f"{scheme}://"
                    result["deeplinks"].append({"uri": uri, "component": comp["name"], "data": d})

    return result


# ---------------------------------------------------------------------------
# Formatting helper
# ---------------------------------------------------------------------------

def format_component(comp: dict) -> str:
    lines = [f"  • {comp['name']}"]
    if comp.get("permission"):
        lines.append(f"      🔒 permission: {comp['permission']}")
    if comp.get("authorities"):
        lines.append(f"      📡 authority: {comp['authorities']}")
    if comp.get("grant_uri_permissions") == "true":
        lines.append(f"      ⚠️  grantUriPermissions=true")
    for f in comp.get("intent_filters", []):
        if f["actions"]:
            lines.append(f"      actions: {', '.join(f['actions'])}")
        for d in f.get("data", []):
            lines.append(f"      data: {d}")
    return "\n".join(lines)
