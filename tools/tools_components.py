"""
tools_components.py — Tool implementations for Android component enumeration:
                       exported components, deep links, permissions, content providers.
"""

import re
from typing import Optional

from .adb_utils import run_adb_shell, fmt_error
from .manifest_parser import parse_manifest, format_component


def tool_list_exported_components(args: dict) -> str:
    package            = args["package"]
    include_unexported = args.get("include_unexported", False)
    manifest = parse_manifest(package)
    if manifest is None:
        return fmt_error(
            f"No decoded manifest for {package}.\n"
            f"Run: pull_apk('{package}') → jadx_decompile('{package}', mode='manifest_only')"
        )
    if "error" in manifest:
        return fmt_error(manifest["error"])
    lines = [f"🔓 Exported Components — {package}  (AndroidManifest.xml)"]
    for label, key in [
        ("Activities", "activities"),
        ("Services",   "services"),
        ("Receivers",  "receivers"),
        ("Providers",  "providers"),
    ]:
        comps    = manifest[key]
        exported = [c for c in comps if c["exported"]]
        lines.append(f"\n  ⚡ {label} ({len(exported)} exported / {len(comps)} total):")
        if exported:
            for c in exported:
                lines.append(format_component(c))
        else:
            lines.append("    (none)")
        if include_unexported:
            unexp = [c for c in comps if not c["exported"]]
            if unexp:
                lines.append(f"  🔒 Unexported {label} ({len(unexp)}):")
                for c in unexp:
                    lines.append(f"    • {c['name']}")
    return "\n".join(lines)


def tool_list_deeplinks(args: dict, device: Optional[str]) -> str:
    package  = args["package"]
    manifest = parse_manifest(package)
    if manifest and "error" not in manifest:
        dls   = manifest["deeplinks"]
        lines = [f"🔗 Deep Links — {package}  (AndroidManifest.xml)"]
        if not dls:
            lines.append("  No deep links found.")
        else:
            schemes = set()
            for dl in dls:
                lines.append(f"\n  • {dl['uri']}")
                lines.append(f"      component: {dl['component']}")
                for k, v in dl["data"].items():
                    lines.append(f"      {k}: {v}")
                if dl["data"].get("scheme"):
                    schemes.add(dl["data"]["scheme"])
            lines.append(f"\n  Schemes: {', '.join(sorted(schemes))}")
        return "\n".join(lines)

    # Fallback to dumpsys
    stdout, _, rc = run_adb_shell(f"dumpsys package {package}", device)
    if rc != 0:
        return fmt_error("dumpsys failed. Run jadx_decompile for accurate results.")
    schemes = list(dict.fromkeys(re.findall(r'Scheme:\s*"([^"]+)"', stdout)))
    auths   = list(dict.fromkeys(re.findall(r'Authority:\s*"([^"]+)"', stdout)))
    lines   = [f"🔗 Deep Links — {package}  (dumpsys fallback — run jadx_decompile for accuracy)"]
    lines.append(f"  Schemes: {', '.join(schemes) or 'none'}")
    lines.append(f"  Authorities: {', '.join(auths) or 'none'}")
    if schemes and auths:
        lines.append("  Examples:")
        for s in schemes[:3]:
            for a in auths[:2]:
                lines.append(f"    {s}://{a}/")
    return "\n".join(lines)


def tool_list_permissions(package: str, device: Optional[str]) -> str:
    manifest = parse_manifest(package)
    mf_perms = manifest.get("uses_permissions", []) if manifest and "error" not in manifest else []
    stdout, _, rc = run_adb_shell(f"dumpsys package {package}", device)
    granted = re.findall(r"(\S+): granted=true", stdout) if rc == 0 else []
    lines = [f"🔐 Permissions — {package}"]
    if mf_perms:
        lines.append(f"\n  Declared ({len(mf_perms)}):")
        for p in mf_perms:
            lines.append(f"    • {p}{'  ✅ granted' if p in granted else ''}")
    extra = [p for p in granted if p not in mf_perms]
    if extra:
        lines.append(f"\n  Extra runtime grants ({len(extra)}):")
        for p in extra:
            lines.append(f"    • {p}")
    if not mf_perms and not granted:
        lines.append("  No permissions found.")
    return "\n".join(lines)


def tool_list_content_providers(args: dict, device: Optional[str]) -> str:
    package  = args["package"]
    manifest = parse_manifest(package)
    if manifest and "error" not in manifest:
        providers = manifest["providers"]
        lines = [f"🗄️ Content Providers — {package}  (AndroidManifest.xml)"]
        if not providers:
            lines.append("  None.")
            return "\n".join(lines)
        for label, filt in [("Exported", True), ("Unexported", False)]:
            group = [p for p in providers if p["exported"] == filt]
            lines.append(f"\n  {'⚡' if filt else '🔒'} {label} ({len(group)}):")
            for p in group:
                lines.append(f"    • {p['name']}")
                if p.get("authorities"):
                    lines.append(f"        content://{p['authorities']}")
                if p.get("read_permission"):
                    lines.append(f"        read_perm: {p['read_permission']}")
                if p.get("write_permission"):
                    lines.append(f"        write_perm: {p['write_permission']}")
                if p.get("grant_uri_permissions") == "true":
                    lines.append(f"        ⚠️  grantUriPermissions=true")
        return "\n".join(lines)

    # Fallback to dumpsys
    stdout, _, rc = run_adb_shell(f"dumpsys package {package}", device)
    auths = list(dict.fromkeys(re.findall(r"[Aa]uthority[:\s=]+\"?([^\"\s,]+)\"?", stdout)))
    lines = [f"🗄️ Content Providers — {package}  (dumpsys fallback)"]
    for a in auths:
        lines.append(f"  • content://{a}")
    return "\n".join(lines)
