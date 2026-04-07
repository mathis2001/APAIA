"""
manifest_parser.py — Parse and format decoded AndroidManifest.xml files,
                      including detection of common security misconfigurations.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .jadx_utils import manifest_path

ANDROID_NS = "http://schemas.android.com/apk/res/android"


# ---------------------------------------------------------------------------
# Misconfig severity model
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    INFO     = "INFO"

SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.INFO:     "🔵",
}

@dataclass
class Misconfig:
    severity: Severity
    title: str
    detail: str
    recommendation: str


# ---------------------------------------------------------------------------
# Dangerous permissions worth flagging
# ---------------------------------------------------------------------------

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS":           (Severity.HIGH,   "Read contacts"),
    "android.permission.WRITE_CONTACTS":          (Severity.HIGH,   "Write contacts"),
    "android.permission.READ_CALL_LOG":           (Severity.HIGH,   "Read call log"),
    "android.permission.WRITE_CALL_LOG":          (Severity.HIGH,   "Write call log"),
    "android.permission.PROCESS_OUTGOING_CALLS":  (Severity.HIGH,   "Intercept outgoing calls"),
    "android.permission.READ_SMS":                (Severity.HIGH,   "Read SMS"),
    "android.permission.RECEIVE_SMS":             (Severity.HIGH,   "Receive SMS"),
    "android.permission.SEND_SMS":                (Severity.HIGH,   "Send SMS"),
    "android.permission.RECEIVE_MMS":             (Severity.HIGH,   "Receive MMS"),
    "android.permission.RECORD_AUDIO":            (Severity.HIGH,   "Record audio (microphone)"),
    "android.permission.CAMERA":                  (Severity.HIGH,   "Camera access"),
    "android.permission.ACCESS_FINE_LOCATION":    (Severity.HIGH,   "Precise GPS location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (Severity.HIGH, "Background location"),
    "android.permission.READ_EXTERNAL_STORAGE":   (Severity.MEDIUM, "Read external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE":  (Severity.MEDIUM, "Write external storage"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (Severity.HIGH,   "Manage all files (broad storage)"),
    "android.permission.GET_ACCOUNTS":            (Severity.MEDIUM, "Enumerate device accounts"),
    "android.permission.USE_BIOMETRIC":           (Severity.INFO,   "Biometric authentication"),
    "android.permission.BLUETOOTH_SCAN":          (Severity.MEDIUM, "Bluetooth scanning (nearby devices)"),
    "android.permission.BLUETOOTH_CONNECT":       (Severity.MEDIUM, "Bluetooth connect"),
    "android.permission.NFC":                     (Severity.MEDIUM, "NFC access"),
    "android.permission.INSTALL_PACKAGES":        (Severity.CRITICAL,"Install arbitrary APKs"),
    "android.permission.DELETE_PACKAGES":         (Severity.HIGH,   "Uninstall packages"),
    "android.permission.REQUEST_INSTALL_PACKAGES":(Severity.HIGH,   "Request APK installs"),
    "android.permission.READ_PHONE_STATE":        (Severity.MEDIUM, "Read phone state / IMEI"),
    "android.permission.CALL_PHONE":              (Severity.HIGH,   "Initiate phone calls"),
    "android.permission.CHANGE_NETWORK_STATE":    (Severity.MEDIUM, "Change network state"),
    "android.permission.SYSTEM_ALERT_WINDOW":     (Severity.HIGH,   "Draw over other apps"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (Severity.CRITICAL, "Accessibility service (keylogger risk)"),
    "android.permission.BIND_DEVICE_ADMIN":       (Severity.CRITICAL, "Device admin — full device control"),
    "android.permission.MASTER_CLEAR":            (Severity.CRITICAL, "Factory reset device"),
}


# ---------------------------------------------------------------------------
# Low-level XML helpers
# ---------------------------------------------------------------------------

def _attr(elem, name: str) -> Optional[str]:
    return elem.get(f"{{{ANDROID_NS}}}{name}") or elem.get(name)


def _bool_attr(elem, name: str, default: Optional[bool] = None) -> Optional[bool]:
    val = _attr(elem, name)
    if val is None:
        return default
    return val.lower() in ("true", "1")


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
# Misconfig detection
# ---------------------------------------------------------------------------

def detect_misconfigs(package: str) -> list[Misconfig]:
    """
    Analyse a decoded AndroidManifest.xml and return a list of Misconfig findings,
    ordered from most to least severe.
    """
    mp = manifest_path(package)
    if not mp:
        return []
    try:
        tree = ET.parse(str(mp))
    except ET.ParseError:
        return []

    root     = tree.getroot()
    app_elem = root.find("application")
    if app_elem is None:
        return []

    findings: list[Misconfig] = []

    # --- Application-level flags ----------------------------------------

    # debuggable=true
    if _bool_attr(app_elem, "debuggable") is True:
        findings.append(Misconfig(
            severity=Severity.CRITICAL,
            title="Application is debuggable",
            detail="android:debuggable=\"true\" allows ADB debugging, memory inspection, and bypass of certificate pinning on non-rooted devices.",
            recommendation="Remove debuggable or set it to false. Never ship a production build with this flag enabled.",
        ))

    # allowBackup=true (default is true pre-API 31, so flag explicit true OR absence on low targetSdk)
    allow_backup = _bool_attr(app_elem, "allowBackup")
    target_sdk   = _sdk_version(root)
    if allow_backup is True or (allow_backup is None and target_sdk < 31):
        findings.append(Misconfig(
            severity=Severity.HIGH,
            title="Full backup enabled (allowBackup)",
            detail=(
                "android:allowBackup=\"true\" (or unset on targetSdk < 31) lets any user with USB debugging "
                "extract app data via `adb backup` without root."
            ),
            recommendation="Set android:allowBackup=\"false\", or use android:fullBackupContent / dataExtractionRules to restrict what is backed up.",
        ))

    # usesCleartextTraffic=true
    if _bool_attr(app_elem, "usesCleartextTraffic") is True:
        findings.append(Misconfig(
            severity=Severity.HIGH,
            title="Cleartext HTTP traffic allowed",
            detail="android:usesCleartextTraffic=\"true\" permits unencrypted HTTP connections, enabling MITM attacks on the same network.",
            recommendation="Remove the flag (defaults to false on API 28+) and enforce HTTPS. Use a Network Security Config to allowlist specific domains if needed.",
        ))

    # networkSecurityConfig — check for cleartext or user-cert trust in the referenced file
    nsc = _attr(app_elem, "networkSecurityConfig")
    if nsc:
        findings.append(Misconfig(
            severity=Severity.INFO,
            title="Custom Network Security Config present",
            detail=f"android:networkSecurityConfig is set ({nsc}). Review the referenced XML for cleartext domains or user-CA trust anchors.",
            recommendation="Ensure the NSC does not allow cleartext traffic or trust user-installed CAs in production builds.",
        ))

    # testOnly=true
    if _bool_attr(app_elem, "testOnly") is True:
        findings.append(Misconfig(
            severity=Severity.HIGH,
            title="testOnly flag is set",
            detail="android:testOnly=\"true\" grants elevated debug/testing privileges and should never appear in a production APK.",
            recommendation="Remove android:testOnly from the manifest before release.",
        ))

    # largeHeap=true (minor privacy / DoS signal)
    if _bool_attr(app_elem, "largeHeap") is True:
        findings.append(Misconfig(
            severity=Severity.INFO,
            title="largeHeap requested",
            detail="android:largeHeap=\"true\" increases memory ceiling. Sensitive data held in memory is at higher risk in a heap-dump scenario.",
            recommendation="Avoid largeHeap unless strictly necessary, and ensure sensitive data is zeroed after use.",
        ))

    # --- Component-level misconfigs ------------------------------------

    all_components = (
        [("activity", el) for el in app_elem.findall("activity") + app_elem.findall("activity-alias")]
        + [("service",  el) for el in app_elem.findall("service")]
        + [("receiver", el) for el in app_elem.findall("receiver")]
        + [("provider", el) for el in app_elem.findall("provider")]
    )

    for tag, el in all_components:
        name        = _resolved_name(el, root.get("package", package))
        has_filter  = bool(el.findall("intent-filter"))
        exported    = _is_exported(el, has_filter)
        permission  = _attr(el, "permission")

        # Exported component with no permission guard
        if exported and not permission:
            severity = Severity.HIGH if tag in ("service", "provider") else Severity.MEDIUM
            findings.append(Misconfig(
                severity=severity,
                title=f"Exported {tag} with no permission",
                detail=f"{name} is exported but declares no android:permission, making it accessible to any app on the device.",
                recommendation=f"Add android:permission to {name} or set android:exported=\"false\" if external access is unintended.",
            ))

        # Provider-specific checks
        if tag == "provider" and exported:
            if _bool_attr(el, "grantUriPermissions") is True and not permission:
                findings.append(Misconfig(
                    severity=Severity.HIGH,
                    title="Exported provider with grantUriPermissions and no permission",
                    detail=f"{name} can grant arbitrary URI access to other apps without requiring a permission, risking data leakage.",
                    recommendation="Restrict grantUriPermissions with <grant-uri-permission> path filters, or require a read/write permission.",
                ))
            read_perm  = _attr(el, "readPermission")
            write_perm = _attr(el, "writePermission")
            if exported and not read_perm and not write_perm and not permission:
                findings.append(Misconfig(
                    severity=Severity.HIGH,
                    title="Exported provider with no read/write permissions",
                    detail=f"{name} is exported without readPermission or writePermission — any app can read/write its data.",
                    recommendation="Set android:readPermission and android:writePermission, or restrict export.",
                ))

        # Exported receiver without permission — intent injection risk
        if tag == "receiver" and exported and not permission:
            findings.append(Misconfig(
                severity=Severity.MEDIUM,
                title="Exported broadcast receiver with no permission",
                detail=f"{name} can receive broadcasts from any app, potentially enabling intent injection or logic abuse.",
                recommendation="Require a custom signature-level permission on the receiver, or restrict it to internal broadcasts.",
            ))

        # launchMode singleInstance / singleTask — task hijacking
        if tag == "activity":
            launch_mode = _attr(el, "launchMode")
            if launch_mode in ("singleInstance", "singleTask"):
                # singleInstance is always high-risk; singleTask is high-risk when exported
                severity = Severity.HIGH if (launch_mode == "singleInstance" or exported) else Severity.MEDIUM
                findings.append(Misconfig(
                    severity=severity,
                    title=f"Task hijacking risk — launchMode=\"{launch_mode}\"",
                    detail=(
                        f"{name} uses android:launchMode=\"{launch_mode}\". "
                        f"{'singleInstance places the activity in its own isolated task, meaning any app that sends a matching intent can inject itself into the back-stack and intercept the user navigation flow.' if launch_mode == 'singleInstance' else 'singleTask reuses an existing task if one matches, allowing a malicious app to start this activity and sit on top of the legitimate task, creating a UI spoofing or phishing opportunity.'} "
                        f"{'The activity is also exported, making it directly reachable by third-party apps.' if exported else 'The activity is not exported, but a malicious app with a matching taskAffinity can still trigger hijacking via implicit intents if intent-filters are present.'}"
                    ),
                    recommendation=(
                        "Prefer the default launchMode (\"standard\") or \"singleTop\" for sensitive screens. "
                        "If singleTask/singleInstance is required, set android:taskAffinity=\"\" to prevent affinity-based hijacking, "
                        "verify callers with getCallingPackage() or a signature-level permission, "
                        "and ensure the activity does not display sensitive data before authenticating the caller."
                    ),
                ))

    # --- Dangerous permissions ----------------------------------------

    declared_perms = [
        _attr(p, "name") for p in root.findall("uses-permission") if _attr(p, "name")
    ]
    for perm in declared_perms:
        if perm in DANGEROUS_PERMISSIONS:
            sev, label = DANGEROUS_PERMISSIONS[perm]
            findings.append(Misconfig(
                severity=sev,
                title=f"Dangerous permission declared: {label}",
                detail=f"{perm} grants access to sensitive device capabilities.",
                recommendation="Verify this permission is strictly necessary. If so, handle the data it exposes with care and explain the usage to users.",
            ))

    # --- Sort by severity ---------------------------------------------

    _order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.INFO: 3}
    findings.sort(key=lambda m: _order[m.severity])
    return findings


def format_misconfigs(package: str) -> str:
    """Return a human-readable security report for the given package's manifest."""
    findings = detect_misconfigs(package)
    if not findings:
        return f"✅ No manifest misconfigurations detected for {package}."

    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    header = (
        f"🔍 Manifest Security Report — {package}\n"
        f"{'═'*60}\n"
        f"  🔴 Critical: {counts[Severity.CRITICAL]}  "
        f"🟠 High: {counts[Severity.HIGH]}  "
        f"🟡 Medium: {counts[Severity.MEDIUM]}  "
        f"🔵 Info: {counts[Severity.INFO]}\n"
        f"{'─'*60}"
    )
    lines = [header]
    for i, m in enumerate(findings, 1):
        icon = SEVERITY_ICON[m.severity]
        lines.append(f"\n[{i}] {icon} {m.severity.value} — {m.title}")
        lines.append(f"    Detail: {m.detail}")
        lines.append(f"    Fix:    {m.recommendation}")
    lines.append(f"\n{'═'*60}")
    lines.append(f"  {len(findings)} finding(s) total.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Formatting helpers
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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolved_name(elem, package: str) -> str:
    name = _attr(elem, "name") or ""
    if name.startswith("."):
        return package + name
    if "." not in name and name:
        return package + "." + name
    return name or "(unnamed)"


def _sdk_version(root) -> int:
    """Return targetSdkVersion as int, defaulting to 1 if absent."""
    sdk_elem = root.find("uses-sdk")
    if sdk_elem is None:
        return 1
    val = _attr(sdk_elem, "targetSdkVersion")
    try:
        return int(val)
    except (TypeError, ValueError):
        return 1
