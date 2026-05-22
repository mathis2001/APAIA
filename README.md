# 🤖 Android Pentest AI Assistant (APAIA) MCP Server

Android Pentest AI Assistant (APAIA) is an MCP server for Claude Desktop that was specifically created for pentesting purposes and aims to provide assistance for recon and static code analysis using ADB and JADX.

---

## Prerequisites

- Python 3.10+
- `adb` in PATH (Android SDK platform-tools)
- `jadx` — https://github.com/skylot/jadx/releases
- Android device or emulator connected
- Claude
---

## Installation

```bash
git clone https://github.com/mathis2001/APAIA

cd APAIA
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Claude Desktop Configuration

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "android-pentest": {
      "command": "/ABSOLUTE/PATH/APAIA/.venv/bin/python",
      "args": ["/ABSOLUTE/PATH/APAIA/server.py"],
      "env": {
        "JADX_PATH": "/usr/local/bin/jadx",
        "ANDROID_PENTEST_WORKDIR": "/tmp/android-pentest"
      }
    }
  }
}
```

> `JADX_PATH` — only needed if jadx is not in PATH  
> `ANDROID_PENTEST_WORKDIR` — where pulled APKs and jadx output are stored (default: `~/.android-pentest`)

---

## Tool Reference

### 🔍 Device & Package
| Tool | Description |
|------|-------------|
| `list_devices` | Connected ADB devices |
| `device_info` | OS, arch, SELinux, root |
| `list_packages` | Filter: all/system/third-party |
| `app_info` | Version, SDK, paths, debuggable |

### 📦 APK + JADX Static Analysis
| Tool | Description |
|------|-------------|
| `pull_apk` | Pull APK(s) from device. Handles split APKs. |
| `jadx_decompile` | Decompile: `manifest_only` (5s, recon) or `full` (30–300s, source) |
| `jadx_get_manifest` | View decoded AndroidManifest.xml |
| `jadx_list_files` | Browse decompiled files (filter by path/extension) |
| `jadx_read_file` | Read a specific Java/XML file |
| `jadx_search` | Grep across all Java sources (secrets, URLs, crypto…) |
| `jadx_status` | Show what's been pulled/decompiled |

### ⚡ Component Enumeration (manifest-backed)
| Tool | Description |
|------|-------------|
| `list_exported_components` | Exported activities/services/receivers/providers — parsed from real manifest |
| `list_deeplinks` | URI schemes + intent filter data from manifest |
| `list_permissions` | Declared + runtime-granted permissions |
| `list_content_providers` | Providers with authorities, permissions, grantUriPermissions |

### 📤 Intent Interaction
| Tool | Description |
|------|-------------|
| `send_intent` | am start/broadcast/startservice with typed extras |
| `open_deeplink` | Open a URI on device |

### 👆 UI Automation
| Tool | Description |
|------|-------------|
| `ui_tap` / `ui_swipe` | Touch interactions |
| `ui_input_text` | Type into focused field |
| `ui_keyevent` | ENTER=66, DEL=67, BACK=4, TAB=61 |
| `ui_clear_field` | Select-all + delete |
| `take_screenshot` | Screen capture to local PNG |
| `dump_ui_hierarchy` | uiautomator XML dump (find coordinates) |

### 🎯 PoC Attacks
| Tool | Description |
|------|-------------|
| `poc_bruteforce_login` | UI bruteforce with success/failure detection |
| `poc_fuzz_deeplinks` | Deep link fuzzer with `{FUZZ}` template |
| `poc_intent_fuzzer` | Batch intent sending with varying extras |
| `poc_query_content_provider` | Unauth access + SQLi testing |
| `poc_deeplink_hijacking` | Deeplink Hijacking PoC testing |

### 📋 Runtime Analysis
| Tool | Description |
|------|-------------|
| `capture_logcat` | Timed logcat (filter by tag/package) |
| `list_app_files` | Browse app data dir (run-as / root) |
| `pull_app_file` | Pull file from device |

---

## Pentest Workflow

```
# 1. Recon
list_packages(filter='third-party')
app_info('com.example.app')

# 2. Pull + decode (fast path — manifest only)
pull_apk('com.example.app')
jadx_decompile('com.example.app', mode='manifest_only')

# 3. Attack surface mapping
list_exported_components('com.example.app')
list_deeplinks('com.example.app')
list_content_providers('com.example.app')
list_permissions('com.example.app')

# 4. Full source analysis (when needed)
jadx_decompile('com.example.app', mode='full')
jadx_search('com.example.app', pattern='API_KEY|secret|password', context_lines=5)
jadx_search('com.example.app', pattern='setJavaScriptEnabled')
jadx_search('com.example.app', pattern='MODE_WORLD_READABLE')
jadx_search('com.example.app', pattern='SELECT.*FROM', file_filter='*.java')
jadx_list_files('com.example.app', extension='java', path_filter='sources/com/example/auth')
jadx_read_file('com.example.app', 'sources/com/example/LoginActivity.java')

# 5. Interact with components
open_deeplink('myapp://reset?token=INJECT')
send_intent(action='com.example.ADMIN_ACTION', component='com.example/.AdminActivity')
poc_query_content_provider(uri='content://com.example.provider/users')

# 6. UI PoC
take_screenshot()              # → find element positions
dump_ui_hierarchy()            # → get exact coordinates
poc_bruteforce_login(
    username='admin@example.com',
    passwords=['admin','password','1234','test123'],
    username_coords=[540,800], password_coords=[540,960], submit_coords=[540,1100],
    success_indicator='Dashboard'
)

# 7. Runtime analysis
capture_logcat(package='com.example.app', duration_seconds=10, level='D')
list_app_files('com.example.app', path='/shared_prefs')
pull_app_file(package='com.example.app', remote_path='/data/data/com.example.app/shared_prefs/prefs.xml', local_path='/tmp/prefs.xml')
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JADX_PATH` | `jadx` (from PATH) | Absolute path to jadx binary |
| `ANDROID_PENTEST_WORKDIR` | `~/.android-pentest` | Work directory for APKs and decompiled output |

## Screenshots & Video Records

https://github.com/user-attachments/assets/c9c3da45-78d7-47f4-98ad-e9d7b46b0829

https://github.com/user-attachments/assets/3e67dbd4-9fc7-4f74-8eea-b91b97240e7d

https://github.com/user-attachments/assets/250d6847-c490-42e8-86a0-6dfe8774ee63

<img width="786" height="648" alt="Recon1" src="https://github.com/user-attachments/assets/71f827ef-2481-400e-a80c-67755c807d6b" />
<img width="786" height="648" alt="Recon2" src="https://github.com/user-attachments/assets/2f4edb6e-96b1-4c32-8916-3fc78da76a3a" />
<img width="786" height="648" alt="Recon3" src="https://github.com/user-attachments/assets/87bdf058-b097-439b-a0b1-cf05139611a2" />
<img width="786" height="648" alt="Recon4" src="https://github.com/user-attachments/assets/a0d76417-1e18-4c2c-9608-7e98cfc71037" />
<img width="786" height="648" alt="manifest-audit" src="https://github.com/user-attachments/assets/acec26c4-0b2c-48e8-ba38-a64117ba8b72" />






