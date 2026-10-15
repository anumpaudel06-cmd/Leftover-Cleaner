# Leftover-Cleaner 🛡️

**A Surgical, Open-Source Windows 10/11 Utility for Orphan Application Residues, Leftover Registry Keys, and System Cache Reclamation.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6.svg)](https://microsoft.com)
[![Python Version](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![UI: CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter%20Fluent-202020.svg)](https://github.com/TomSchimansky/CustomTkinter)
[![Build Status](https://github.com/anumpaudel06-cmd/Leftover-Cleaner/actions/workflows/build-exe.yml/badge.svg)](https://github.com/anumpaudel06-cmd/Leftover-Cleaner/actions)
[![Latest Release](https://img.shields.io/github/v/release/anumpaudel06-cmd/Leftover-Cleaner?color=brightgreen&label=Download%20.EXE)](https://github.com/anumpaudel06-cmd/Leftover-Cleaner/releases/latest)
[![Safety Engine](https://img.shields.io/badge/Safety%20Engine-100%25%20Verified-brightgreen.svg)](#safety-guarantees)

---

## 📥 Download Standalone Executable (.exe)

You do **not** need Python installed to run Leftover-Cleaner on Windows:

👉 **[Download the Latest Standalone `Leftover-Cleaner.exe`](https://github.com/anumpaudel06-cmd/Leftover-Cleaner/releases/latest)**

*Simply download `Leftover-Cleaner.exe` and run it. The app will automatically request Windows Administrator elevation via UAC and launch the modern Windows 11 Fluent interface.*

---

## 📌 Executive Summary

Traditional uninstaller routines on Microsoft Windows notoriously leave gigabytes of residual data: orphaned `%AppData%` and `%ProgramData%` configuration folders, leftover vendor registry hives under `HKCU\Software` and `HKLM\Software`, dead startup run items, and bloated crash/update caches.

Most third-party "cleaners" are aggressive, opaque, or risk OS destabilization by touching active system libraries. **Leftover-Cleaner** was engineered from the ground up as a surgical, transparent, and strictly safeguarded open-source utility designed to clean disk clutter **without ever risking OS stability**.

---

## 🏗️ Architecture & Modules

Leftover-Cleaner is built in Python 3.11+ using native Windows APIs (`ctypes`, `winreg`, Windows Shell32, and PowerShell WMI services), wrapped in a Windows 11 Fluent interface:

```
Leftover-Cleaner/
├── .github/workflows/
│   └── build-exe.yml         # Automated GitHub Actions workflow compiling Windows .EXE
├── app.manifest              # UAC elevation ('requireAdministrator') & PerMonitorV2 DPI
├── build_exe.bat             # Standalone PyInstaller compilation script
├── requirements.txt          # Python dependencies
├── docs/
│   └── ARCHITECTURE.md       # Deep-dive architectural specification
├── tests/
│   └── test_safety.py        # Automated unit verification for safety whitelists
└── src/
    ├── main.py               # UAC check, auto-elevation, DPI context, CLI dispatch
    ├── core/
    │   ├── safety_engine.py  # Whitelist engine, restore point API, .reg exporter
    │   ├── orphan_scanner.py # 32/64-bit Registry cross-referencing & residue detection
    │   ├── registry_cleaner.py# Safe residual keys, MUI cache, dead startup entries
    │   └── junk_cleaner.py   # Windows Temp, Prefetch, crash dumps, lock handler
    └── ui/
        └── app_window.py     # CustomTkinter Windows 11 Fluent UI & telemetry drawer
```

---

## 🛡️ Safety Guarantees & Anti-Corruption Guardrails

| Guardrail | Mechanism | Protection Outcome |
| :--- | :--- | :--- |
| **System Path Blacklist** | Canonical path normalization (`os.path.realpath`) | `System32`, `SysWOW64`, `WinSxS`, `Boot`, `Drivers`, user profile roots can **never** be targeted. |
| **Registry Hive Immunity** | Case-insensitive token boundary matching | `Microsoft`, `Classes`, `SAM`, `SECURITY`, `SYSTEM` hives are completely immutable. |
| **Pre-Purge Restore Point** | Native PowerShell `Checkpoint-Computer` invocation | Generates an instantaneous Windows System Restore checkpoint before modifications. |
| **Automated `.reg` Backup** | Native `reg export` execution to `LeftoverCleaner_Backups/` | Every deleted or altered registry key is saved into a dated `.reg` file for 1-click restore. |
| **Quarantine Isolation** | Staged file relocation with JSON manifest | Deleted folders are held in local quarantine first, allowing immediate 1-click rollback. |
| **Dry-Run Inspection** | Read-only scan mode enabled by default | Users inspect path, disk size, and confidence score before any file operation executes. |

---

## 🚀 Building from Source

### Prerequisites
- Windows 10 or 11 (64-bit recommended)
- Python 3.11+ installed and added to `PATH`

### 1-Click Compilation
Run the included build batch script:
```cmd
build_exe.bat
```

### Manual Compilation
```cmd
# 1. Create and activate a clean virtual environment
python -m venv venv
venv\Scripts\activate

# 2. Install requirements
pip install -r requirements.txt

# 3. Run safety verification tests
python -m unittest discover -s tests -p "test_*.py"

# 4. Compile with PyInstaller & Administrator Manifest
pyinstaller --onefile --windowed --clean --name="Leftover-Cleaner" --manifest="app.manifest" --add-data="src;src" --collect-all="customtkinter" src\main.py
```
The compiled binary will be placed in `dist\Leftover-Cleaner.exe`.

---

## 🖥️ Command Line Usage (Headless & Automation)

Leftover-Cleaner can be executed in automated environments or via PowerShell scripts:

```cmd
# Run a dry-run scan (Preview only, no deletions)
Leftover-Cleaner.exe --dry-run

# Run scan and export detected items to JSON
Leftover-Cleaner.exe --scan-only --export report.json

# Run safe cleanup without creating a restore point (e.g. in VMs)
Leftover-Cleaner.exe --no-restore-point
```

---

## ⚖️ Disclaimer

Leftover-Cleaner is an open-source administrative utility. While it implements rigorous multi-tiered safety guardrails, users should always ensure periodic offline backups of critical data. Distributed under the MIT License.
