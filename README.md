# GhostPurge 🛡️

**A Surgical, Open-Source Windows 10/11 Utility for Orphan Application Residues, Leftover Registry Keys, and System Cache Reclamation.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6.svg)](https://microsoft.com)
[![Python Version](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![UI: CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter%20Fluent-202020.svg)](https://github.com/TomSchimansky/CustomTkinter)
[![Build: Standalone EXE](https://img.shields.io/badge/Packaging-PyInstaller%20Single--EXE-success.svg)](#compilation-guide)
[![Safety Engine](https://img.shields.io/badge/Safety%20Engine-100%25%20Verified-brightgreen.svg)](#safety-guarantees)

---

## 📌 Executive Summary

Traditional uninstaller routines on Microsoft Windows notoriously leave gigabytes of residual data: orphaned `%AppData%` and `%ProgramData%` configuration folders, leftover vendor registry hives under `HKCU\Software` and `HKLM\Software`, dead startup run items, and bloated crash/update caches.

Most third-party "cleaners" are aggressive, opaque, or risk OS destabilization by touching active system libraries. **GhostPurge** was engineered from the ground up as a surgical, transparent, and strictly safeguarded open-source utility designed to clean disk clutter **without ever risking OS stability**.

---

## 🏗️ Architecture & Modules

GhostPurge is built in modern Python 3.11+ using native Windows APIs (`ctypes`, `winreg`, Windows Shell32, and PowerShell WMI services), wrapped in a Windows 11 Fluent interface:

```
ghostpurge/
├── app.manifest              # UAC elevation ('requireAdministrator') & PerMonitorV2 DPI
├── build_exe.bat             # Standalone PyInstaller compilation script
├── requirements.txt          # Python dependencies
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

### Key Technical Subsystems

1. **UAC Auto-Elevation (`src/main.py`)**:
   Automatically detects running privilege level via `ctypes.windll.shell32.IsUserAnAdmin()`. If not elevated, it cleanly respawns itself under the Windows `runas` verb, ensuring access to `HKLM` and System Temp without permission drops.
2. **Orphan Cross-Referencing Engine (`src/core/orphan_scanner.py`)**:
   Enumerates installed software signatures across both 64-bit and 32-bit registry uninstall hives:
   - `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`
   - `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`
   Cross-references directories in `%AppData%`, `%LocalAppData%`, `%ProgramData%`, and `%ProgramFiles%`. Any directory whose publisher or application tokens no longer correspond to registered installations or active system services is flagged with a granular confidence score.
3. **Safe Registry Worker (`src/core/registry_cleaner.py`)**:
   Restricted strictly to user and machine application roots (`HKCU\Software`, `HKLM\Software`). Scans for abandoned application keys, dead MUI cache paths, and invalid shell association residues. System-critical roots (`Microsoft`, `Classes`, `Services`, `Policies`) are hard-blocked by the safety engine.
4. **Resilient System Junk Cleaner (`src/core/junk_cleaner.py`)**:
   Safely empties temporary cache roots (`C:\Windows\Temp`, `%LocalAppData%\Temp`, Windows Update downloads, `.dmp` crash reports). Handles files currently locked by background services gracefully using `PermissionError` and `WinError 32` interception—no crashes or hang states.

---

## 🛡️ Safety Guarantees & Anti-Corruption Guardrails

| Guardrail | Mechanism | Protection Outcome |
| :--- | :--- | :--- |
| **System Path Blacklist** | Canonical path normalization (`os.path.realpath`) | `System32`, `SysWOW64`, `WinSxS`, `Boot`, `Drivers`, user documents can **never** be targeted. |
| **Registry Hive Immunity** | Case-insensitive token boundary matching | `Microsoft`, `Classes`, `SAM`, `SECURITY`, `SYSTEM` hives are completely immutable. |
| **Pre-Purge Restore Point** | Native PowerShell `Checkpoint-Computer` invocation | Generates an instantaneous Windows System Restore checkpoint before modifications. |
| **Automated `.reg` Backup** | Native `reg export` execution to `GhostPurge_Backups/` | Every deleted or altered registry key is saved into a dated `.reg` file for 1-click restore. |
| **Quarantine Isolation** | Staged file relocation with JSON manifest | Deleted folders are held in local quarantine first, allowing immediate 1-click rollback. |
| **Dry-Run Inspection** | Read-only scan mode enabled by default | Users inspect path, disk size, and confidence score before any file operation executes. |

---

## 🚀 Compilation & Packaging Guide

To package GhostPurge into a standalone, single-file Windows executable:

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
pyinstaller --onefile --windowed --clean --name="GhostPurge" --manifest="app.manifest" --add-data="src;src" --collect-all="customtkinter" src\main.py
```
The compiled binary will be placed in `dist\GhostPurge.exe`.

---

## 🖥️ Command Line Usage (Headless & Automation)

GhostPurge can be executed in automated environments or via PowerShell scripts:

```cmd
# Run a dry-run scan (Preview only, no deletions)
GhostPurge.exe --dry-run

# Run scan and export detected items to JSON
GhostPurge.exe --scan-only --export report.json

# Run safe cleanup without creating a restore point (e.g. in VMs)
GhostPurge.exe --no-restore-point
```

---

## ⚖️ Disclaimer

GhostPurge is an open-source administrative utility. While it implements rigorous multi-tiered safety guardrails, users should always ensure periodic offline backups of critical data. Distributed under the MIT License.
