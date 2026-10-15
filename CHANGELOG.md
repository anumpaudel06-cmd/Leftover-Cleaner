# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-15

### Added
- **Self-Elevation**: Integrated Windows UAC detection (`ctypes.windll.shell32.IsUserAnAdmin`) and automated `runas` elevation.
- **Orphan File & Directory Scanner**:
  - Scanning targets: `%AppData%` (Roaming & Local), `%LocalAppData%\Programs`, `%ProgramData%`, `%ProgramFiles%`, and `%ProgramFiles(x86)%`.
  - Registry Uninstall cross-referencing across both 32-bit and 64-bit hives (`HKLM` and `HKCU`).
- **Registry Cleaner (Safe Heuristics)**:
  - Scanning `HKCU\Software` and `HKLM\Software` for uninstalled software residual keys.
  - Obsolete Windows MUI Cache reference detector.
  - Missing executable startup run item cleaner.
- **System Junk & Cache Cleaner**:
  - Cleaners for `C:\Windows\Temp`, `%LocalAppData%\Temp`, Windows Update downloads, and crash dumps (`.dmp`).
  - Graceful active process file lock bypass (`PermissionError` & `WinError 32`).
- **Safety Engine**:
  - Protected whitelist engine blocking `System32`, `WinSxS`, `Drivers`, `HKLM\Software\Microsoft`, etc.
  - Automated Windows System Restore Point generation via PowerShell `Checkpoint-Computer`.
  - Automated `.reg` backup exports to dedicated backup folder.
  - Quarantine directory manager with 1-click restore capability.
  - Dry-Run preview mode enabled by default.
- **Packaging & CI/CD**:
  - Native Windows Application Manifest (`app.manifest`) for UAC elevation and PerMonitorV2 High-DPI.
  - PyInstaller compilation script (`build_exe.bat`).
  - Automated GitHub Actions workflow compiling standalone `Leftover-Cleaner.exe` on Windows runners.
