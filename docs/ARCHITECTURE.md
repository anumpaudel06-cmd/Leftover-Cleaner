# Architecture & Technical Deep-Dive

**Leftover-Cleaner** is designed with a modular, layered architecture to guarantee isolation between detection heuristics and physical file/registry deletion routines.

```
┌────────────────────────────────────────────────────────┐
│                   CustomTkinter UI                     │
│         (Windows 11 Fluent Theme / Controls)           │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│                   Supervisor (main.py)                 │
│      - UAC Elevation Check (ctypes.IsUserAnAdmin)      │
│      - High-DPI Context (PerMonitorV2)                 │
└──────────────────────────┬─────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
│   Orphan    │     │  Registry   │     │    Junk     │
│   Scanner   │     │   Cleaner   │     │   Cleaner   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│                 Safety Engine (Core)                   │
│   - System Path Blacklist (System32, WinSxS, Drivers)  │
│   - Protected Registry Hives (Microsoft, SAM, System)  │
│   - Windows System Restore Point (Checkpoint-Computer) │
│   - .REG Backup Exporter (reg.exe export)              │
│   - Quarantine Manager (Local rollback stage)          │
└────────────────────────────────────────────────────────┘
```

---

## 1. UAC Self-Elevation Mechanism

Windows registry keys under `HKLM\Software` and system directories like `C:\Windows\Temp` require elevated administrative access (`SeBackupPrivilege` and `SeRestorePrivilege`).

On startup, `src/main.py` invokes:
```python
ctypes.windll.shell32.IsUserAnAdmin()
```
If this returns 0 (standard user):
```python
ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
```
The child process inherits full token privileges while the unprivileged parent process cleanly terminates.

---

## 2. Orphan Cross-Referencing Algorithm

Windows maintains installed software keys in three main registry branches:
1. `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` (64-bit native)
2. `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (32-bit apps on 64-bit OS)
3. `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall` (User-level per-user apps)

The `OrphanScanner` reads all subkeys using `winreg.KEY_WOW64_64KEY` and `winreg.KEY_WOW64_32KEY`. It normalizes `DisplayName`, `Publisher`, and `InstallLocation` into token sets.

When scanning `%AppData%` or `%ProgramData%`:
- If the folder token matches none of the installed software signatures or publisher namespaces, it is tagged as an orphan candidate.
- Folder contents are inspected: if the folder contains only configuration or log files, it receives a **95% Confidence Score** ("Safe to remove"). If it contains active binary libraries (`.dll`, `.exe`), it receives a **65% Confidence Score** ("Review needed").

---

## 3. Active Process Sharing Violation Handling

Operating system processes frequently lock log files in `Temp`. Traditional scripts crash when encountering `WinError 32` (`ERROR_SHARING_VIOLATION`).

The `JunkCleaner` wraps deletion routines with fine-grained exception handling:
```python
except (PermissionError, OSError) as ex:
    skipped.append(f"{child.name} (locked by process)")
    continue
```
The scan and purge proceed without interruption, and locked files are reported cleanly in the audit log.
