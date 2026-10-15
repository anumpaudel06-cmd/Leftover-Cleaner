# Security Policy & Windows Safety Guarantees

## 🛡️ Safety Philosophy

**Leftover-Cleaner** is built with multiple defense-in-depth security layers to ensure the host operating system is protected:

1. **Strict System Whitelist / Blacklist Engine**:
   - Hardcoded, non-overridable path immunity for `C:\Windows\System32`, `SysWOW64`, `WinSxS`, `Boot`, `Recovery`, and active user profile roots.
   - Registry hive immunity for `Microsoft`, `Classes`, `Services`, `SAM`, `SECURITY`, `SYSTEM`, and `Policies`.
2. **Automated Windows System Restore Points**:
   - Calls the Windows WMI System Restore API via PowerShell (`Checkpoint-Computer`) prior to wide file removals.
3. **Automatic `.reg` Backups**:
   - Backs up targeted registry keys into dated `.reg` files in `%LocalAppData%\LeftoverCleaner_Backups\Registry\` before deletion.
4. **Quarantine Isolation**:
   - Staged folder relocation with manifest allowing 1-click restore.

---

## 🔒 Reporting a Vulnerability

If you discover a security vulnerability or an edge case where an operating system component could potentially be targeted:

1. **Do not open a public issue.**
2. Please open a Private Security Advisory directly through GitHub or contact the maintainers with:
   - Specific Windows version / build
   - Path or registry key affected
   - Reproduction steps
3. We take all reports seriously and aim to address confirmed safety issues within 48 hours.
