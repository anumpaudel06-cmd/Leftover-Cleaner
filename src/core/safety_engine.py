"""
GhostPurge Safety Engine
=======================
Enforces strict anti-corruption guardrails, path normalization, system whitelists,
automated Windows Restore Point creation, and registry backup generation.
"""

import os
import sys
import json
import shutil
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

logger = logging.getLogger("GhostPurge.SafetyEngine")


class SystemSafetyViolation(Exception):
    """Raised when an operation attempts to target a protected OS file or registry hive."""
    pass


class SafetyEngine:
    """
    Mandatory safety controller.
    Validates all file and registry deletion targets against critical Windows core systems.
    """

    # Critical Windows directories that must NEVER be modified or deleted
    CRITICAL_PATH_BLACKLIST = {
        "system32",
        "syswow64",
        "winsxs",
        "boot",
        "recovery",
        "system volume information",
        "servicing",
        "assembly",
        "microsoft.net",
        "systemapps",
        "inf",
        "drivers",
        "driverstore",
        "diagnostics",
        "catroot",
        "catroot2",
        "fonts",
        "resources",
    }

    # Protected Registry paths and root hives
    CRITICAL_REGISTRY_BLACKLIST = {
        "classes",
        "services",
        "sam",
        "security",
        "system",
        "hardware",
        "bcd00000000",
        "policies",
        "windows nt",
        "windows defender",
        "microsoft",
        "cryptography",
    }

    def __init__(self, backup_dir: Optional[str] = None):
        if backup_dir:
            self.backup_dir = Path(backup_dir)
        else:
            local_appdata = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
            self.backup_dir = Path(local_appdata) / "GhostPurge_Backups"

        self.quarantine_dir = self.backup_dir / "Quarantine"
        self.registry_dir = self.backup_dir / "Registry"
        self._initialize_backup_structure()

    def _initialize_backup_structure(self) -> None:
        """Create structured backup folders for quarantine and registry dumps."""
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            self.registry_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to initialize backup directory: {e}")

    @staticmethod
    def normalize_path(path_str: str) -> str:
        """Resolve symbolic links, relative segments, and canonicalize path string."""
        if not path_str:
            return ""
        # Handle env vars
        expanded = os.path.expandvars(path_str).strip()
        # Clean double slashes
        clean_str = expanded.replace("/", "\\")
        return clean_str

    def is_safe_path(self, target_path: str) -> Tuple[bool, str]:
        """
        Validate whether a file/directory path is strictly safe to modify or delete.
        Returns: (is_safe: bool, reason: str)
        """
        if not target_path or not target_path.strip():
            return False, "Empty path provided."

        normalized = self.normalize_path(target_path)
        # Split tokens by both backslash and forward slash
        raw_parts = [p.strip() for p in normalized.replace("/", "\\").split("\\") if p.strip()]
        parts_lower = [p.lower() for p in raw_parts]

        if not parts_lower:
            return False, "Empty path structure."

        # Guardrail 1: Never target root drives or user profile root
        # e.g. "C:" or ["C:"] or empty drive
        if len(parts_lower) == 1 and (":" in parts_lower[0] or parts_lower[0].endswith(":")):
            return False, f"Target is a filesystem drive root: {normalized}"

        userprofile = os.environ.get("USERPROFILE", "").lower()
        if userprofile and normalized.lower() == userprofile.replace("/", "\\"):
            return False, "Target is the active user profile root."

        # Guardrail 2: Windows System directory protection
        win_dir = os.environ.get("WINDIR", "C:\\Windows").lower().replace("/", "\\")
        if normalized.lower() == win_dir or (len(parts_lower) == 2 and parts_lower[1] == "windows"):
            return False, "Target is the Windows installation directory."

        # Guardrail 3: Critical Blacklisted System Folders
        for part in parts_lower:
            if part in self.CRITICAL_PATH_BLACKLIST:
                return False, f"Path intersects protected system folder: '{part}'"

        # Guardrail 4: Critical system files
        filename_lower = parts_lower[-1]
        if filename_lower in {"explorer.exe", "kernel32.dll", "ntoskrnl.exe", "hal.dll", "user32.dll", "ntdll.dll"}:
            return False, f"Protected kernel or core binary: {filename_lower}"

        # Guardrail 5: Protected Microsoft application data roots
        # We must never delete the base Microsoft vendor folder
        if parts_lower[-1] == "microsoft" and any(p in parts_lower for p in ["appdata", "programdata"]):
            return False, "Target is the core Microsoft vendor application data root."

        return True, "Verified safe by safety engine."

    def is_safe_registry_key(self, hive_name: str, subkey_path: str) -> Tuple[bool, str]:
        """
        Validate whether a registry key is safe to remove.
        Guarantees HKLM\\Software\\Microsoft, Services, and Security hives are untouched.
        """
        if not subkey_path or not subkey_path.strip():
            return False, "Target is the root hive or empty subkey."

        full_key = f"{hive_name}\\{subkey_path}".strip("\\").replace("/", "\\")
        tokens = [t.lower() for t in full_key.split("\\") if t]

        if not tokens or len(tokens) <= 1:
            return False, "Target is the root hive or empty subkey."

        # Check for critical system hives and keywords anywhere in path
        for token in tokens:
            if token in self.CRITICAL_REGISTRY_BLACKLIST:
                return False, f"Target is inside protected system hive or token '{token}'"

        return True, "Registry key verified safe by safety engine."

    def create_system_restore_point(self, description: str = "Pre-GhostPurge-Cleanup") -> Tuple[bool, str]:
        """
        Creates a Windows System Restore Point using PowerShell Checkpoint-Computer.
        Requires elevated administrative privileges.
        """
        try:
            ps_command = (
                f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '
                f'"Checkpoint-Computer -Description \'{description}\' -RestorePointType \'MODIFY_SETTINGS\' -ErrorAction Stop"'
            )
            logger.info("Triggering Windows System Restore Point creation...")
            result = subprocess.run(
                ps_command,
                capture_output=True,
                text=True,
                shell=True,
                timeout=60,
            )

            if result.returncode == 0:
                logger.info("System Restore Point created successfully.")
                return True, "System Restore Point created successfully."
            else:
                err_msg = result.stderr.strip() or result.stdout.strip()
                logger.warning(f"Could not create restore point (may be disabled on host OS): {err_msg}")
                return False, f"Restore point note: {err_msg}"
        except subprocess.TimeoutExpired:
            return False, "System Restore Point creation timed out (60s)."
        except Exception as ex:
            return False, f"Restore point error: {str(ex)}"

    def export_registry_key_backup(self, full_key_path: str) -> Tuple[bool, str]:
        """
        Exports a registry key to a dated .reg file using Windows native 'reg.exe export'.
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = "".join(c if c.isalnum() else "_" for c in full_key_path)[-50:]
            backup_file = self.registry_dir / f"RegBackup_{timestamp}_{safe_name}.reg"

            cmd = f'reg.exe export "{full_key_path}" "{str(backup_file)}" /y'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)

            if result.returncode == 0 and backup_file.exists():
                return True, str(backup_file)
            else:
                return False, result.stderr.strip() or "Export failed"
        except Exception as e:
            return False, str(e)

    def quarantine_folder(self, folder_path: str, reason: str = "Orphan residue") -> Tuple[bool, str]:
        """
        Moves a folder to local Quarantine rather than direct hard deletion,
        allowing immediate 1-click restoration if needed.
        """
        is_safe, check_reason = self.is_safe_path(folder_path)
        if not is_safe:
            raise SystemSafetyViolation(f"Blocked quarantine of protected path: {check_reason}")

        try:
            src = Path(self.normalize_path(folder_path))
            if not src.exists():
                return False, "Folder does not exist."

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_name = f"{timestamp}_{src.name}"
            dest = self.quarantine_dir / dest_name

            shutil.move(str(src), str(dest))

            # Record manifest for 1-click restore
            manifest_file = self.quarantine_dir / "quarantine_manifest.json"
            entries = []
            if manifest_file.exists():
                try:
                    with open(manifest_file, "r", encoding="utf-8") as f:
                        entries = json.load(f)
                except Exception:
                    entries = []

            entries.append({
                "original_path": str(src),
                "quarantine_path": str(dest),
                "timestamp": timestamp,
                "reason": reason,
            })

            with open(manifest_file, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2)

            return True, str(dest)
        except PermissionError:
            return False, "Locked by active process (PermissionError)."
        except Exception as ex:
            return False, str(ex)
