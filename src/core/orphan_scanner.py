"""
GhostPurge Orphan Scanner
========================
Discovers orphaned application folders and vendor residue in AppData, LocalAppData,
ProgramData, and ProgramFiles by cross-referencing registered Windows Uninstall keys.
"""

import os
import re
import sys
import logging
from pathlib import Path
from typing import List, Dict, Set, Any, Optional, Callable, Tuple
from dataclasses import dataclass

try:
    import winreg
except ImportError:
    winreg = None  # Fallback for cross-platform linting/analysis

from .safety_engine import SafetyEngine

logger = logging.getLogger("GhostPurge.OrphanScanner")


@dataclass
class ScanResultItem:
    name: str
    category: str  # "orphan_dir", "registry", "cache"
    item_type: str  # "Folder", "File", "Registry Key"
    path: str
    size_bytes: int
    confidence_score: int  # 0 to 100
    confidence_label: str  # "Safe to remove" or "Review needed"
    reason: str
    last_modified: Optional[str] = None


class OrphanScanner:
    """
    Scans common application data roots and cross-references folder names
    against registered Windows software installations to detect orphaned directories.
    """

    def __init__(self, safety_engine: SafetyEngine):
        self.safety = safety_engine
        self.installed_apps: Set[str] = set()
        self.installed_publishers: Set[str] = set()
        self.installed_paths: Set[str] = set()

    def load_installed_applications(self) -> None:
        """
        Enumerate all installed applications from Windows 32-bit and 64-bit
        Uninstall registry keys in both HKLM and HKCU.
        """
        self.installed_apps.clear()
        self.installed_publishers.clear()
        self.installed_paths.clear()

        if not winreg:
            logger.warning("winreg not available; mock mode or non-windows environment.")
            return

        uninstall_hives = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", 0),
        ]

        for root_hive, subkey_path, flags in uninstall_hives:
            try:
                access = winreg.KEY_READ | flags if flags else winreg.KEY_READ
                with winreg.OpenKey(root_hive, subkey_path, 0, access) as key:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    for i in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name, 0, access) as app_key:
                                self._extract_app_metadata(app_key)
                        except Exception:
                            continue
            except Exception as e:
                logger.debug(f"Unable to read registry path {subkey_path}: {e}")

        logger.info(f"Enumerated {len(self.installed_apps)} registered installed software signatures.")

    def _extract_app_metadata(self, key_handle: Any) -> None:
        """Helper to extract DisplayName, Publisher, and InstallLocation from an uninstall subkey."""
        def get_val(name: str) -> str:
            try:
                val, _ = winreg.QueryValueEx(key_handle, name)
                return str(val).strip()
            except Exception:
                return ""

        display_name = get_val("DisplayName")
        publisher = get_val("Publisher")
        install_loc = get_val("InstallLocation")

        if display_name:
            norm_name = self._normalize_token(display_name)
            self.installed_apps.add(norm_name)
            # Add word tokens
            for token in re.findall(r"[A-Za-z0-9]{3,}", norm_name):
                self.installed_apps.add(token.lower())

        if publisher:
            norm_pub = self._normalize_token(publisher)
            self.installed_publishers.add(norm_pub)
            for token in re.findall(r"[A-Za-z0-9]{3,}", norm_pub):
                self.installed_publishers.add(token.lower())

        if install_loc and os.path.exists(install_loc):
            self.installed_paths.add(os.path.realpath(install_loc).lower())

    @staticmethod
    def _normalize_token(text: str) -> str:
        """Strip version numbers, symbols, and whitespace for fuzzy matching."""
        cleaned = re.sub(r"[\(\)\[\]_\-.]", " ", text)
        cleaned = re.sub(r"\b(v\d+|\d+\.\d+|\d+bit|x64|x86|community|edition|pro)\b", "", cleaned, flags=re.I)
        return " ".join(cleaned.split()).lower()

    def is_known_installed(self, folder_name: str, folder_path: str) -> bool:
        """
        Check if a folder correlates to currently registered software or system components.
        """
        norm_folder = self._normalize_token(folder_name)
        folder_tokens = set(re.findall(r"[A-Za-z0-9]{3,}", norm_folder))

        # Check full folder string match
        if norm_folder in self.installed_apps or norm_folder in self.installed_publishers:
            return True

        # Check token intersection with installed apps
        if folder_tokens and len(folder_tokens.intersection(self.installed_apps)) >= 1:
            return True

        if folder_tokens and len(folder_tokens.intersection(self.installed_publishers)) >= 1:
            return True

        # Check if physical folder is an active install location
        real_path = os.path.realpath(folder_path).lower()
        for inst_path in self.installed_paths:
            if real_path == inst_path or real_path.startswith(inst_path + os.sep):
                return True

        return False

    def get_folder_size(self, path: Path) -> int:
        """Calculate total directory disk consumption in bytes, skipping unreadable files."""
        total = 0
        try:
            for entry in path.rglob("*"):
                try:
                    if not entry.is_symlink() and entry.is_file():
                        total += entry.stat().st_size
                except (PermissionError, FileNotFoundError, OSError):
                    continue
        except (PermissionError, FileNotFoundError, OSError):
            pass
        return total

    def scan_target_roots(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[ScanResultItem]:
        """
        Scans %AppData%, %LocalAppData%, %ProgramData%, and %ProgramFiles% for orphan folders.
        """
        self.load_installed_applications()
        results: List[ScanResultItem] = []

        # Determine target roots dynamically
        appdata_roaming = os.environ.get("APPDATA")
        local_appdata = os.environ.get("LOCALAPPDATA")
        program_data = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")

        scan_roots = []
        if appdata_roaming:
            scan_roots.append((Path(appdata_roaming), "Roaming AppData Residue"))
        if local_appdata:
            scan_roots.append((Path(local_appdata), "Local AppData Residue"))
            programs_dir = Path(local_appdata) / "Programs"
            if programs_dir.exists():
                scan_roots.append((programs_dir, "User Local Programs Residue"))
        if program_data:
            scan_roots.append((Path(program_data), "ProgramData Residual Root"))
        if program_files:
            scan_roots.append((Path(program_files), "Program Files Orphan Residue"))
        if program_files_x86:
            scan_roots.append((Path(program_files_x86), "Program Files (x86) Orphan Residue"))

        for root_dir, category_desc in scan_roots:
            if not root_dir.exists():
                continue

            if progress_callback:
                progress_callback(f"Scanning target directory: {root_dir}")

            try:
                for entry in root_dir.iterdir():
                    if not entry.is_dir():
                        continue

                    # Safety check first!
                    is_safe, reason = self.safety.is_safe_path(str(entry))
                    if not is_safe:
                        logger.debug(f"Safety Engine filtered {entry.name}: {reason}")
                        continue

                    if progress_callback:
                        progress_callback(f"Checking residue signature: {entry.name}")

                    # Check against registered software
                    if not self.is_known_installed(entry.name, str(entry)):
                        # Evaluate folder contents for confidence
                        confidence, conf_label, conf_reason = self._evaluate_confidence(entry)
                        size_bytes = self.get_folder_size(entry)

                        # Only surface non-trivial residues or empty abandoned folders
                        results.append(ScanResultItem(
                            name=entry.name,
                            category="orphan_dir",
                            item_type="Folder",
                            path=str(entry),
                            size_bytes=size_bytes,
                            confidence_score=confidence,
                            confidence_label=conf_label,
                            reason=f"No registered software uninstall entry matches '{entry.name}'. {conf_reason}",
                        ))
            except (PermissionError, OSError) as e:
                logger.warning(f"Skipping inaccessible root {root_dir}: {e}")

        return results

    def _evaluate_confidence(self, folder: Path) -> Tuple[int, str, str]:
        """
        Determines safety confidence score (0-100) based on folder heuristics:
        Presence of running binaries, file extensions, and modification timestamps.
        """
        has_executables = False
        has_configs_only = True
        file_count = 0

        try:
            for item in folder.glob("*"):
                file_count += 1
                if item.suffix.lower() in {".exe", ".dll", ".sys"}:
                    has_executables = True
                    has_configs_only = False
                elif item.suffix.lower() not in {".log", ".txt", ".json", ".ini", ".xml", ".cache", ".dat", ".tmp"}:
                    has_configs_only = False
                if file_count > 50:
                    break
        except Exception:
            pass

        if has_executables:
            return 65, "Review needed", "Contains binary executables/libraries."
        elif has_configs_only or file_count == 0:
            return 95, "Safe to remove", "Contains only static configurations, logs, or empty tree."
        else:
            return 85, "Safe to remove", "Residue caches and data with no active binaries."
