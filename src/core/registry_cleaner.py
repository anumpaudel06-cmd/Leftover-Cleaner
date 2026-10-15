"""
GhostPurge Registry Cleaner (Safe Heuristics)
============================================
Scans HKCU\\Software and HKLM\\Software for residual software keys belonging to uninstalled
programs, obsolete MUI Cache references, and invalid startup entries.
"""

import os
import logging
from typing import List, Set, Optional, Callable, Any, Tuple
from dataclasses import dataclass

try:
    import winreg
except ImportError:
    winreg = None

from .safety_engine import SafetyEngine
from .orphan_scanner import ScanResultItem

logger = logging.getLogger("GhostPurge.RegistryCleaner")


class RegistryCleaner:
    """
    Safely identifies residual vendor/software keys in HKCU\\Software and HKLM\\Software,
    obsolete MUI Cache paths, and dead startup entries.
    """

    def __init__(self, safety_engine: SafetyEngine, known_installed_tokens: Optional[Set[str]] = None):
        self.safety = safety_engine
        self.known_tokens: Set[str] = known_installed_tokens or set()

    def set_installed_tokens(self, tokens: Set[str]) -> None:
        self.known_tokens = tokens

    def scan_software_residue(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[ScanResultItem]:
        """
        Scans HKCU\\Software and HKLM\\Software for vendor/app keys of uninstalled software.
        """
        results: List[ScanResultItem] = []
        if not winreg:
            return results

        hives_to_check = [
            (winreg.HKEY_CURRENT_USER, r"Software", "HKCU\\Software"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software", "HKLM\\Software"),
        ]

        for root_hkey, path, label in hives_to_check:
            if progress_callback:
                progress_callback(f"Scanning registry root: {label}")

            try:
                with winreg.OpenKey(root_hkey, path, 0, winreg.KEY_READ) as key:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    for i in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            full_path = f"{label}\\{subkey_name}"

                            # Safety engine verification
                            is_safe, reason = self.safety.is_safe_registry_key(label, subkey_name)
                            if not is_safe:
                                continue

                            if progress_callback:
                                progress_callback(f"Checking registry signature: {full_path}")

                            # Check if vendor key corresponds to an installed app
                            clean_token = subkey_name.lower().replace(" ", "").replace("_", "")
                            if clean_token not in self.known_tokens and len(clean_token) > 2:
                                # Estimate registry key size/impact
                                subkey_count, val_count = self._count_key_contents(root_hkey, f"{path}\\{subkey_name}")

                                results.append(ScanResultItem(
                                    name=subkey_name,
                                    category="registry",
                                    item_type="Registry Key",
                                    path=full_path,
                                    size_bytes=val_count * 256,  # Normalized heuristic size
                                    confidence_score=90,
                                    confidence_label="Safe to remove",
                                    reason=f"Residual software configuration with {val_count} values and {subkey_count} subkeys; no installed software matches.",
                                ))
                        except Exception as ex:
                            logger.debug(f"Error enumerating subkey at index {i}: {ex}")
            except Exception as e:
                logger.warning(f"Could not open {label}: {e}")

        # Scan MUI Cache & Startup dead entries
        results.extend(self.scan_obsolete_mui_cache(progress_callback))
        results.extend(self.scan_dead_startup_entries(progress_callback))

        return results

    def _count_key_contents(self, root_hkey: Any, subkey_path: str) -> tuple[int, int]:
        """Returns (num_subkeys, num_values) for a registry path."""
        try:
            with winreg.OpenKey(root_hkey, subkey_path, 0, winreg.KEY_READ) as k:
                info = winreg.QueryInfoKey(k)
                return info[0], info[1]
        except Exception:
            return 0, 0

    def scan_obsolete_mui_cache(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[ScanResultItem]:
        """
        Scans Windows MUI Cache for references to executable paths that no longer exist on disk.
        """
        results: List[ScanResultItem] = []
        if not winreg:
            return results

        mui_cache_paths = [
            r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        ]

        for mui_path in mui_cache_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mui_path, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(min(num_values, 200)):  # Check top entries safely
                        try:
                            val_name, _, _ = winreg.EnumValue(key, i)
                            # MUI Cache value names are often file paths like "C:\Program Files\OldApp\app.exe.FriendlyAppName"
                            raw_path = val_name.split(".FriendlyAppName")[0].split(".ApplicationCompany")[0]
                            if os.path.isabs(raw_path) and not os.path.exists(raw_path):
                                results.append(ScanResultItem(
                                    name=f"MUI: {os.path.basename(raw_path)}",
                                    category="registry",
                                    item_type="MUI Cache",
                                    path=f"HKCU\\{mui_path}\\{val_name[:60]}...",
                                    size_bytes=128,
                                    confidence_score=95,
                                    confidence_label="Safe to remove",
                                    reason=f"Points to non-existent executable: {raw_path}",
                                ))
                        except Exception:
                            continue
            except Exception:
                pass

        return results

    def scan_dead_startup_entries(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[ScanResultItem]:
        """
        Scans HKCU and HKLM Run/RunOnce keys for startup programs whose executable target is missing.
        """
        results: List[ScanResultItem] = []
        if not winreg:
            return results

        run_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        ]

        for root_hkey, subkey, label in run_locations:
            try:
                with winreg.OpenKey(root_hkey, subkey, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(num_values):
                        try:
                            val_name, val_data, _ = winreg.EnumValue(key, i)
                            # Extract path from cmdline
                            cmd = str(val_data).strip().strip('"')
                            exe_path = cmd.split(".exe")[0] + ".exe" if ".exe" in cmd.lower() else cmd.split()[0]
                            if os.path.isabs(exe_path) and not os.path.exists(exe_path):
                                results.append(ScanResultItem(
                                    name=f"Startup: {val_name}",
                                    category="registry",
                                    item_type="Startup Key",
                                    path=f"{label} -> {val_name}",
                                    size_bytes=256,
                                    confidence_score=95,
                                    confidence_label="Safe to remove",
                                    reason=f"Obsolete startup entry targeting missing binary: {exe_path}",
                                ))
                        except Exception:
                            continue
            except Exception:
                pass

        return results
