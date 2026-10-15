"""
GhostPurge System Junk & Cache Cleaner
=====================================
Scans and safely cleans Windows temporary directories, Windows Update download caches,
crash dumps (.dmp), thumbnail databases, and log residues while gracefully handling
files locked by running operating system processes.
"""

import os
import sys
import shutil
import logging
from pathlib import Path
from typing import List, Tuple, Optional, Callable
from .safety_engine import SafetyEngine
from .orphan_scanner import ScanResultItem

logger = logging.getLogger("GhostPurge.JunkCleaner")


class JunkCleaner:
    """
    Safely inventories and purges temporary files and caches.
    Ensures zero crashes from locked file descriptors or system permission boundaries.
    """

    def __init__(self, safety_engine: SafetyEngine):
        self.safety = safety_engine

    def scan_junk_locations(
        self,
        include_prefetch: bool = False,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> List[ScanResultItem]:
        """
        Gathers safe-to-clean system temporary files, caches, and crash dumps.
        """
        results: List[ScanResultItem] = []

        local_temp = os.environ.get("TEMP", os.environ.get("TMP"))
        windir = os.environ.get("WINDIR", "C:\\Windows")
        win_temp = os.path.join(windir, "Temp")
        softwaredist_download = os.path.join(windir, "SoftwareDistribution", "Download")
        crash_dumps = os.path.join(local_temp or "", "CrashDumps") if local_temp else None
        prefetch_dir = os.path.join(windir, "Prefetch")

        targets = [
            (local_temp, "User Temp Directory", "Temp File", 98, "Safe to remove"),
            (win_temp, "Windows System Temp", "Temp File", 95, "Safe to remove"),
            (softwaredist_download, "Windows Update Download Cache", "Update Cache", 92, "Safe to remove"),
        ]

        if crash_dumps and os.path.exists(crash_dumps):
            targets.append((crash_dumps, "Windows Crash Dumps (.dmp)", "Crash Dump", 95, "Safe to remove"))

        if include_prefetch and os.path.exists(prefetch_dir):
            targets.append((prefetch_dir, "Windows Prefetch Cache", "Prefetch File", 70, "Review needed"))

        for target_path, name_label, item_type, confidence, conf_label in targets:
            if not target_path or not os.path.exists(target_path):
                continue

            if progress_callback:
                progress_callback(f"Scanning cache location: {name_label}")

            try:
                target_obj = Path(target_path)
                total_size = 0
                item_count = 0

                for item in target_obj.iterdir():
                    try:
                        # Safety check
                        is_safe, _ = self.safety.is_safe_path(str(item))
                        if not is_safe:
                            continue

                        if item.is_file(follow_symlinks=False):
                            total_size += item.stat().st_size
                            item_count += 1
                        elif item.is_dir(follow_symlinks=False):
                            total_size += self._get_dir_size(item)
                            item_count += 1
                    except (PermissionError, OSError):
                        continue

                if item_count > 0:
                    results.append(ScanResultItem(
                        name=f"{name_label} ({item_count} items)",
                        category="cache",
                        item_type=item_type,
                        path=target_path,
                        size_bytes=total_size,
                        confidence_score=confidence,
                        confidence_label=conf_label,
                        reason=f"Temporary cached residues and logs ({item_count} files/folders).",
                    ))
            except (PermissionError, OSError) as e:
                logger.warning(f"Could not scan cache {target_path}: {e}")

        return results

    def _get_dir_size(self, path_obj: Path) -> int:
        total = 0
        try:
            for p in path_obj.rglob("*"):
                try:
                    if p.is_file(follow_symlinks=False):
                        total += p.stat().st_size
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass
        return total

    def clean_target_item(self, item: ScanResultItem, dry_run: bool = True) -> Tuple[int, int, List[str]]:
        """
        Safely purges items in target path while gracefully bypassing locked files.
        Returns: (bytes_freed: int, files_deleted: int, skipped_locked: List[str])
        """
        if dry_run:
            logger.info(f"[Dry-Run] Simulating purge of {item.path} ({item.size_bytes} bytes)")
            return item.size_bytes, 1, []

        is_safe, reason = self.safety.is_safe_path(item.path)
        if not is_safe:
            logger.error(f"Refusing to delete unsafe target: {item.path} ({reason})")
            return 0, 0, [f"Blocked: {reason}"]

        bytes_freed = 0
        deleted_count = 0
        skipped = []

        path_obj = Path(item.path)
        if not path_obj.exists():
            return 0, 0, []

        # If it's a temp container directory, clean the contents rather than deleting the root container
        if path_obj.is_dir() and item.category == "cache":
            for child in path_obj.iterdir():
                try:
                    if child.is_file(follow_symlinks=False):
                        size = child.stat().st_size
                        child.unlink(missing_ok=True)
                        bytes_freed += size
                        deleted_count += 1
                    elif child.is_dir(follow_symlinks=False):
                        size = self._get_dir_size(child)
                        shutil.rmtree(child, ignore_errors=False)
                        bytes_freed += size
                        deleted_count += 1
                except (PermissionError, OSError) as ex:
                    # Windows sharing violation / locked by active system process
                    skipped.append(f"{child.name} (locked by process)")
                    continue
        elif path_obj.is_dir():
            # For orphan folders, move to quarantine
            success, q_path = self.safety.quarantine_folder(str(path_obj), reason=item.reason)
            if success:
                bytes_freed = item.size_bytes
                deleted_count = 1
            else:
                skipped.append(f"{path_obj.name}: {q_path}")
        else:
            try:
                size = path_obj.stat().st_size
                path_obj.unlink(missing_ok=True)
                bytes_freed = size
                deleted_count = 1
            except (PermissionError, OSError):
                skipped.append(f"{path_obj.name} (locked)")

        return bytes_freed, deleted_count, skipped
