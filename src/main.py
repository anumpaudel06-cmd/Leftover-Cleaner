"""
GhostPurge - Windows Safe Residual & Orphan Cleaner
===================================================
Application Entry Point with Automatic Administrator Self-Elevation,
PerMonitorV2 High-DPI Awareness, and CLI/GUI Execution Dispatch.
"""

import sys
import os
import ctypes
import argparse
import logging
from pathlib import Path

# Robust sys.path bootstrapping for both standalone PyInstaller and direct execution
_CURRENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _CURRENT_DIR.parent if _CURRENT_DIR.name == "src" else _CURRENT_DIR
_SRC_DIR = _CURRENT_DIR if _CURRENT_DIR.name == "src" else (_CURRENT_DIR / "src")

for _p in [str(_SRC_DIR), str(_PROJECT_ROOT)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Handle PyInstaller _MEIPASS extraction bundle
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    _meipass = Path(sys._MEIPASS)
    for _mp in [str(_meipass), str(_meipass / "src")]:
        if _mp not in sys.path:
            sys.path.insert(0, _mp)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("LeftoverCleaner")


def is_admin() -> bool:
    """Check if the current process holds elevated Windows Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        # On non-Windows platforms (e.g. during development/testing)
        return os.getuid() == 0 if hasattr(os, "getuid") else True


def elevate_privileges() -> None:
    """
    Relaunches the current script via the Windows UAC 'runas' verb.
    Blocks the current unprivileged process and transfers control to the elevated instance.
    """
    if sys.platform != "win32":
        logger.info("Non-Windows OS detected; skipping Windows UAC self-elevation.")
        return

    logger.info("Requesting administrative elevation via Windows UAC (runas)...")

    # Script path or executable binary
    if getattr(sys, "frozen", False):
        executable = sys.executable
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    else:
        executable = sys.executable
        params = f'"{sys.argv[0]}" ' + " ".join([f'"{arg}"' for arg in sys.argv[1:]])

    # Invoke ShellExecuteW with "runas"
    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        executable,
        params,
        None,
        1,  # SW_SHOWNORMAL
    )

    # Return value > 32 indicates success
    if ret > 32:
        logger.info("Elevated instance launched successfully. Exiting parent process.")
        sys.exit(0)
    else:
        logger.error(f"UAC elevation was declined by user or failed (code: {ret}).")
        # Proceed with limited privileges or exit
        sys.exit(1)


def configure_high_dpi() -> None:
    """Enable PerMonitorV2 High-DPI awareness on Windows 10/11 for crisp Fluent typography."""
    if sys.platform != "win32":
        return

    try:
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
        ctypes.windll.user32.SetProcessDpiAwarenessContext(-4)
        logger.debug("Configured DPI Awareness Context: PerMonitorV2")
    except Exception:
        try:
            # Fallback for earlier Windows builds
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
            logger.debug("Configured Process DPI Awareness: Per-Monitor")
        except Exception as e:
            logger.debug(f"High-DPI configuration note: {e}")


def run_headless_cli(args: argparse.Namespace) -> None:
    """Execute Leftover-Cleaner in non-interactive / automated command-line mode."""
    try:
        from core.safety_engine import SafetyEngine
        from core.orphan_scanner import OrphanScanner
        from core.registry_cleaner import RegistryCleaner
        from core.junk_cleaner import JunkCleaner
    except ModuleNotFoundError:
        from src.core.safety_engine import SafetyEngine
        from src.core.orphan_scanner import OrphanScanner
        from src.core.registry_cleaner import RegistryCleaner
        from src.core.junk_cleaner import JunkCleaner

    print("\n" + "=" * 65)
    print("   Leftover-Cleaner - Headless Windows Residual Cleaner")
    print("=" * 65 + "\n")

    safety = SafetyEngine()
    scanner = OrphanScanner(safety)
    junk = JunkCleaner(safety)

    def log_progress(msg: str):
        print(f"[*] {msg}")

    print("[Phase 1/3] Scanning for orphaned application folders...")
    orphan_items = scanner.scan_target_roots(progress_callback=log_progress)

    print("\n[Phase 2/3] Scanning residual registry hives...")
    reg_cleaner = RegistryCleaner(safety, scanner.installed_apps)
    reg_items = reg_cleaner.scan_software_residue(progress_callback=log_progress)

    print("\n[Phase 3/3] Scanning system temporary caches...")
    cache_items = junk.scan_junk_locations(include_prefetch=False, progress_callback=log_progress)

    all_items = orphan_items + reg_items + cache_items
    total_bytes = sum(item.size_bytes for item in all_items)
    mb_reclaimable = total_bytes / (1024 * 1024)

    print("\n" + "-" * 65)
    print(f"Scan complete: {len(all_items)} candidate items discovered.")
    print(f"Total Disk Space Reclaimable: {mb_reclaimable:.2f} MB")
    print("-" * 65)

    for item in all_items:
        conf_marker = "[SAFE]" if item.confidence_score >= 80 else "[REVIEW]"
        print(f"{conf_marker} {item.name:<32} {item.size_bytes / (1024*1024):>8.2f} MB | {item.path}")

    if getattr(args, "delete", False):
        print("\n[*] Starting permanent deletion of verified safe leftover items (Confidence >= 80%)...")
        deleted_count = 0
        freed = 0
        for item in all_items:
            if item.confidence_score >= 80:
                success, msg = safety.permanently_delete(item.path, item.category)
                if success:
                    deleted_count += 1
                    freed += item.size_bytes
                    print(f"  [Deleted] {item.name}")
                else:
                    print(f"  [Skipped] {item.name}: {msg}")
        print(f"\n[+] Cleanup complete: Deleted {deleted_count} items, freed {freed / (1024*1024):.2f} MB.")

    if args.export:
        import json
        export_data = [
            {
                "name": it.name,
                "category": it.category,
                "path": it.path,
                "size_mb": round(it.size_bytes / (1024 * 1024), 2),
                "confidence": it.confidence_score,
                "reason": it.reason,
            }
            for it in all_items
        ]
        with open(args.export, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)
        print(f"\n[+] Scan report successfully exported to: {args.export}")


def main() -> None:
    """Main application supervisor."""
    parser = argparse.ArgumentParser(description="Leftover-Cleaner - Windows Safe Residual & Orphan Cleaner")
    parser.add_argument("--delete", action="store_true", help="Permanently delete safe leftover files and folders")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Execute scan in simulation preview mode (no disk changes)")
    parser.add_argument("--scan-only", action="store_true", help="Run headless terminal scan and display results")
    parser.add_argument("--no-restore-point", action="store_true", help="Skip System Restore Point creation")
    parser.add_argument("--export", type=str, help="Export scan results to specified JSON file")
    parser.add_argument("--skip-elevation", action="store_true", help="Bypass UAC elevation check (for testing)")

    args = parser.parse_args()

    # Step 1: Self-elevation verification
    if not args.skip_elevation and not is_admin():
        elevate_privileges()

    # Step 2: Configure High DPI for crystal-clear Segoe UI rendering
    configure_high_dpi()

    # Step 3: Branch to Headless or GUI
    if args.scan_only:
        run_headless_cli(args)
    else:
        try:
            try:
                from ui.app_window import GhostPurgeApp
            except ModuleNotFoundError:
                from src.ui.app_window import GhostPurgeApp
            app = GhostPurgeApp(dry_run_default=args.dry_run, skip_restore_point=args.no_restore_point)
            app.mainloop()
        except Exception as e:
            logger.warning(f"GUI framework note ({e}); running in headless console mode.")
            run_headless_cli(args)


if __name__ == "__main__":
    main()
