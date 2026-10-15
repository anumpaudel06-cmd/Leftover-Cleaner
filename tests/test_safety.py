"""
GhostPurge Safety Engine Verification Tests
==========================================
Verifies that critical Windows system directories, kernel binaries, and system registry
hives can NEVER be flagged, targeted, or deleted under any circumstance.
"""

import os
import sys
import unittest
from pathlib import Path

# Add src to python path for testing
test_dir = Path(__file__).resolve().parent
src_dir = test_dir.parent / "src"
sys.path.insert(0, str(src_dir))

from core.safety_engine import SafetyEngine, SystemSafetyViolation
from core.orphan_scanner import OrphanScanner


class TestGhostPurgeSafetyEngine(unittest.TestCase):
    """Rigorous safety guardrail verification suite."""

    def setUp(self):
        self.safety = SafetyEngine()

    def test_system_directories_blocked(self):
        """Ensure critical Windows folders are strictly immune to targeting."""
        dangerous_paths = [
            r"C:\Windows\System32",
            r"C:\Windows\System32\drivers",
            r"C:\Windows\SysWOW64",
            r"C:\Windows\WinSxS",
            r"C:\Windows\Boot",
            r"C:\Windows\SystemApps",
            r"C:\Windows\servicing",
            r"C:\Windows",
            r"C:\\",
            r"D:\\",
            r"C:\System Volume Information",
            r"C:\Users\ActiveUser\AppData\Roaming\Microsoft",
            r"C:\ProgramData\Microsoft",
        ]

        for path in dangerous_paths:
            with self.subTest(path=path):
                is_safe, reason = self.safety.is_safe_path(path)
                self.assertFalse(
                    is_safe,
                    f"CRITICAL SAFETY BREACH: Protected path was marked safe! Path: {path}"
                )
                self.assertIsNotNone(reason)

    def test_kernel_and_shell_binaries_blocked(self):
        """Ensure essential Windows binaries cannot be selected."""
        critical_binaries = [
            r"C:\Windows\explorer.exe",
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Windows\System32\ntoskrnl.exe",
            r"C:\Windows\System32\user32.dll",
            r"C:\Windows\System32\hal.dll",
        ]

        for binary in critical_binaries:
            with self.subTest(binary=binary):
                is_safe, reason = self.safety.is_safe_path(binary)
                self.assertFalse(is_safe, f"Critical binary marked safe: {binary}")

    def test_safe_third_party_paths_permitted(self):
        """Ensure harmless third-party orphan folders are allowed through."""
        safe_candidates = [
            r"C:\Users\ExampleUser\AppData\Local\UninstalledVendorApp",
            r"C:\Users\ExampleUser\AppData\Roaming\OldChatClientResidue",
            r"C:\ProgramData\OldGameStudio123",
            r"C:\Users\ExampleUser\AppData\Local\Temp\junk_test.tmp",
        ]

        for path in safe_candidates:
            with self.subTest(path=path):
                is_safe, reason = self.safety.is_safe_path(path)
                self.assertTrue(is_safe, f"Legitimate orphan path was blocked: {path} ({reason})")

    def test_protected_registry_hives_blocked(self):
        """Ensure critical Windows registry hives cannot be selected."""
        dangerous_keys = [
            ("HKLM\\Software", "Microsoft"),
            ("HKLM\\Software", "Microsoft\\Windows NT\\CurrentVersion"),
            ("HKLM\\SYSTEM", "CurrentControlSet\\Services"),
            ("HKLM\\SAM", "SAM"),
            ("HKLM\\SECURITY", "Policy"),
            ("HKCU\\Software", "Classes\\exefile"),
            ("HKLM\\Software", "Policies\\Microsoft\\Windows"),
        ]

        for hive, subkey in dangerous_keys:
            with self.subTest(hive=hive, subkey=subkey):
                is_safe, reason = self.safety.is_safe_registry_key(hive, subkey)
                self.assertFalse(
                    is_safe,
                    f"CRITICAL REGISTRY SAFETY BREACH: Protected key marked safe: {hive}\\{subkey}"
                )

    def test_safe_third_party_registry_permitted(self):
        """Ensure residual third-party vendor registry keys are permitted."""
        safe_keys = [
            ("HKCU\\Software", "UninstalledMediaConverter"),
            ("HKCU\\Software", "DeadTorrentClient"),
            ("HKLM\\Software", "AbandonedCodeEditor"),
        ]

        for hive, subkey in safe_keys:
            with self.subTest(hive=hive, subkey=subkey):
                is_safe, reason = self.safety.is_safe_registry_key(hive, subkey)
                self.assertTrue(is_safe, f"Safe vendor registry key was blocked: {hive}\\{subkey}")

    def test_empty_paths_handled_gracefully(self):
        """Ensure empty or malformed paths return safe False without crashing."""
        self.assertFalse(self.safety.is_safe_path("")[0])
        self.assertFalse(self.safety.is_safe_path("   ")[0])
        self.assertFalse(self.safety.is_safe_registry_key("HKCU", "")[0])


if __name__ == "__main__":
    unittest.main()
