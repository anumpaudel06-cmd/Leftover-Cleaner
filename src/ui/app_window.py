"""
GhostPurge - Windows 11 Fluent Desktop Interface
===============================================
Implemented with CustomTkinter following Microsoft Fluent Design guidelines:
Clean neutral slate palette, Segoe UI typography, high information density,
collapsible scan log drawer, and granular safety inspection.
"""

import sys
import threading
from typing import List, Dict, Optional, Callable
from pathlib import Path

try:
    import customtkinter as ctk
except ImportError:
    ctk = None

from core.safety_engine import SafetyEngine
from core.orphan_scanner import OrphanScanner, ScanResultItem
from core.registry_cleaner import RegistryCleaner
from core.junk_cleaner import JunkCleaner


class GhostPurgeApp(ctk.CTk if ctk else object):
    """
    Windows 11 Fluent GUI Application for GhostPurge.
    """

    # Windows 11 Fluent Color Palette
    COLOR_BG_DARK = "#202020"
    COLOR_BG_LIGHT = "#F3F3F3"
    COLOR_SIDEBAR_DARK = "#181818"
    COLOR_SIDEBAR_LIGHT = "#E9E9E9"
    COLOR_CARD_DARK = "#2B2B2B"
    COLOR_CARD_LIGHT = "#FFFFFF"
    COLOR_ACCENT = "#0067C0"       # Windows 11 Accent Blue
    COLOR_ACCENT_HOVER = "#1877D2"
    COLOR_SAFE = "#107C41"         # Windows Green
    COLOR_REVIEW = "#B86200"       # Windows Amber / Caution
    COLOR_TEXT_MUTED = "#8A8A8A"

    def __init__(self, dry_run_default: bool = True, skip_restore_point: bool = False):
        if not ctk:
            raise RuntimeError("CustomTkinter is required to launch the GhostPurge GUI.")

        super().__init__()

        self.dry_run = dry_run_default
        self.skip_restore_point = skip_restore_point
        self.safety = SafetyEngine()
        self.scanner = OrphanScanner(self.safety)
        self.reg_cleaner = RegistryCleaner(self.safety)
        self.junk_cleaner = JunkCleaner(self.safety)

        self.scanned_items: List[ScanResultItem] = []
        self.selected_indices: set = set()
        self.is_scanning = False
        self.active_tab = "all"  # "all", "orphan_dir", "registry", "cache"

        # Window Setup
        self.title("GhostPurge - Windows Safe Residual & Orphan Cleaner")
        self.geometry("1100x720")
        self.minsize(980, 640)
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self._build_layout()

    def _build_layout(self) -> None:
        """Construct the sidebar, header, central workbench, and collapsible log console."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # 1. Left Sidebar Navigation
        self.sidebar_frame = ctk.CTkFrame(
            self,
            width=240,
            corner_radius=0,
            fg_color=(self.COLOR_SIDEBAR_LIGHT, self.COLOR_SIDEBAR_DARK),
        )
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_propagate(False)
        self._build_sidebar()

        # 2. Main Content Viewport
        self.main_frame = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color=(self.COLOR_BG_LIGHT, self.COLOR_BG_DARK),
        )
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self._build_header_strip()
        self._build_metric_overview()
        self._build_table_controls()
        self._build_item_treeview()
        self._build_log_drawer()

    def _build_sidebar(self) -> None:
        """Windows 11 Fluent Sidebar Navigation."""
        # Brand Wordmark
        title_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="GhostPurge",
            font=ctk.CTkFont(family="Segoe UI Variable Display", size=20, weight="bold"),
            anchor="w",
        )
        title_label.pack(padx=24, pady=(24, 4), anchor="w")

        subtitle = ctk.CTkLabel(
            self.sidebar_frame,
            text="Windows Safety Purge Engine",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=self.COLOR_TEXT_MUTED,
            anchor="w",
        )
        subtitle.pack(padx=24, pady=(0, 24), anchor="w")

        # Navigation items
        nav_items = [
            ("All Findings", "all"),
            ("Orphan Folders", "orphan_dir"),
            ("Registry Residuals", "registry"),
            ("System Cache & Temp", "cache"),
        ]

        self.nav_buttons = {}
        for label, tab_id in nav_items:
            btn = ctk.CTkButton(
                self.sidebar_frame,
                text=label,
                anchor="w",
                height=36,
                corner_radius=6,
                fg_color="transparent",
                text_color=("black", "white"),
                hover_color=("rgba(0,0,0,0.06)", "rgba(255,255,255,0.08)"),
                command=lambda t=tab_id: self._select_tab(t),
                font=ctk.CTkFont(family="Segoe UI", size=13),
            )
            btn.pack(padx=16, pady=3, fill="x")
            self.nav_buttons[tab_id] = btn

        self._highlight_active_nav("all")

        # Sidebar footer: Safety Status & Toggle
        spacer = ctk.CTkLabel(self.sidebar_frame, text="")
        spacer.pack(expand=True, fill="both")

        self.dry_run_switch = ctk.CTkSwitch(
            self.sidebar_frame,
            text="Dry-Run Mode (Preview Only)",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=self._on_toggle_dry_run,
        )
        if self.dry_run:
            self.dry_run_switch.select()
        self.dry_run_switch.pack(padx=20, pady=(0, 8), anchor="w")

        theme_switch = ctk.CTkSegmentedButton(
            self.sidebar_frame,
            values=["Dark", "Light"],
            command=ctk.set_appearance_mode,
            height=28,
        )
        theme_switch.set("Dark")
        theme_switch.pack(padx=20, pady=(0, 20), fill="x")

    def _build_header_strip(self) -> None:
        """Top action bar with scan status and primary execution buttons."""
        self.header_frame = ctk.CTkFrame(
            self.main_frame,
            fg_color="transparent",
            height=54,
        )
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=28, pady=(20, 10))

        self.status_label = ctk.CTkLabel(
            self.header_frame,
            text="System Ready · Whitelist Guardrails Active",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="normal"),
            text_color=("black", "white"),
        )
        self.status_label.pack(side="left")

        # Action Buttons
        self.purge_button = ctk.CTkButton(
            self.header_frame,
            text="Execute Safe Purge",
            fg_color=self.COLOR_ACCENT,
            hover_color=self.COLOR_ACCENT_HOVER,
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            height=34,
            corner_radius=6,
            command=self._confirm_purge_execution,
        )
        self.purge_button.pack(side="right", padx=(10, 0))

        self.scan_button = ctk.CTkButton(
            self.header_frame,
            text="Scan Residues",
            fg_color=("rgba(0,0,0,0.08)", "rgba(255,255,255,0.1)"),
            hover_color=("rgba(0,0,0,0.14)", "rgba(255,255,255,0.18)"),
            text_color=("black", "white"),
            font=ctk.CTkFont(family="Segoe UI", size=13),
            height=34,
            corner_radius=6,
            command=self._start_scan_thread,
        )
        self.scan_button.pack(side="right")

    def _build_metric_overview(self) -> None:
        """Metrics banner showing disk space reclaimable and item tallies."""
        metrics_container = ctk.CTkFrame(
            self.main_frame,
            fg_color=(self.COLOR_CARD_LIGHT, self.COLOR_CARD_DARK),
            corner_radius=8,
            border_width=1,
            border_color=("rgba(0,0,0,0.08)", "rgba(255,255,255,0.08)"),
        )
        metrics_container.grid(row=1, column=0, sticky="ew", padx=28, pady=(0, 14))

        # Reclaimable Space Card
        self.reclaim_label = ctk.CTkLabel(
            metrics_container,
            text="0.00 MB",
            font=ctk.CTkFont(family="Segoe UI Variable Display", size=28, weight="bold"),
        )
        self.reclaim_label.pack(side="left", padx=24, pady=16)

        desc_label = ctk.CTkLabel(
            metrics_container,
            text="Disk Space Reclaimable\nAcross safe orphan candidates",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=self.COLOR_TEXT_MUTED,
            justify="left",
        )
        desc_label.pack(side="left", padx=(0, 32))

        # Summary Counter Chips
        self.count_summary_label = ctk.CTkLabel(
            metrics_container,
            text="0 Items Detected  ·  0 Orphan Folders  ·  0 Registry Keys  ·  0 Cache Targets",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=self.COLOR_TEXT_MUTED,
        )
        self.count_summary_label.pack(side="right", padx=24)

    def _build_table_controls(self) -> None:
        """Filter bar and select all/none controls."""
        ctrl_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        ctrl_frame.grid(row=2, column=0, sticky="ew", padx=28, pady=(0, 6))

        self.select_all_btn = ctk.CTkButton(
            ctrl_frame,
            text="Select All Safe",
            width=110,
            height=28,
            corner_radius=5,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color="transparent",
            border_width=1,
            border_color=("rgba(0,0,0,0.2)", "rgba(255,255,255,0.2)"),
            text_color=("black", "white"),
            command=self._select_all_safe,
        )
        self.select_all_btn.pack(side="left", padx=(0, 8))

        self.deselect_all_btn = ctk.CTkButton(
            ctrl_frame,
            text="Deselect All",
            width=90,
            height=28,
            corner_radius=5,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color="transparent",
            border_width=1,
            border_color=("rgba(0,0,0,0.2)", "rgba(255,255,255,0.2)"),
            text_color=("black", "white"),
            command=self._deselect_all,
        )
        self.deselect_all_btn.pack(side="left")

        self.table_filter_info = ctk.CTkLabel(
            ctrl_frame,
            text="Displaying all items",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=self.COLOR_TEXT_MUTED,
        )
        self.table_filter_info.pack(side="right")

    def _build_item_treeview(self) -> None:
        """Scrollable frame displaying detected items with checkboxes and confidence badges."""
        self.scroll_table = ctk.CTkScrollableFrame(
            self.main_frame,
            corner_radius=8,
            fg_color=(self.COLOR_CARD_LIGHT, self.COLOR_CARD_DARK),
            border_width=1,
            border_color=("rgba(0,0,0,0.08)", "rgba(255,255,255,0.08)"),
        )
        self.scroll_table.grid(row=3, column=0, sticky="nsew", padx=28, pady=(0, 10))
        self.scroll_table.grid_columnconfigure(1, weight=1)

        self._render_empty_table_state()

    def _render_empty_table_state(self) -> None:
        """Render clean guidance when no scan has taken place."""
        for child in self.scroll_table.winfo_children():
            child.destroy()

        empty_label = ctk.CTkLabel(
            self.scroll_table,
            text="No residual items scanned yet.\nClick 'Scan Residues' to discover orphan application folders, residual keys, and junk.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=self.COLOR_TEXT_MUTED,
            justify="center",
        )
        empty_label.pack(pady=80)

    def _build_log_drawer(self) -> None:
        """Collapsible console drawer showing active file paths and scanner events."""
        self.drawer_frame = ctk.CTkFrame(
            self.main_frame,
            height=120,
            corner_radius=6,
            fg_color=(self.COLOR_SIDEBAR_LIGHT, self.COLOR_SIDEBAR_DARK),
            border_width=1,
            border_color=("rgba(0,0,0,0.08)", "rgba(255,255,255,0.08)"),
        )
        self.drawer_frame.grid(row=4, column=0, sticky="ew", padx=28, pady=(0, 16))
        self.drawer_frame.grid_propagate(False)

        drawer_header = ctk.CTkFrame(self.drawer_frame, fg_color="transparent", height=24)
        drawer_header.pack(fill="x", padx=12, pady=(6, 2))

        console_title = ctk.CTkLabel(
            drawer_header,
            text="Scanning Log & Safety Inspection",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=self.COLOR_TEXT_MUTED,
        )
        console_title.pack(side="left")

        self.log_textbox = ctk.CTkTextbox(
            self.drawer_frame,
            font=ctk.CTkFont(family="Consolas", size=10),
            corner_radius=4,
            fg_color="transparent",
        )
        self.log_textbox.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self.log_message("[System] GhostPurge initialized. Ready to perform safe dry-run inspection.")

    def log_message(self, message: str) -> None:
        """Append a message to the console drawer."""
        self.log_textbox.insert("end", f"{message}\n")
        self.log_textbox.see("end")

    def _highlight_active_nav(self, active_tab: str) -> None:
        for tab_id, btn in self.nav_buttons.items():
            if tab_id == active_tab:
                btn.configure(fg_color=("rgba(0,0,0,0.08)", "rgba(255,255,255,0.12)"))
            else:
                btn.configure(fg_color="transparent")

    def _select_tab(self, tab_id: str) -> None:
        self.active_tab = tab_id
        self._highlight_active_nav(tab_id)
        self._refresh_table_view()

    def _on_toggle_dry_run(self) -> None:
        self.dry_run = self.dry_run_switch.get() == 1
        status = "Dry-Run Preview (No files deleted)" if self.dry_run else "Active Purge (Files will be removed)"
        self.log_message(f"[Config] Execution mode set: {status}")

    def _start_scan_thread(self) -> None:
        if self.is_scanning:
            return

        self.is_scanning = True
        self.scan_button.configure(state="disabled", text="Scanning...")
        self.status_label.configure(text="Scanning file systems and registry hives...")
        self.log_message("[Scanner] Starting full system scan...")

        thread = threading.Thread(target=self._run_scan_worker, daemon=True)
        thread.start()

    def _run_scan_worker(self) -> None:
        """Background thread worker for scanning."""
        def callback(msg: str):
            self.after(0, lambda m=msg: self.log_message(f"[*] {m}"))

        self.scanner.load_installed_applications()
        orphan_items = self.scanner.scan_target_roots(progress_callback=callback)

        self.reg_cleaner.set_installed_tokens(self.scanner.installed_apps)
        reg_items = self.reg_cleaner.scan_software_residue(progress_callback=callback)

        cache_items = self.junk_cleaner.scan_junk_locations(include_prefetch=False, progress_callback=callback)

        self.scanned_items = orphan_items + reg_items + cache_items
        self.selected_indices = {i for i, it in enumerate(self.scanned_items) if it.confidence_score >= 80}

        self.after(0, self._on_scan_completed)

    def _on_scan_completed(self) -> None:
        self.is_scanning = False
        self.scan_button.configure(state="normal", text="Scan Residues")
        self.status_label.configure(text=f"Scan Complete · {len(self.scanned_items)} candidate residues found")

        total_bytes = sum(it.size_bytes for it in self.scanned_items)
        mb = total_bytes / (1024 * 1024)
        self.reclaim_label.configure(text=f"{mb:.2f} MB")

        orphans = sum(1 for it in self.scanned_items if it.category == "orphan_dir")
        regs = sum(1 for it in self.scanned_items if it.category == "registry")
        caches = sum(1 for it in self.scanned_items if it.category == "cache")
        self.count_summary_label.configure(
            text=f"{len(self.scanned_items)} Total  ·  {orphans} Orphan Folders  ·  {regs} Registry  ·  {caches} Cache"
        )

        self.log_message(f"[Scanner] Scan finished: Found {len(self.scanned_items)} items ({mb:.2f} MB total).")
        self._refresh_table_view()

    def _refresh_table_view(self) -> None:
        """Render the filtered checklist of scan items."""
        for child in self.scroll_table.winfo_children():
            child.destroy()

        filtered = [
            (idx, item) for idx, item in enumerate(self.scanned_items)
            if self.active_tab == "all" or item.category == self.active_tab
        ]

        if not filtered:
            self._render_empty_table_state()
            return

        self.table_filter_info.configure(text=f"Displaying {len(filtered)} items")

        for row_i, (real_idx, item) in enumerate(filtered):
            row_frame = ctk.CTkFrame(
                self.scroll_table,
                fg_color="transparent" if row_i % 2 == 0 else ("rgba(0,0,0,0.02)", "rgba(255,255,255,0.02)"),
                height=38,
            )
            row_frame.pack(fill="x", padx=4, pady=1)

            # Checkbox
            var = ctk.BooleanVar(value=(real_idx in self.selected_indices))
            cb = ctk.CTkCheckBox(
                row_frame,
                text="",
                width=24,
                checkbox_width=18,
                checkbox_height=18,
                command=lambda i=real_idx, v=var: self._toggle_selection(i, v.get()),
                variable=var,
            )
            cb.pack(side="left", padx=(8, 4))

            # Name and Type
            name_label = ctk.CTkLabel(
                row_frame,
                text=f"{item.name} ({item.item_type})",
                font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                anchor="w",
                width=220,
            )
            name_label.pack(side="left", padx=4)

            # Path (truncated)
            path_display = item.path if len(item.path) < 55 else item.path[:52] + "..."
            path_lbl = ctk.CTkLabel(
                row_frame,
                text=path_display,
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=self.COLOR_TEXT_MUTED,
                anchor="w",
            )
            path_lbl.pack(side="left", fill="x", expand=True, padx=8)

            # Size
            size_mb = item.size_bytes / (1024 * 1024)
            size_text = f"{size_mb:.2f} MB" if size_mb >= 0.1 else f"{item.size_bytes / 1024:.0f} KB"
            size_lbl = ctk.CTkLabel(
                row_frame,
                text=size_text,
                font=ctk.CTkFont(family="Consolas", size=11),
                anchor="e",
                width=80,
            )
            size_lbl.pack(side="right", padx=12)

            # Confidence Badge
            is_high = item.confidence_score >= 80
            conf_color = self.COLOR_SAFE if is_high else self.COLOR_REVIEW
            conf_lbl = ctk.CTkLabel(
                row_frame,
                text=item.confidence_label,
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=conf_color,
                anchor="e",
                width=110,
            )
            conf_lbl.pack(side="right", padx=8)

    def _toggle_selection(self, idx: int, selected: bool) -> None:
        if selected:
            self.selected_indices.add(idx)
        else:
            self.selected_indices.discard(idx)

    def _select_all_safe(self) -> None:
        self.selected_indices = {i for i, it in enumerate(self.scanned_items) if it.confidence_score >= 80}
        self._refresh_table_view()

    def _deselect_all(self) -> None:
        self.selected_indices.clear()
        self._refresh_table_view()

    def _confirm_purge_execution(self) -> None:
        """Prompt confirmation and execute safe deletion or dry run."""
        if not self.selected_indices:
            self.log_message("[Warn] No items selected for purge.")
            return

        selected_items = [self.scanned_items[i] for i in self.selected_indices]
        mode = "DRY-RUN (Simulation Only)" if self.dry_run else "PERMANENT PURGE"
        self.log_message(f"[Action] Starting {mode} of {len(selected_items)} items...")

        # System Restore Point checkpoint
        if not self.dry_run and not self.skip_restore_point:
            self.log_message("[Safety] Triggering Windows System Restore Point creation...")
            success, msg = self.safety.create_system_restore_point("Pre-GhostPurge-Cleanup")
            self.log_message(f"[Safety] Restore Point: {msg}")

        # Execute items
        freed = 0
        deleted = 0
        for item in selected_items:
            b, d, skipped = self.junk_cleaner.clean_target_item(item, dry_run=self.dry_run)
            freed += b
            deleted += d
            if skipped:
                for s in skipped:
                    self.log_message(f"  [Skip] {s}")

        self.log_message(f"[Complete] Finished. Freed {freed / (1024*1024):.2f} MB ({deleted} targets processed).")
        if not self.dry_run:
            self.scanned_items = [it for idx, it in enumerate(self.scanned_items) if idx not in self.selected_indices]
            self.selected_indices.clear()
            self._refresh_table_view()
