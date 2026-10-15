"""
Leftover-Cleaner - Windows 11 Fluent Desktop Interface
======================================================
Clean, intuitive, and simple interface for scanning and deleting leftover files,
orphan application folders, and residual registry keys without complexity.
"""

import sys
import threading
from typing import List, Dict, Optional, Callable
from pathlib import Path
from tkinter import messagebox

try:
    import customtkinter as ctk
except ImportError:
    ctk = None

try:
    from core.safety_engine import SafetyEngine
    from core.orphan_scanner import OrphanScanner, ScanResultItem
    from core.registry_cleaner import RegistryCleaner
    from core.junk_cleaner import JunkCleaner
except ModuleNotFoundError:
    from src.core.safety_engine import SafetyEngine
    from src.core.orphan_scanner import OrphanScanner, ScanResultItem
    from src.core.registry_cleaner import RegistryCleaner
    from src.core.junk_cleaner import JunkCleaner


class GhostPurgeApp(ctk.CTk if ctk else object):
    """
    Windows 11 Fluent GUI Application for Leftover-Cleaner.
    """

    COLOR_BG_DARK = "#202020"
    COLOR_BG_LIGHT = "#F3F3F3"
    COLOR_SIDEBAR_DARK = "#181818"
    COLOR_SIDEBAR_LIGHT = "#E9E9E9"
    COLOR_CARD_DARK = "#2B2B2B"
    COLOR_CARD_LIGHT = "#FFFFFF"
    COLOR_ACCENT = "#0067C0"         # Windows Blue
    COLOR_ACCENT_HOVER = "#1877D2"
    COLOR_DELETE = "#C42B1C"         # Windows Red for direct delete
    COLOR_DELETE_HOVER = "#A82315"
    COLOR_SAFE = "#107C41"           # Green
    COLOR_REVIEW = "#B86200"         # Caution Amber
    COLOR_TEXT_MUTED = "#8A8A8A"

    def __init__(self, dry_run_default: bool = False, skip_restore_point: bool = False):
        if not ctk:
            raise RuntimeError("CustomTkinter is required to launch the Leftover-Cleaner GUI.")

        super().__init__()

        # Direct deletion enabled by default (dry-run can be toggled if user explicitly wants simulation)
        self.dry_run = dry_run_default
        self.skip_restore_point = skip_restore_point
        self.safety = SafetyEngine()
        self.scanner = OrphanScanner(self.safety)
        self.reg_cleaner = RegistryCleaner(self.safety)
        self.junk_cleaner = JunkCleaner(self.safety)

        self.scanned_items: List[ScanResultItem] = []
        self.selected_indices: set = set()
        self.is_scanning = False
        self.active_tab = "all"

        # Window Setup
        self.title("Leftover-Cleaner - Windows Safe Residual & Orphan Cleaner")
        self.geometry("1100x720")
        self.minsize(960, 620)
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self._build_layout()

    def _build_layout(self) -> None:
        """Construct sidebar, header action strip, item table, and log console."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # 1. Sidebar Navigation
        self.sidebar_frame = ctk.CTkFrame(
            self,
            width=230,
            corner_radius=0,
            fg_color=(self.COLOR_SIDEBAR_LIGHT, self.COLOR_SIDEBAR_DARK),
        )
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_propagate(False)
        self._build_sidebar()

        # 2. Main Content
        self.main_frame = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color=(self.COLOR_BG_LIGHT, self.COLOR_BG_DARK),
        )
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.main_frame.grid_rowconfigure(3, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self._build_header_strip()
        self._build_metric_overview()
        self._build_table_controls()
        self._build_item_treeview()
        self._build_log_drawer()

    def _build_sidebar(self) -> None:
        """Simple, focused navigation items."""
        # Brand
        title_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="Leftover-Cleaner",
            font=ctk.CTkFont(family="Segoe UI Variable Display", size=18, weight="bold"),
            anchor="w",
        )
        title_label.pack(padx=20, pady=(20, 2), anchor="w")

        subtitle = ctk.CTkLabel(
            self.sidebar_frame,
            text="Safe Residual Cleaner for Windows",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=self.COLOR_TEXT_MUTED,
            anchor="w",
        )
        subtitle.pack(padx=20, pady=(0, 20), anchor="w")

        # Category buttons
        nav_items = [
            ("All Findings", "all"),
            ("Orphan Folders", "orphan_dir"),
            ("Registry Residues", "registry"),
            ("Temporary Cache", "cache"),
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
                hover_color=("#E5E5E5", "#2D2D2D"),
                command=lambda t=tab_id: self._select_tab(t),
                font=ctk.CTkFont(family="Segoe UI", size=13),
            )
            btn.pack(padx=14, pady=3, fill="x")
            self.nav_buttons[tab_id] = btn

        self._highlight_active_nav("all")

        # Footer toggles
        spacer = ctk.CTkLabel(self.sidebar_frame, text="")
        spacer.pack(expand=True, fill="both")

        self.dry_run_switch = ctk.CTkSwitch(
            self.sidebar_frame,
            text="Simulation Only (Dry-Run)",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            command=self._on_toggle_dry_run,
        )
        if self.dry_run:
            self.dry_run_switch.select()
        self.dry_run_switch.pack(padx=18, pady=(0, 10), anchor="w")

        theme_switch = ctk.CTkSegmentedButton(
            self.sidebar_frame,
            values=["Dark", "Light"],
            command=ctk.set_appearance_mode,
            height=28,
        )
        theme_switch.set("Dark")
        theme_switch.pack(padx=18, pady=(0, 18), fill="x")

    def _build_header_strip(self) -> None:
        """Top action bar with prominent Scan and Delete buttons."""
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent", height=50)
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=24, pady=(16, 8))

        self.status_label = ctk.CTkLabel(
            self.header_frame,
            text="Ready · Safe System Protection Active",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=("black", "white"),
        )
        self.status_label.pack(side="left")

        # Primary Delete Action Button (in prominent Windows Red)
        self.delete_button = ctk.CTkButton(
            self.header_frame,
            text="Delete Selected Files",
            fg_color=self.COLOR_DELETE,
            hover_color=self.COLOR_DELETE_HOVER,
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            height=34,
            corner_radius=6,
            command=self._confirm_purge_execution,
        )
        self.delete_button.pack(side="right", padx=(10, 0))

        # Scan Button (in Windows Accent Blue)
        self.scan_button = ctk.CTkButton(
            self.header_frame,
            text="Scan For Leftovers",
            fg_color=self.COLOR_ACCENT,
            hover_color=self.COLOR_ACCENT_HOVER,
            text_color="white",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            height=34,
            corner_radius=6,
            command=self._start_scan_thread,
        )
        self.scan_button.pack(side="right")

    def _build_metric_overview(self) -> None:
        """Disk space reclaimed metric and item counters."""
        metrics_container = ctk.CTkFrame(
            self.main_frame,
            fg_color=(self.COLOR_CARD_LIGHT, self.COLOR_CARD_DARK),
            corner_radius=8,
            border_width=1,
            border_color=("#E0E0E0", "#383838"),
        )
        metrics_container.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 12))

        self.reclaim_label = ctk.CTkLabel(
            metrics_container,
            text="0.00 MB",
            font=ctk.CTkFont(family="Segoe UI Variable Display", size=26, weight="bold"),
        )
        self.reclaim_label.pack(side="left", padx=20, pady=14)

        desc_label = ctk.CTkLabel(
            metrics_container,
            text="Disk Space Reclaimable\nSelect files and click 'Delete Selected Files'",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=self.COLOR_TEXT_MUTED,
            justify="left",
        )
        desc_label.pack(side="left", padx=(0, 24))

        self.count_summary_label = ctk.CTkLabel(
            metrics_container,
            text="0 Items Found",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=self.COLOR_TEXT_MUTED,
        )
        self.count_summary_label.pack(side="right", padx=20)

    def _build_table_controls(self) -> None:
        """Selection buttons."""
        ctrl_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        ctrl_frame.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 6))

        self.select_all_btn = ctk.CTkButton(
            ctrl_frame,
            text="Select All (Safe)",
            width=120,
            height=28,
            corner_radius=5,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color="transparent",
            border_width=1,
            border_color=("#CCCCCC", "#4A4A4A"),
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
            border_color=("#CCCCCC", "#4A4A4A"),
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
        """Scrollable list of scanned leftover candidates."""
        self.scroll_table = ctk.CTkScrollableFrame(
            self.main_frame,
            corner_radius=8,
            fg_color=(self.COLOR_CARD_LIGHT, self.COLOR_CARD_DARK),
            border_width=1,
            border_color=("#E0E0E0", "#383838"),
        )
        self.scroll_table.grid(row=3, column=0, sticky="nsew", padx=24, pady=(0, 10))
        self.scroll_table.grid_columnconfigure(1, weight=1)

        self._render_empty_table_state()

    def _render_empty_table_state(self) -> None:
        for child in self.scroll_table.winfo_children():
            child.destroy()

        empty_label = ctk.CTkLabel(
            self.scroll_table,
            text="No residual items found yet.\nClick 'Scan For Leftovers' above to find leftover folders, files, and registry keys.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=self.COLOR_TEXT_MUTED,
            justify="center",
        )
        empty_label.pack(pady=70)

    def _build_log_drawer(self) -> None:
        """Activity console showing real-time scanning and deletion events."""
        self.drawer_frame = ctk.CTkFrame(
            self.main_frame,
            height=110,
            corner_radius=6,
            fg_color=(self.COLOR_SIDEBAR_LIGHT, self.COLOR_SIDEBAR_DARK),
            border_width=1,
            border_color=("#E0E0E0", "#383838"),
        )
        self.drawer_frame.grid(row=4, column=0, sticky="ew", padx=24, pady=(0, 14))
        self.drawer_frame.grid_propagate(False)

        drawer_header = ctk.CTkFrame(self.drawer_frame, fg_color="transparent", height=22)
        drawer_header.pack(fill="x", padx=10, pady=(4, 2))

        console_title = ctk.CTkLabel(
            drawer_header,
            text="Activity & Deletion Log",
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
        self.log_textbox.pack(fill="both", expand=True, padx=6, pady=(0, 4))
        self.log_message("[System] Leftover-Cleaner initialized. Click 'Scan For Leftovers' to begin.")

    def log_message(self, message: str) -> None:
        self.log_textbox.insert("end", f"{message}\n")
        self.log_textbox.see("end")

    def _highlight_active_nav(self, active_tab: str) -> None:
        for tab_id, btn in self.nav_buttons.items():
            if tab_id == active_tab:
                btn.configure(fg_color=("#E0E0E0", "#363636"))
            else:
                btn.configure(fg_color="transparent")

    def _select_tab(self, tab_id: str) -> None:
        self.active_tab = tab_id
        self._highlight_active_nav(tab_id)
        self._refresh_table_view()

    def _on_toggle_dry_run(self) -> None:
        self.dry_run = self.dry_run_switch.get() == 1
        status = "Simulation Only (No deletion)" if self.dry_run else "Active Permanent Deletion"
        self.log_message(f"[Config] Mode changed to: {status}")

    def _start_scan_thread(self) -> None:
        if self.is_scanning:
            return

        self.is_scanning = True
        self.scan_button.configure(state="disabled", text="Scanning...")
        self.status_label.configure(text="Scanning AppData, ProgramData, and Registry hives...")
        self.log_message("[Scanner] Starting full system leftover scan...")

        thread = threading.Thread(target=self._run_scan_worker, daemon=True)
        thread.start()

    def _run_scan_worker(self) -> None:
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
        self.scan_button.configure(state="normal", text="Scan For Leftovers")
        self.status_label.configure(text=f"Scan Finished · Found {len(self.scanned_items)} leftover items")

        self._update_metrics()
        self.log_message(f"[Scanner] Found {len(self.scanned_items)} leftover candidates.")
        self._refresh_table_view()

    def _update_metrics(self) -> None:
        total_bytes = sum(it.size_bytes for it in self.scanned_items)
        mb = total_bytes / (1024 * 1024)
        self.reclaim_label.configure(text=f"{mb:.2f} MB")

        orphans = sum(1 for it in self.scanned_items if it.category == "orphan_dir")
        regs = sum(1 for it in self.scanned_items if it.category == "registry")
        caches = sum(1 for it in self.scanned_items if it.category == "cache")
        self.count_summary_label.configure(
            text=f"{len(self.scanned_items)} Total  ({orphans} Folders, {regs} Registry, {caches} Cache)"
        )

    def _refresh_table_view(self) -> None:
        """Render the list with checkboxes AND direct individual Delete buttons on each row."""
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
                fg_color="transparent" if row_i % 2 == 0 else ("#F8F8F8", "#252525"),
                height=38,
            )
            row_frame.pack(fill="x", padx=4, pady=1)

            # 1. Checkbox for bulk delete
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
            cb.pack(side="left", padx=(6, 2))

            # 2. Name and Type
            name_label = ctk.CTkLabel(
                row_frame,
                text=f"{item.name}",
                font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                anchor="w",
                width=190,
            )
            name_label.pack(side="left", padx=4)

            # 3. Path
            path_display = item.path if len(item.path) < 50 else item.path[:47] + "..."
            path_lbl = ctk.CTkLabel(
                row_frame,
                text=path_display,
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=self.COLOR_TEXT_MUTED,
                anchor="w",
            )
            path_lbl.pack(side="left", fill="x", expand=True, padx=6)

            # 4. Size
            size_mb = item.size_bytes / (1024 * 1024)
            size_text = f"{size_mb:.2f} MB" if size_mb >= 0.1 else f"{item.size_bytes / 1024:.0f} KB"
            size_lbl = ctk.CTkLabel(
                row_frame,
                text=size_text,
                font=ctk.CTkFont(family="Consolas", size=11),
                anchor="e",
                width=75,
            )
            size_lbl.pack(side="right", padx=8)

            # 5. Direct 1-Click Individual Delete Button
            del_btn = ctk.CTkButton(
                row_frame,
                text="Delete",
                width=65,
                height=26,
                corner_radius=4,
                fg_color=self.COLOR_DELETE,
                hover_color=self.COLOR_DELETE_HOVER,
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                command=lambda it=item, r_idx=real_idx: self._delete_single_item(it, r_idx),
            )
            del_btn.pack(side="right", padx=(4, 8))

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

    def _delete_single_item(self, item: ScanResultItem, idx: int) -> None:
        """Prompt and directly delete an individual file, folder, or registry key."""
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Permanently delete this leftover?\n\nTarget: {item.name}\nPath: {item.path}\nSize: {item.size_bytes / (1024*1024):.2f} MB",
        )
        if not confirm:
            return

        self.log_message(f"[Delete] Removing: {item.path}")
        success, msg = self.safety.permanently_delete(item.path, item.category)

        if success:
            self.log_message(f"[Deleted] {item.name} removed successfully.")
            # Remove from items list
            if idx < len(self.scanned_items) and self.scanned_items[idx] == item:
                self.scanned_items.pop(idx)
            else:
                self.scanned_items = [it for it in self.scanned_items if it != item]

            self.selected_indices = {i for i, it in enumerate(self.scanned_items) if it.confidence_score >= 80}
            self._update_metrics()
            self._refresh_table_view()
            messagebox.showinfo("Success", f"'{item.name}' has been permanently deleted.")
        else:
            self.log_message(f"[Failed] Could not delete {item.name}: {msg}")
            messagebox.showerror("Error", f"Could not delete {item.name}:\n{msg}")

    def _confirm_purge_execution(self) -> None:
        """Bulk delete all selected leftover files and folders."""
        if not self.selected_indices:
            messagebox.showwarning("No Items Selected", "Please select at least one item using the checkboxes to delete.")
            return

        selected_items = [self.scanned_items[i] for i in self.selected_indices]
        total_mb = sum(it.size_bytes for it in selected_items) / (1024 * 1024)

        if self.dry_run:
            messagebox.showinfo(
                "Dry-Run Mode",
                f"Simulation Mode is ON.\n\n{len(selected_items)} item(s) selected ({total_mb:.2f} MB).\nTurn off 'Simulation Only' switch in sidebar to delete permanently.",
            )
            return

        # Simple, clear confirmation
        confirm = messagebox.askyesno(
            "Confirm Permanent Deletion",
            f"Are you sure you want to permanently delete {len(selected_items)} selected leftover item(s)?\n\nDisk space to reclaim: {total_mb:.2f} MB\n\nThis cannot be undone.",
        )
        if not confirm:
            return

        self.log_message(f"[Action] Starting deletion of {len(selected_items)} items...")

        freed_bytes = 0
        deleted_count = 0
        failed_count = 0

        for item in selected_items:
            success, msg = self.safety.permanently_delete(item.path, item.category)
            if success:
                freed_bytes += item.size_bytes
                deleted_count += 1
                self.log_message(f"  [Deleted] {item.name}")
            else:
                failed_count += 1
                self.log_message(f"  [Failed] {item.name}: {msg}")

        freed_mb = freed_bytes / (1024 * 1024)
        self.log_message(f"[Finished] Deleted {deleted_count} items ({freed_mb:.2f} MB freed).")

        # Remove deleted items from UI list
        self.scanned_items = [it for it in self.scanned_items if it not in selected_items]
        self.selected_indices.clear()
        self._update_metrics()
        self._refresh_table_view()

        messagebox.showinfo(
            "Cleanup Complete",
            f"Successfully deleted {deleted_count} items!\nFreed {freed_mb:.2f} MB of disk space."
            + (f"\n\n({failed_count} item(s) were locked by active system processes and skipped)." if failed_count else "")
        )
