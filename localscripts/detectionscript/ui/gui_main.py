# gui_main.py
import time
import tkinter as tk
from tkinter import ttk, messagebox
import logging
from collections import deque, defaultdict

from core.capture import ip_data, lock, aggregate_minute_data
from ui.gui_unsafe import UnsafeConfigWindow
from ui.gui_temporal import TemporalAnalysisWindow
from ui.gui_blocklist_manager import open_blocklist_manager
from core.dns_blocklist_integration import download_dns_blocklists, load_dns_blocklists
# *** FIX: Import 'blocklists' correctly ***
from core.blocklist_integration import blocklists, download_blocklists, load_blocklists
from config.globals import UNSAFE_PORTS, UNSAFE_PROTOCOLS
from ui.gui_detail import DetailWindow
from ui.gui_dns import DnsMonitorWindow

logger = logging.getLogger(__name__)

class PacketStatsGUI:
    def __init__(self, master):
        """Initialize the main GUI window."""
        self.master = master
        self.master.title("Network Monitor")
        self.master.geometry("850x600")

        logger.info("Initializing PacketStatsGUI...")

        # Blocklist Initialization
        try:
            logger.info("Downloading and loading initial IP blocklists...")
            download_blocklists()
            load_blocklists()
            logger.info("Initial IP blocklists loaded.")
            logger.info("Downloading and loading initial DNS blocklists...")
            download_dns_blocklists()
            load_dns_blocklists()
            logger.info("Initial DNS blocklists loaded.")
        except Exception as e:
            logger.error(f"Failed to initialize blocklists: {e}", exc_info=True)
            messagebox.showerror("Blocklist Error", f"Failed to load initial blocklists: {e}")

        # Internal State
        self.current_sort_column = "max_per_sec"
        self.current_sort_ascending = False

        # GUI Structure
        top_frame = tk.Frame(self.master)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        self.add_description_frame(top_frame)
        self.add_configuration_frame(top_frame)

        table_frame = tk.Frame(self.master)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.add_table_frame(table_frame)

        # Background Tasks
        self.schedule_aggregation()
        self._update_scheduled = None
        self.update_gui()

        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
        logger.info("PacketStatsGUI initialized.")

    def on_close(self):
        """Handle window closing actions."""
        logger.info("Closing main application window.")
        if self._update_scheduled:
            try: self.master.after_cancel(self._update_scheduled)
            except tk.TclError: pass
            self._update_scheduled = None
        try: self.master.destroy()
        except tk.TclError: pass

    def add_description_frame(self, parent_frame):
        """Add description label."""
        desc_label_text = (
            "Monitor network participants by source IP. Double-click IP for details.\n"
            "Rows flagged red if Max P/S > Threshold, or if optional flags (Unsafe, Malicious, DNS) are triggered."
        )
        desc_label = tk.Label(parent_frame, text=desc_label_text, justify=tk.LEFT, anchor="w")
        desc_label.pack(side=tk.TOP, anchor="w", pady=(0, 5))

    def add_configuration_frame(self, parent_frame):
        """Add configuration options."""
        controls_frame = tk.Frame(parent_frame)
        controls_frame.pack(side=tk.TOP, fill=tk.X, anchor='w')

        row1_frame = tk.Frame(controls_frame); row1_frame.pack(fill=tk.X, pady=2)
        tk.Label(row1_frame, text="Max P/S Threshold:").pack(side=tk.LEFT, padx=(0, 2))
        self.threshold_entry = tk.Entry(row1_frame, width=8); self.threshold_entry.pack(side=tk.LEFT, padx=(0, 10)); self.threshold_entry.insert(0, "1000")
        self.flag_unsafe_var = tk.BooleanVar(value=False); tk.Checkbutton(row1_frame, text="Flag Unsafe", variable=self.flag_unsafe_var).pack(side=tk.LEFT, padx=5)
        self.flag_malicious_var = tk.BooleanVar(value=True); tk.Checkbutton(row1_frame, text="Flag Malicious IP", variable=self.flag_malicious_var).pack(side=tk.LEFT, padx=5)
        self.flag_dns_var = tk.BooleanVar(value=True); tk.Checkbutton(row1_frame, text="Flag Bad DNS", variable=self.flag_dns_var).pack(side=tk.LEFT, padx=5)

        row2_frame = tk.Frame(controls_frame); row2_frame.pack(fill=tk.X, pady=2)
        tk.Button(row2_frame, text="Configure Unsafe", command=self.configure_unsafe).pack(side=tk.LEFT, padx=5)
        tk.Button(row2_frame, text="Manage Blocklists", command=open_blocklist_manager).pack(side=tk.LEFT, padx=5)
        tk.Button(row2_frame, text="Temporal Analysis", command=self.open_temporal_analysis).pack(side=tk.LEFT, padx=5)
        tk.Button(row2_frame, text="DNS Monitor", command=self.open_dns_monitor).pack(side=tk.LEFT, padx=5)

    def add_table_frame(self, parent_frame):
        """Add the main Treeview table."""
        columns = ("ip", "total", "per_minute", "per_second", "max_per_sec")
        self.tree = ttk.Treeview(parent_frame, columns=columns, show="headings")
        self.tree.heading("ip", text="IP Address", anchor=tk.CENTER, command=lambda: self.sort_column("ip"))
        self.tree.heading("total", text="Total Pkts", anchor=tk.CENTER, command=lambda: self.sort_column("total"))
        self.tree.heading("per_minute", text="Pkts/Min", anchor=tk.CENTER, command=lambda: self.sort_column("per_minute"))
        self.tree.heading("per_second", text="Pkts/Sec", anchor=tk.CENTER, command=lambda: self.sort_column("per_second"))
        self.tree.heading("max_per_sec", text="Max P/S", anchor=tk.CENTER, command=lambda: self.sort_column("max_per_sec"))
        self.tree.column("ip", width=150, anchor=tk.W); self.tree.column("total", width=100, anchor=tk.CENTER)
        self.tree.column("per_minute", width=100, anchor=tk.CENTER); self.tree.column("per_second", width=100, anchor=tk.CENTER)
        self.tree.column("max_per_sec", width=100, anchor=tk.CENTER)
        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.tree.yview); self.tree.configure(yscrollcommand=scrollbar.set); scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.tag_configure("red", background="#FF9999"); self.tree.bind("<Double-1>", self.on_double_click); self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def schedule_aggregation(self):
        """Schedule periodic data aggregation."""
        logger.debug("Running periodic data aggregation.")
        try: aggregate_minute_data()
        except Exception as e: logger.error(f"Error during data aggregation: {e}", exc_info=True)
        finally:
            if self.master.winfo_exists(): self.master.after(60000, self.schedule_aggregation)

    def configure_unsafe(self):
        logger.debug("Opening Configure Unsafe Ports/Protocols window."); top = tk.Toplevel(self.master); UnsafeConfigWindow(top)
    def open_temporal_analysis(self):
        logger.debug("Opening Temporal Analysis window."); top = tk.Toplevel(self.master); TemporalAnalysisWindow(top, None, self.get_threshold)
    def open_dns_monitor(self):
        logger.debug("Opening DNS Monitor window."); top = tk.Toplevel(self.master); DnsMonitorWindow(top)
    def get_threshold(self):
        try: return int(self.threshold_entry.get())
        except ValueError: logger.warning(f"Invalid threshold value: '{self.threshold_entry.get()}'. Using 0."); return 0
    def get_flag_unsafe(self): return self.flag_unsafe_var.get()
    def get_flag_malicious(self): return self.flag_malicious_var.get()
    def get_flag_dns(self): return self.flag_dns_var.get()

    def on_double_click(self, event):
        """Handle double-click to show details."""
        row_id = self.tree.focus()
        if not row_id: logger.warning("Double-click event with no row focused."); return
        try:
            row_values = self.tree.item(row_id)["values"]
            if not row_values: logger.warning(f"Double-click on row {row_id} with no values."); return
            source_ip = row_values[0]
            logger.info(f"Double-click detected on IP: {source_ip}. Opening detail window.")
            top = tk.Toplevel(self.master)
            DetailWindow(top, source_ip, self.get_threshold, self.get_flag_unsafe, self.get_flag_malicious)
        except IndexError: logger.error(f"Could not extract IP from row {row_id} values: {row_values}", exc_info=True)
        except Exception as e: logger.error(f"Error opening detail window for row {row_id}: {e}", exc_info=True)

    def update_gui(self):
        """Update the main table with latest data and flags."""
        if not self.master.winfo_exists():
            logger.warning("Main window closed unexpectedly during update."); self._update_scheduled = None; return

        try:
            threshold = self.get_threshold()
            flag_unsafe = self.get_flag_unsafe()
            flag_mal_ip = self.get_flag_malicious()
            flag_dns_hit = self.get_flag_dns()
            now = time.time()
            prune_time_60s = now - 61

            data_for_table = []
            with lock:
                ip_keys = list(ip_data.keys())
                for ip in ip_keys:
                    if ip not in ip_data: continue
                    d = ip_data[ip]
                    timestamps_deque = d.get("timestamps", deque())
                    while timestamps_deque and timestamps_deque[0] < prune_time_60s:
                        timestamps_deque.popleft()

                    total = d.get("total", 0)
                    per_min = len(timestamps_deque)
                    one_sec_ago = now - 1.0
                    per_second = sum(1 for t in timestamps_deque if t >= one_sec_ago)
                    d["max_per_sec"] = max(d.get("max_per_sec", 0), per_second)
                    max_ps = d["max_per_sec"]

                    is_over_threshold = max_ps > threshold
                    unsafe_triggered = False
                    if flag_unsafe:
                        protocols_dict = d.get("protocols", {})
                        unsafe_port_found = any(p in UNSAFE_PORTS for (_, p) in protocols_dict if p is not None)
                        unsafe_protocol_found = any(p in UNSAFE_PROTOCOLS for (p, _) in protocols_dict if p is not None)
                        if unsafe_port_found or unsafe_protocol_found: unsafe_triggered = True

                    malicious_ip_triggered = flag_mal_ip and d.get("contacted_malicious_ip", False)
                    dns_hit_triggered = flag_dns_hit and bool(d.get("suspicious_dns"))

                    should_flag_red = is_over_threshold or unsafe_triggered or malicious_ip_triggered or dns_hit_triggered

                    data_for_table.append((ip, total, per_min, per_second, max_ps, should_flag_red))

            if self.current_sort_column:
                data_for_table = self.sort_data(data_for_table, self.current_sort_column, self.current_sort_ascending)

            selected_item = self.tree.focus()
            scroll_pos = self.tree.yview()
            self.tree.delete(*self.tree.get_children())
            for row in data_for_table:
                ip_val, total_val, per_min_val, per_sec_val, max_ps_val, flag_red = row
                tags = ("red",) if flag_red else ()
                self.tree.insert("", tk.END, values=(ip_val, total_val, per_min_val, per_sec_val, max_ps_val), tags=tags)
            if selected_item and self.tree.exists(selected_item):
                 self.tree.focus(selected_item)
                 self.tree.selection_set(selected_item)
            self.tree.yview_moveto(scroll_pos[0])

        except Exception as e:
            logger.error(f"Error updating main GUI: {e}", exc_info=True)
        finally:
            if self.master.winfo_exists():
                self._update_scheduled = self.master.after(1000, self.update_gui)
            else:
                self._update_scheduled = None

    def sort_data(self, data, column, ascending):
        """Sort table data by column."""
        col_map = {"ip": 0, "total": 1, "per_minute": 2, "per_second": 3, "max_per_sec": 4}
        try:
            col_index = col_map[column]
            if column == "ip":
                 import ipaddress # Import locally if needed for sorting
                 return sorted(data, key=lambda x: ipaddress.ip_address(str(x[col_index])), reverse=not ascending)
            else:
                 return sorted(data, key=lambda x: float(x[col_index]) if isinstance(x[col_index], (int, float)) else 0, reverse=not ascending)
        except (KeyError, IndexError, ValueError, ipaddress.AddressValueError) as e:
             logger.error(f"Error sorting data by column '{column}': {e}", exc_info=True)
             return data

    def sort_column(self, column):
        """Handle column header click for sorting."""
        logger.debug(f"Sorting column requested: {column}")
        if column == self.current_sort_column:
            self.current_sort_ascending = not self.current_sort_ascending
        else:
            self.current_sort_column = column
            self.current_sort_ascending = True
