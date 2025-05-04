# ui/gui_main.py
import time
import tkinter as tk
from tkinter import ttk, messagebox
import logging
from collections import deque
import ipaddress

# Import core components
from core.config_manager import config
from core.whitelist_manager import get_whitelist
from core.capture import ip_data, lock, aggregate_minute_data
from core.blocklist_integration import download_blocklists, load_blocklists

# Import UI components
from ui.gui_unsafe import UnsafeConfigWindow
from ui.gui_temporal import TemporalAnalysisWindow
import ui.gui_blocklist_manager as gui_blocklist_manager
from ui.gui_detail import DetailWindow
from ui.gui_dns import DnsMonitorWindow
from ui.gui_scan_config import ScanConfigWindow
from ui.gui_whitelist_manager import WhitelistManagerWindow

logger = logging.getLogger(__name__)
whitelist = get_whitelist() # Get the singleton instance

# --- Constants ---
UPDATE_INTERVAL_MS = 1000
AGGREGATION_INTERVAL_MS = 60000
PRUNE_SECONDS = 61 # Prune data slightly older than 1 minute
TAG_ALERT = "red" # Tag name for flagged rows
COLOR_ALERT_BG = "#FF9999" # Background color for flagged rows
WINDOW_GEOMETRY = "950x600"
# --- End Constants ---

class PacketStatsGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Network Monitor")
        self.master.geometry(WINDOW_GEOMETRY)
        logger.info("Initializing PacketStatsGUI...")

        # Attempt blocklist initialization early, notify user on failure
        try:
            logger.info("Downloading/loading blocklists (if needed)...")
            download_blocklists(force_download=False)
            load_blocklists()
            logger.info("Blocklists processed.")
        except Exception as e:
            logger.error(f"Blocklist initialization error: {e}", exc_info=True)
            messagebox.showerror("Blocklist Error", f"Failed to load blocklists: {e}\nBlocklist features may be disabled.")

        self.current_sort_column = "max_per_sec" # Default sort
        self.current_sort_ascending = False

        top_frame = tk.Frame(self.master)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        self.add_description_frame(top_frame)
        self.add_configuration_frame(top_frame)

        table_frame = tk.Frame(self.master)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.add_table_frame(table_frame)

        self.schedule_aggregation()
        self._update_scheduled = None # Handle for the update loop
        self.update_gui() # Start the first update

        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
        logger.info("PacketStatsGUI initialized.")

    def on_close(self):
        """Gracefully handle window closing."""
        logger.info("Closing main window.")
        if self._update_scheduled:
            try:
                self.master.after_cancel(self._update_scheduled)
            except tk.TclError:
                # Might happen if window is already destroyed
                pass
            self._update_scheduled = None
        try:
            # Ensure the window is destroyed if not already
            if self.master.winfo_exists():
                self.master.destroy()
        except tk.TclError:
            pass # Window likely already gone

    def add_description_frame(self, parent_frame):
        """Adds the description label."""
        desc_text = ("Monitor network activity. Double-click IP for details.\n"
                     f"Rows flagged {TAG_ALERT} based on Threshold and enabled Flags.")
        tk.Label(parent_frame, text=desc_text, justify=tk.LEFT).pack(side=tk.TOP, anchor="w", pady=(0, 5))

    def add_configuration_frame(self, parent_frame):
        """Adds the configuration controls (threshold, flags, buttons)."""
        config_frame = tk.Frame(parent_frame)
        config_frame.pack(side=tk.TOP, fill=tk.X, anchor='w')

        # --- Row 1: Threshold and Flags ---
        row1_frame = tk.Frame(config_frame)
        row1_frame.pack(fill=tk.X, pady=2)

        tk.Label(row1_frame, text="Pkts/Min Threshold:").pack(side=tk.LEFT, padx=(0, 2)) # Changed Text
        self.threshold_var = tk.StringVar(value=str(config.max_packets_per_minute))
        self.threshold_entry = tk.Entry(row1_frame, width=8, textvariable=self.threshold_var)
        self.threshold_entry.pack(side=tk.LEFT, padx=(0, 10)) # Increased padding
        self.threshold_var.trace_add("write", self.update_threshold_config)

        # Flag Checkboxes
        self.flag_unsafe_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row1_frame, text="Flag Unsafe", variable=self.flag_unsafe_var).pack(side=tk.LEFT, padx=2)
        self.flag_malicious_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row1_frame, text="Flag Malicious IP", variable=self.flag_malicious_var).pack(side=tk.LEFT, padx=2)
        self.flag_dns_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row1_frame, text="Flag Bad DNS", variable=self.flag_dns_var).pack(side=tk.LEFT, padx=2)
        self.flag_scan_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row1_frame, text="Flag Scan", variable=self.flag_scan_var).pack(side=tk.LEFT, padx=2)

        # --- Row 2: Configuration Buttons ---
        row2_frame = tk.Frame(config_frame)
        row2_frame.pack(fill=tk.X, pady=2)

        tk.Button(row2_frame, text="Conf Unsafe", command=self.configure_unsafe).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Conf Scan", command=self.configure_scan).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Blocklists", command=self.open_blocklist_manager).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Whitelist", command=self.open_whitelist_manager).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Temporal", command=self.open_temporal_analysis).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="DNS Mon", command=self.open_dns_monitor).pack(side=tk.LEFT, padx=3)

    def add_table_frame(self, parent_frame):
        """Adds the main statistics table (Treeview)."""
        columns = ("ip", "total", "per_minute", "per_second", "max_per_sec")
        self.tree = ttk.Treeview(parent_frame, columns=columns, show="headings")

        # Column definitions (header, width, anchor)
        headers = {"ip": "IP Address", "total": "Total Pkts", "per_minute": "Pkts/Min",
                   "per_second": "Pkts/Sec", "max_per_sec": "Max P/S"}
        widths = {"ip": 150, "total": 100, "per_minute": 100, "per_second": 100, "max_per_sec": 100}
        anchors = {"ip": tk.W, "total": tk.CENTER, "per_minute": tk.CENTER,
                   "per_second": tk.CENTER, "max_per_sec": tk.CENTER}

        for col in columns:
            self.tree.heading(col, text=headers[col], anchor=tk.CENTER,
                              command=lambda c=col: self.sort_column(c))
            self.tree.column(col, width=widths[col], anchor=anchors[col])

        # Scrollbar
        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Tag for flagged rows
        self.tree.tag_configure(TAG_ALERT, background=COLOR_ALERT_BG)
        # Bind double-click event
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def update_threshold_config(self, *args):
        """Callback when threshold entry changes."""
        try:
            new_thresh = int(self.threshold_var.get())
            if new_thresh >= 0:
                config.max_packets_per_minute = new_thresh
                logger.debug(f"GUI Threshold updated: {config.max_packets_per_second}")
            else:
                 logger.warning(f"Ignoring negative threshold input: {new_thresh}")
                 # Reset entry to current valid value if input was negative
                 self.threshold_var.set(str(config.max_packets_per_second))
        except ValueError:
            logger.warning(f"Invalid integer input for threshold: '{self.threshold_var.get()}'")
            # Reset entry to current valid value if input was not an integer
            self.threshold_var.set(str(config.max_packets_per_second))
        except Exception as e: # Fallback for unexpected errors
            logger.error(f"Unexpected error updating threshold config: {e}", exc_info=True)

    def schedule_aggregation(self):
        """Schedules the periodic aggregation of minute data."""
        logger.debug("Scheduling next data aggregation...")
        try:
            aggregate_minute_data()
        except Exception as e:
            logger.error(f"Error during scheduled aggregation: {e}", exc_info=True)
        finally:
            # Reschedule even if an error occurred
            if self.master.winfo_exists():
                self.master.after(AGGREGATION_INTERVAL_MS, self.schedule_aggregation)

    # --- Configuration Window Openers ---
    def configure_unsafe(self):
        logger.debug("Opening Unsafe Configuration window.")
        top = tk.Toplevel(self.master)
        UnsafeConfigWindow(top)

    def open_temporal_analysis(self):
        logger.debug("Opening Temporal Analysis window.")
        top = tk.Toplevel(self.master)
        TemporalAnalysisWindow(top)

    def open_dns_monitor(self):
        logger.debug("Opening DNS Monitor window.")
        top = tk.Toplevel(self.master)
        DnsMonitorWindow(top)

    def configure_scan(self):
        logger.debug("Opening Scan Detection Configuration window.")
        top = tk.Toplevel(self.master)
        ScanConfigWindow(top)

    def open_blocklist_manager(self):
        logger.debug("Opening Blocklist Manager window.")
        top = tk.Toplevel(self.master)
        gui_blocklist_manager.BlocklistManagerWindow(top)

    def open_whitelist_manager(self):
        logger.debug("Opening Whitelist Manager window.")
        top = tk.Toplevel(self.master)
        WhitelistManagerWindow(top)

    # --- Flag Getters ---
    def get_flag_unsafe(self): return self.flag_unsafe_var.get()
    def get_flag_malicious(self): return self.flag_malicious_var.get()
    def get_flag_dns(self): return self.flag_dns_var.get()
    def get_flag_scan(self): return self.flag_scan_var.get()

    def on_double_click(self, event):
        """Handles double-clicking on a row in the table."""
        focused_item_id = self.tree.focus() # Get ID of the focused item
        if not focused_item_id:
            logger.warning("Double-click event with no row selected.")
            return

        try:
            item_values = self.tree.item(focused_item_id)["values"]
            source_ip = item_values[0] if item_values else None

            if not source_ip:
                logger.warning(f"Double-clicked row {focused_item_id} has no values or IP.")
                return

            logger.info(f"Double-clicked IP: {source_ip}. Opening detail window.")
            # Open the detail window
            detail_top = tk.Toplevel(self.master)
            DetailWindow(
                detail_top,
                source_ip,
                self.get_flag_unsafe,    # Pass getter functions for live flag status
                self.get_flag_malicious,
                self.get_flag_scan
            )
        except IndexError:
            logger.error(f"Could not extract IP from row {focused_item_id}. Values: {item_values}", exc_info=True)
        except Exception as e:
            logger.error(f"Error opening detail window for IP {source_ip}: {e}", exc_info=True)
            messagebox.showerror("Error", f"Could not open detail window:\n{e}")

    def update_gui(self):
        """Periodically updates the statistics table."""
        # Stop updates if the main window is closed
        if not self.master.winfo_exists():
            logger.warning("Main window closed, stopping GUI updates.")
            self._update_scheduled = None
            return

        try:
            # Get current configuration values
            threshold = config.max_packets_per_minute
            flag_unsafe_enabled = self.get_flag_unsafe()
            flag_malicious_enabled = self.get_flag_malicious()
            flag_dns_enabled = self.get_flag_dns()
            flag_scan_enabled = self.get_flag_scan()

            now = time.time()
            prune_timestamp = now - PRUNE_SECONDS
            data_for_table = []

            # Acquire lock to safely read shared data
            with lock:
                # Iterate over a copy of keys to avoid issues if dict changes during iteration (shouldn't happen with lock)
                ip_keys = list(ip_data.keys())

                for ip in ip_keys:
                    # Re-check if IP still exists within the lock
                    if ip not in ip_data:
                        continue

                    # Skip whitelisted source IPs
                    if whitelist.is_ip_whitelisted(ip):
                        logger.debug(f"Skipping whitelisted source IP {ip}")
                        continue

                    data = ip_data[ip]
                    timestamps_deque = data.get("timestamps", deque())

                    # Prune old timestamps (modifies deque, needs lock)
                    while timestamps_deque and timestamps_deque[0] < prune_timestamp:
                        timestamps_deque.popleft()

                    total_packets = data.get("total", 0)
                    packets_per_minute = len(timestamps_deque) # Count remaining timestamps

                    # Calculate packets in the last second
                    one_second_ago = now - 1.0
                    packets_per_second = sum(1 for t in timestamps_deque if t >= one_second_ago)

                    # Update and get max packets per second (needs lock)
                    data["max_per_sec"] = max(data.get("max_per_sec", 0), packets_per_second)
                    max_packets_sec = data["max_per_sec"]

                    # Determine if the row should be flagged
                    is_over_threshold = packets_per_minute > threshold
                    is_unsafe_triggered = False
                    if flag_unsafe_enabled:
                        ports_used = set(p[1] for p in data.get("protocols", {}).keys() if p[1] is not None)
                        protocols_used = set(p[0] for p in data.get("protocols", {}).keys() if p[0] is not None)
                        if not config.unsafe_ports.isdisjoint(ports_used):
                            is_unsafe_triggered = True
                        if not config.unsafe_protocols.isdisjoint(protocols_used):
                            is_unsafe_triggered = True

                    is_malicious_triggered = flag_malicious_enabled and data.get("contacted_malicious_ip", False)
                    is_dns_triggered = flag_dns_enabled and bool(data.get("suspicious_dns"))
                    is_scan_detected = flag_scan_enabled and (data.get("detected_scan_ports", False) or data.get("detected_scan_hosts", False))

                    # Combine flags
                    should_flag_row = (is_over_threshold or is_unsafe_triggered or
                                       is_malicious_triggered or is_dns_triggered or is_scan_detected)

                    data_for_table.append((ip, total_packets, packets_per_minute,
                                           packets_per_second, max_packets_sec, should_flag_row))

            # Sort data if a sort column is set
            if self.current_sort_column:
                data_for_table = self.sort_data(data_for_table, self.current_sort_column, self.current_sort_ascending)

            # --- Update Treeview ---
            selected_item_id = self.tree.focus() # Preserve selection
            scroll_position = self.tree.yview() # Preserve scroll position

            self.tree.delete(*self.tree.get_children()) # Clear existing rows

            for row_data in data_for_table:
                ip_val, total_val, pmin_val, psec_val, maxp_val, flag_val = row_data
                tags_to_apply = (TAG_ALERT,) if flag_val else ()
                self.tree.insert("", tk.END, values=(ip_val, total_val, pmin_val, psec_val, maxp_val), tags=tags_to_apply)

            # Restore selection and scroll position if possible
            if selected_item_id and self.tree.exists(selected_item_id):
                self.tree.focus(selected_item_id)
                self.tree.selection_set(selected_item_id)
            self.tree.yview_moveto(scroll_position[0])
            # --- End Treeview Update ---

        except Exception as e:
            logger.error(f"Error during main GUI update: {e}", exc_info=True)
            # Avoid continuous errors by logging once or implementing backoff? For now, just log.
        finally:
            # Reschedule the next update if the window still exists
            if self.master.winfo_exists():
                self._update_scheduled = self.master.after(UPDATE_INTERVAL_MS, self.update_gui)
            else:
                self._update_scheduled = None # Ensure handle is cleared if window closed between checks

    def sort_data(self, data, column, ascending):
        """Sorts the table data based on the selected column."""
        column_map = {"ip": 0, "total": 1, "per_minute": 2, "per_second": 3, "max_per_sec": 4}
        try:
            col_index = column_map[column]
            reverse_sort = not ascending

            if column == "ip":
                # Sort by IP address correctly
                key_func = lambda x: ipaddress.ip_address(str(x[col_index]))
            else:
                # Sort numerically, treating non-numeric as 0
                key_func = lambda x: float(x[col_index]) if isinstance(x[col_index], (int, float)) else 0.0

            return sorted(data, key=key_func, reverse=reverse_sort)

        except (KeyError, IndexError, ValueError, ipaddress.AddressValueError) as e:
            logger.error(f"Sorting error on column '{column}': {e}", exc_info=True)
            return data # Return unsorted data on error

    def sort_column(self, column):
        """Handles clicking on a column header to sort."""
        logger.debug(f"Sort requested for column: {column}")
        if column == self.current_sort_column:
            # Toggle sort direction
            self.current_sort_ascending = not self.current_sort_ascending
        else:
            # Set new sort column, default to ascending
            self.current_sort_column = column
            self.current_sort_ascending = True
        # Implicitly triggers update in the next update_gui cycle where data is re-sorted