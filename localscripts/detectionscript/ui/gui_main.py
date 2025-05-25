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
# from ui.gui_dns import DnsMonitorWindow # Removed
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
        self.master = master
        self.master.title("Network Monitor")
        self.master.geometry(WINDOW_GEOMETRY)
        logger.info("Initializing PacketStatsGUI...")

        # References to open Toplevel windows
        self.temporal_window_ref = None
        # self.dns_monitor_window_ref = None # Removed
        self.detail_window_refs = [] # Can have multiple detail windows
        # Config windows are typically modal or short-lived, but can be tracked if complex.
        self.unsafe_config_window_ref = None
        self.scan_config_window_ref = None
        self.blocklist_manager_window_ref = None
        self.whitelist_manager_window_ref = None


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
        """Gracefully handle window closing, ensuring child Toplevels are closed first."""
        logger.info("Main application on_close triggered.")

        # Cancel scheduled updates for the main GUI
        if self._update_scheduled:
            try:
                self.master.after_cancel(self._update_scheduled)
                logger.debug("Main GUI update loop cancelled.")
            except tk.TclError:
                logger.debug("TclError cancelling main GUI update (already cancelled/invalid).")
            self._update_scheduled = None
        
        # Attempt to close known Toplevel windows gracefully
        # This allows their own WM_DELETE_WINDOW handlers (on_close methods) to execute
        window_refs_to_close = [
            self.temporal_window_ref, # self.dns_monitor_window_ref, # Removed
            self.unsafe_config_window_ref, self.scan_config_window_ref,
            self.blocklist_manager_window_ref, self.whitelist_manager_window_ref
        ]
        # Add all detail windows
        window_refs_to_close.extend(self.detail_window_refs)

        for window_instance in window_refs_to_close:
            if window_instance and window_instance.winfo_exists():
                try:
                    logger.info(f"Attempting to close child window: {window_instance.title()}")
                    window_instance.destroy() # This should trigger its on_close via WM_DELETE_WINDOW
                except tk.TclError as e:
                    logger.warning(f"TclError closing child window {window_instance.title()}: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error closing child window {window_instance.title()}: {e}", exc_info=True)
        
        # Clear the list of detail windows after attempting to close them
        self.detail_window_refs.clear()

        # Give Tkinter a moment to process these destruction events if necessary
        # self.master.update_idletasks() # Usually not needed if destroy is handled well

        # Finally, destroy the main window
        try:
            if self.master.winfo_exists():
                logger.info("Destroying main application window.")
                self.master.destroy()
                logger.info("Main application window destroyed.")
            else:
                logger.info("Main application window already destroyed.")
        except tk.TclError as e:
            logger.warning(f"TclError destroying main window: {e} (likely already gone).")
        except Exception as e:
            logger.error(f"Unexpected error destroying main window: {e}", exc_info=True)


    def _clear_window_reference(self, window_instance, ref_attr_name=None, ref_list_name=None):
        """Clears a reference to a closed Toplevel window."""
        logger.debug(f"Clearing reference for window: {window_instance}, attr: {ref_attr_name}, list: {ref_list_name}")
        if ref_attr_name and hasattr(self, ref_attr_name) and getattr(self, ref_attr_name) == window_instance:
            setattr(self, ref_attr_name, None)
            logger.debug(f"Cleared attribute reference: {ref_attr_name}")
        elif ref_list_name and hasattr(self, ref_list_name):
            try:
                getattr(self, ref_list_name).remove(window_instance)
                logger.debug(f"Removed window from list reference: {ref_list_name}")
            except ValueError:
                logger.debug(f"Window not found in list reference: {ref_list_name}")
        
        # The window's own WM_DELETE_WINDOW protocol should handle its actual destruction.
        # If this clear_window_reference is called by that protocol, we don't want to call destroy() again.
        # However, if this is called for other reasons, ensure it's destroyed.
        # For now, assume WM_DELETE_WINDOW on the Toplevel handles its own destroy().


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
        # tk.Button(row2_frame, text="DNS Mon", command=self.open_dns_monitor).pack(side=tk.LEFT, padx=3) # Removed

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
        if self.unsafe_config_window_ref and self.unsafe_config_window_ref.winfo_exists():
            self.unsafe_config_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.unsafe_config_window_ref = top # Store reference
        UnsafeConfigWindow(top)
        top.protocol("WM_DELETE_WINDOW", lambda t=top: (UnsafeConfigWindow(t).master.destroy(), self._clear_window_reference(t, "unsafe_config_window_ref")))


    def open_temporal_analysis(self):
        logger.debug("Opening Temporal Analysis window.")
        if self.temporal_window_ref and self.temporal_window_ref.winfo_exists():
            self.temporal_window_ref.lift() # Bring to front if already open
            return
        top = tk.Toplevel(self.master)
        self.temporal_window_ref = top # Store reference
        # The TemporalAnalysisWindow itself sets its WM_DELETE_WINDOW to its on_close method.
        # We need to ensure our reference is cleared when it's closed by its 'X' button.
        # The on_close in TemporalAnalysisWindow will call top.destroy().
        # We hook into that to clear our reference.
        temporal_instance = TemporalAnalysisWindow(top)
        top.protocol("WM_DELETE_WINDOW", lambda t=top, ti=temporal_instance: (ti.on_close(), self._clear_window_reference(t, "temporal_window_ref")))

    # Removed open_dns_monitor method

    def configure_scan(self):
        logger.debug("Opening Scan Detection Configuration window.")
        if self.scan_config_window_ref and self.scan_config_window_ref.winfo_exists():
            self.scan_config_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.scan_config_window_ref = top
        ScanConfigWindow(top) # This window manages its own closure.
        top.protocol("WM_DELETE_WINDOW", lambda t=top: (ScanConfigWindow(t).master.destroy(), self._clear_window_reference(t, "scan_config_window_ref")))


    def open_blocklist_manager(self):
        logger.debug("Opening Blocklist Manager window.")
        if self.blocklist_manager_window_ref and self.blocklist_manager_window_ref.winfo_exists():
            self.blocklist_manager_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.blocklist_manager_window_ref = top
        gui_blocklist_manager.BlocklistManagerWindow(top)
        top.protocol("WM_DELETE_WINDOW", lambda t=top: (gui_blocklist_manager.BlocklistManagerWindow(t).master.destroy(), self._clear_window_reference(t, "blocklist_manager_window_ref")))


    def open_whitelist_manager(self):
        logger.debug("Opening Whitelist Manager window.")
        if self.whitelist_manager_window_ref and self.whitelist_manager_window_ref.winfo_exists():
            self.whitelist_manager_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.whitelist_manager_window_ref = top
        WhitelistManagerWindow(top)
        top.protocol("WM_DELETE_WINDOW", lambda t=top: (WhitelistManagerWindow(t).master.destroy(), self._clear_window_reference(t, "whitelist_manager_window_ref")))

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
            
            # Check if a detail window for this IP is already open
            for existing_detail_top, ip_in_detail in self.detail_window_refs:
                if ip_in_detail == source_ip and existing_detail_top.winfo_exists():
                    existing_detail_top.lift()
                    return

            detail_top = tk.Toplevel(self.master)
            # Store tuple of (window_instance, ip_string)
            detail_ref_tuple = (detail_top, source_ip)
            self.detail_window_refs.append(detail_ref_tuple)

            detail_instance = DetailWindow(
                detail_top,
                source_ip,
                self.get_flag_unsafe,    # Pass getter functions for live flag status
                self.get_flag_malicious,
                self.get_flag_scan
            )
            # Handle closure of detail window to remove from list
            detail_top.protocol("WM_DELETE_WINDOW", 
                lambda t=detail_top, dt_instance=detail_instance, ref=detail_ref_tuple: (
                    dt_instance.on_close() if hasattr(dt_instance, 'on_close') else t.destroy(), 
                    self._clear_window_reference(t, ref_list_name="detail_window_refs")
                )
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
            selected_ip_address = None
            focused_item_id = self.tree.focus() # Get the ID of the currently focused item
            if focused_item_id:
                # Get the values of the focused item, IP is assumed to be the first value
                item_values = self.tree.item(focused_item_id, "values")
                if item_values and len(item_values) > 0:
                    selected_ip_address = item_values[0]
                    logger.debug(f"Preserving selection: IP {selected_ip_address}")

            scroll_position = self.tree.yview() # Preserve scroll position

            self.tree.delete(*self.tree.get_children()) # Clear existing rows

            new_item_id_to_select = None
            for row_data in data_for_table:
                ip_val, total_val, pmin_val, psec_val, maxp_val, flag_val = row_data
                tags_to_apply = (TAG_ALERT,) if flag_val else ()
                # Insert the new row and get its item ID
                current_item_id = self.tree.insert("", tk.END, values=(ip_val, total_val, pmin_val, psec_val, maxp_val), tags=tags_to_apply)
                # If this IP matches the previously selected one, store its new item ID
                if selected_ip_address and ip_val == selected_ip_address:
                    new_item_id_to_select = current_item_id
            
            # If we found the previously selected IP among the new items, re-select it
            if new_item_id_to_select:
                logger.debug(f"Restoring selection to item ID: {new_item_id_to_select} for IP: {selected_ip_address}")
                self.tree.focus(new_item_id_to_select)
                self.tree.selection_set(new_item_id_to_select)
                # Optionally, ensure the selected item is visible
                # self.tree.see(new_item_id_to_select) 
            
            self.tree.yview_moveto(scroll_position[0]) # Restore scroll position
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
