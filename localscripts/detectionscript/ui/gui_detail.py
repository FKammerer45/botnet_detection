# ui/gui_detail.py
import time
import tkinter as tk
from tkinter import ttk
import logging
from collections import deque
import ipaddress

# Import core components
from core.config_manager import config
from core.whitelist_manager import get_whitelist
from core.capture import ip_data, lock
# from core.blocklist_integration import blocklists # Not directly needed, use config for active lists

logger = logging.getLogger(__name__)
whitelist = get_whitelist() # Get the singleton instance

# --- Constants ---
UPDATE_INTERVAL_MS = 1000
PRUNE_SECONDS = 61 # Prune data slightly older than 1 minute
TAG_ALERT = "red" # Tag name for flagged rows
COLOR_ALERT_BG = "#FF9999" # Background color for flagged rows
COLOR_SCAN_DETECTED = "red"
COLOR_SCAN_DISABLED = "grey"
COLOR_SCAN_NONE = "green"
COLOR_SCAN_DEFAULT = "black" # Should not be used if logic is correct
# --- End Constants ---


class DetailWindow:
    def __init__(self, master, source_ip, get_flag_unsafe_func, get_flag_malicious_func=None, get_flag_scan_func=None):
        self.master = master
        self.master.title(f"Details for {source_ip}")
        self.source_ip = source_ip
        logger.info(f"Opening detail window for IP: {self.source_ip}")

        # Store getter functions from the main GUI to check current flag states
        self.get_flag_unsafe_func = get_flag_unsafe_func
        self.get_flag_malicious_func = get_flag_malicious_func
        self.get_flag_scan_func = get_flag_scan_func

        # --- Main Structure: Notebook for Tabs ---
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Destinations Tab
        self.dest_frame = tk.Frame(self.notebook)
        self.notebook.add(self.dest_frame, text="Destinations")
        self._setup_destinations_tab()
        self.dest_sort_column = None # Track sorting state for this tab
        self.dest_sort_ascending = True

        # Protocols Tab
        self.proto_frame = tk.Frame(self.notebook)
        self.notebook.add(self.proto_frame, text="Protocols")
        self._setup_protocols_tab()
        self.proto_sort_column = None # Track sorting state for this tab
        self.proto_sort_ascending = True

        # Threat Info Tab
        self.threat_frame = tk.Frame(self.notebook)
        self.notebook.add(self.threat_frame, text="Threat Info")
        self._setup_threat_tab()
        # No sorting needed for threat tab currently

        # --- Scan Status Label (Below Tabs) ---
        self.scan_status_frame = tk.Frame(self.master)
        self.scan_status_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        self.scan_status_label = tk.Label(self.scan_status_frame, text="Scan Status: Initializing...",
                                          fg=COLOR_SCAN_DISABLED, anchor=tk.W)
        self.scan_status_label.pack(fill=tk.X)

        # --- Start Update Loop ---
        self._update_scheduled = None
        self.update_gui() # Start the first update
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Gracefully handle detail window closing."""
        logger.info(f"Closing detail window for IP: {self.source_ip}")
        if self._update_scheduled:
            try:
                self.master.after_cancel(self._update_scheduled)
            except tk.TclError:
                pass
            self._update_scheduled = None
        try:
            if self.master.winfo_exists():
                self.master.destroy()
        except tk.TclError:
            pass

    def _setup_destinations_tab(self):
        """Sets up the Treeview for the Destinations tab."""
        columns = ("dst_ip", "total", "per_second", "max_per_sec")
        self.dest_tree = ttk.Treeview(self.dest_frame, columns=columns, show='headings')

        headers = {"dst_ip": "Destination IP", "total": "Total Packets",
                   "per_second": "Packets/Sec", "max_per_sec": "Max P/S"}
        widths = {"dst_ip": 150, "total": 100, "per_second": 100, "max_per_sec": 100}
        anchors = {"dst_ip": tk.W, "total": tk.CENTER, "per_second": tk.CENTER, "max_per_sec": tk.CENTER}

        for col in columns:
            self.dest_tree.heading(col, text=headers[col], anchor=tk.CENTER,
                                   command=lambda c=col: self.sort_column(self.dest_tree, c, columns))
            self.dest_tree.column(col, width=widths[col], anchor=anchors[col])

        self.dest_tree.tag_configure(TAG_ALERT, background=COLOR_ALERT_BG)
        self.dest_tree.pack(fill=tk.BOTH, expand=True)

    def _setup_protocols_tab(self):
        """Sets up the Treeview for the Protocols tab."""
        columns = ("proto_port", "total", "per_second", "max_per_sec")
        self.proto_tree = ttk.Treeview(self.proto_frame, columns=columns, show='headings')

        headers = {"proto_port": "Protocol/Port", "total": "Total Packets",
                   "per_second": "Packets/Sec", "max_per_sec": "Max P/S"}
        widths = {"proto_port": 150, "total": 100, "per_second": 100, "max_per_sec": 100}
        anchors = {"proto_port": tk.W, "total": tk.CENTER, "per_second": tk.CENTER, "max_per_sec": tk.CENTER}

        for col in columns:
            self.proto_tree.heading(col, text=headers[col], anchor=tk.CENTER,
                                    command=lambda c=col: self.sort_column(self.proto_tree, c, columns))
            self.proto_tree.column(col, width=widths[col], anchor=anchors[col])

        self.proto_tree.tag_configure(TAG_ALERT, background=COLOR_ALERT_BG)
        self.proto_tree.pack(fill=tk.BOTH, expand=True)

    def _setup_threat_tab(self):
        """Sets up the Treeview for the Threat Info tab."""
        columns = ("mal_ip", "blocklists", "direction", "count")
        self.threat_tree = ttk.Treeview(self.threat_frame, columns=columns, show="headings")

        headers = {"mal_ip": "Malicious IP", "blocklists": "Blocklists", "direction": "Dir", "count": "Count"}
        widths = {"mal_ip": 130, "blocklists": 150, "direction": 60, "count": 60}
        anchors = {"mal_ip": tk.W, "blocklists": tk.W, "direction": tk.CENTER, "count": tk.CENTER}

        for col in columns:
            self.threat_tree.heading(col, text=headers[col], anchor=tk.CENTER) # No sorting for this table
            self.threat_tree.column(col, width=widths[col], anchor=anchors[col])

        self.threat_tree.pack(fill=tk.BOTH, expand=True)

    def update_gui(self):
        """Periodically updates all tabs in the detail window."""
        if not self.master.winfo_exists():
            logger.warning(f"Detail window for {self.source_ip} closed, stopping updates.")
            return

        try:
            # Get current flag states from main window via stored functions
            flag_unsafe_enabled = self.get_flag_unsafe_func() if callable(self.get_flag_unsafe_func) else False
            flag_malicious_enabled = self.get_flag_malicious_func() if callable(self.get_flag_malicious_func) else False
            flag_scan_enabled = self.get_flag_scan_func() if callable(self.get_flag_scan_func) else False
            threshold = config.max_packets_per_second

            now = time.time()
            prune_timestamp = now - PRUNE_SECONDS
            dest_data_for_table = []
            proto_data_for_table = []
            scan_ports_detected = False
            scan_hosts_detected = False
            source_ip_exists = False

            # --- Safely read and process shared data ---
            with lock:
                # Check for source IP existence *inside* the lock
                if self.source_ip in ip_data:
                    source_ip_exists = True
                    ip_entry = ip_data[self.source_ip]
                    scan_ports_detected = ip_entry.get("detected_scan_ports", False)
                    scan_hosts_detected = ip_entry.get("detected_scan_hosts", False)

                    # --- Process Destinations ---
                    destinations = ip_entry.get("destinations", {}).copy() # Copy for safe iteration outside lock if needed, but process under lock here
                    for dst_ip, dest_details in destinations.items():
                        timestamps_deque = dest_details.get("timestamps", deque())
                        # Prune old timestamps
                        while timestamps_deque and timestamps_deque[0] < prune_timestamp:
                            timestamps_deque.popleft()

                        # Calculate stats
                        one_second_ago = now - 1.0
                        packets_per_second = sum(1 for t in timestamps_deque if t >= one_second_ago)
                        dest_details["max_per_sec"] = max(dest_details.get("max_per_sec", 0), packets_per_second)
                        total_packets = dest_details.get("total", 0)
                        max_packets_sec = dest_details["max_per_sec"]

                        is_whitelisted = whitelist.is_ip_whitelisted(dst_ip)
                        dest_data_for_table.append((dst_ip, total_packets, packets_per_second, max_packets_sec, is_whitelisted))

                    # --- Process Protocols ---
                    protocols = ip_entry.get("protocols", {}).copy() # Copy for safe iteration outside lock if needed, but process under lock here
                    for (proto, port), proto_details in protocols.items():
                        timestamps_deque = proto_details.get("timestamps", deque())
                        # Prune old timestamps
                        while timestamps_deque and timestamps_deque[0] < prune_timestamp:
                            timestamps_deque.popleft()

                        # Calculate stats
                        one_second_ago = now - 1.0
                        packets_per_second = sum(1 for t in timestamps_deque if t >= one_second_ago)
                        proto_details["max_per_sec"] = max(proto_details.get("max_per_sec", 0), packets_per_second)
                        total_packets = proto_details.get("total", 0)
                        max_packets_sec = proto_details["max_per_sec"]

                        proto_str = f"{proto.upper()}:{port}" if port is not None else proto.upper()
                        proto_data_for_table.append((proto_str, total_packets, packets_per_second, max_packets_sec, proto, port))
                else:
                    logger.warning(f"Source IP {self.source_ip} no longer found in ip_data (lock held).")
            # --- End of locked section ---

            # --- Update Destination Table ---
            if source_ip_exists:
                if self.dest_sort_column:
                    dest_data_for_table = self.sort_data(dest_data_for_table, self.dest_sort_column, self.dest_sort_ascending, ("dst_ip", "total", "per_second", "max_per_sec"))

                selected_dest_id = self.dest_tree.focus()
                scroll_dest_pos = self.dest_tree.yview()
                self.dest_tree.delete(*self.dest_tree.get_children())

                for row in dest_data_for_table:
                    dst, total, p_sec, max_p, is_whitelisted = row
                    tags = ()
                    # Flag if not whitelisted and over threshold
                    if not is_whitelisted and max_p > threshold:
                        tags = (TAG_ALERT,)
                    self.dest_tree.insert("", tk.END, values=(dst, total, p_sec, max_p), tags=tags)

                if selected_dest_id and self.dest_tree.exists(selected_dest_id):
                    self.dest_tree.focus(selected_dest_id)
                    self.dest_tree.selection_set(selected_dest_id)
                self.dest_tree.yview_moveto(scroll_dest_pos[0])
            else:
                # Clear table if source IP disappeared
                self.dest_tree.delete(*self.dest_tree.get_children())
                self.dest_tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))

            # --- Update Protocol Table ---
            if source_ip_exists:
                if self.proto_sort_column:
                     # Pass extra indices (proto, port) for potential tie-breaking if needed by sort_data
                    proto_data_for_table = self.sort_data(proto_data_for_table, self.proto_sort_column, self.proto_sort_ascending,
                                                       ("proto_port", "total", "per_second", "max_per_sec"), extra_data_indices=[4, 5])

                selected_proto_id = self.proto_tree.focus()
                scroll_proto_pos = self.proto_tree.yview()
                self.proto_tree.delete(*self.proto_tree.get_children())

                for row in proto_data_for_table:
                    proto_str, total, p_sec, max_p = row[:4]
                    proto = row[4] if len(row) > 4 else None
                    port = row[5] if len(row) > 5 else None
                    tags = ()
                    is_flagged = False

                    # Flag if over threshold
                    if max_p > threshold:
                        is_flagged = True

                    # Flag if unsafe (and flag enabled)
                    if not is_flagged and flag_unsafe_enabled:
                        is_unsafe_port = (port in config.unsafe_ports) if port is not None else False
                        is_unsafe_proto = (proto in config.unsafe_protocols) if proto is not None else False
                        if is_unsafe_port or is_unsafe_proto:
                            is_flagged = True

                    if is_flagged:
                        tags = (TAG_ALERT,)

                    self.proto_tree.insert("", tk.END, values=(proto_str, total, p_sec, max_p), tags=tags)

                if selected_proto_id and self.proto_tree.exists(selected_proto_id):
                    self.proto_tree.focus(selected_proto_id)
                    self.proto_tree.selection_set(selected_proto_id)
                self.proto_tree.yview_moveto(scroll_proto_pos[0])
            else:
                 # Clear table if source IP disappeared
                self.proto_tree.delete(*self.proto_tree.get_children())
                self.proto_tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))

            # --- Update Threat Info Tab ---
            # This function handles its own locking and checks flag_malicious_enabled
            self.update_threat_info(flag_malicious_enabled, source_ip_exists)

            # --- Update Scan Status Label ---
            status_text = "Scan Status: "
            status_color = COLOR_SCAN_DEFAULT # Default unlikely to be used

            if not flag_scan_enabled:
                status_text += "Detection Disabled"
                status_color = COLOR_SCAN_DISABLED
            elif scan_ports_detected and scan_hosts_detected:
                status_text += "Port & Host Scan Detected!"
                status_color = COLOR_SCAN_DETECTED
            elif scan_ports_detected:
                status_text += "Port Scan Detected!"
                status_color = COLOR_SCAN_DETECTED
            elif scan_hosts_detected:
                status_text += "Host Scan Detected!"
                status_color = COLOR_SCAN_DETECTED
            elif not source_ip_exists:
                 status_text += "Source IP data unavailable"
                 status_color = COLOR_SCAN_DISABLED
            else:
                status_text += "No Scan Detected"
                status_color = COLOR_SCAN_NONE

            self.scan_status_label.config(text=status_text, fg=status_color)

        except Exception as e:
            logger.error(f"Error during detail GUI update for {self.source_ip}: {e}", exc_info=True)
        finally:
            # Reschedule the next update
            if self.master.winfo_exists():
                self._update_scheduled = self.master.after(UPDATE_INTERVAL_MS, self.update_gui)
            else:
                self._update_scheduled = None # Clear handle

    def update_threat_info(self, flag_malicious_enabled, source_ip_exists):
        """Updates the Threat Info tab."""
        logger.debug(f"Updating Threat Info tab for {self.source_ip}. Malicious Flag Enabled: {flag_malicious_enabled}")

        # Preserve selection and scroll state
        selected_threat_id = self.threat_tree.focus()
        scroll_threat_pos = self.threat_tree.yview()
        self.threat_tree.delete(*self.threat_tree.get_children()) # Clear current entries

        if not flag_malicious_enabled:
            logger.debug(f"Malicious flag disabled for {self.source_ip}.")
            self.threat_tree.insert("", tk.END, values=("Malicious IP Flag Disabled", "", "", ""))
            return # Don't proceed further

        if not source_ip_exists:
             self.threat_tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))
             return

        threat_data_for_table = []
        with lock:
            # We already confirmed source_ip exists before calling this function usually,
            # but double-check inside lock just in case.
            if self.source_ip not in ip_data:
                logger.warning(f"IP {self.source_ip} disappeared before threat info update (lock held).")
                self.threat_tree.insert("", tk.END, values=(f"Data for {self.source_ip} became unavailable", "", "", ""))
                return

            source_info = ip_data[self.source_ip]
            malicious_hits = source_info.get("malicious_hits", {})
            logger.debug(f"Raw malicious_hits dict for {self.source_ip}: {malicious_hits}")

            if not malicious_hits:
                logger.debug(f"No malicious hits recorded for {self.source_ip}.")
                self.threat_tree.insert("", tk.END, values=("No recorded malicious hits", "", "", ""))
                return

            # Process hits, filtering by currently active blocklists
            active_ip_lists = config.get_active_blocklist_urls("ip") # Get URLs currently enabled in config
            logger.debug(f"Active IP blocklist URLs from config: {active_ip_lists}")

            # ****************************************************************
            # ************ CORRECTED INDENTATION STARTS HERE *****************
            # ****************************************************************
            for mal_ip, hit_info in malicious_hits.items(): # Line 360 from previous analysis
                # The capture thread should only add hits from active lists at the time of detection.
                # However, we can double-check here against the *current* config state if needed,
                # or simply display the stored info. Let's display stored info for now.
                # If filtering by *current* active lists is desired:
                # blocklists_hit = hit_info.get("blocklists", set())
                # active_hits_on_lists = {bl for bl in blocklists_hit if bl in active_ip_lists}
                # if not active_hits_on_lists:
                #    logger.debug(f"Skipping hit {self.source_ip}->{mal_ip}, lists currently inactive: {blocklists_hit}")
                #    continue
                # bl_names = ', '.join(sorted(list(active_hits_on_lists))) # Use filtered list

                # Displaying stored info (lists active at time of hit):
                blocklists_hit = hit_info.get("blocklists", set())
                if not blocklists_hit: # Should not happen if added correctly
                     logger.warning(f"Hit recorded for {mal_ip} from {self.source_ip} with empty blocklist set.")
                     continue # Skip this hit if blocklist info is missing
                bl_names = ', '.join(sorted(list(blocklists_hit)))


                direction = hit_info.get("direction", "N/A")
                count = hit_info.get("count", 0)
                threat_data_for_table.append((mal_ip, bl_names, direction, count))
            # **************************************************************
            # ************ CORRECTED INDENTATION ENDS HERE *****************
            # **************************************************************
        # --- End of locked section ---

        # Sort by malicious IP
        try:
            threat_data_for_table.sort(key=lambda x: ipaddress.ip_address(str(x[0])) if x and x[0] else ipaddress.ip_address("0.0.0.0")) # Handle potential None/empty IP
        except (ipaddress.AddressValueError, ValueError, TypeError) as e:
             logger.error(f"Error sorting threat data IPs for {self.source_ip}: {e}", exc_info=True)
             # Continue with potentially unsorted data


        if not threat_data_for_table:
            # This case might be hit if hits existed but none were from currently active lists (if filtering applied)
            # Or if the malicious_hits dict was empty to begin with.
            logger.debug(f"No relevant threat data to display for {self.source_ip} after processing.")
            # Check if the dictionary was empty vs filtered
            if not malicious_hits: # Check original dict state again
                 self.threat_tree.insert("", tk.END, values=("No recorded malicious hits", "", "", ""))
            else:
                 self.threat_tree.insert("", tk.END, values=("No hits matching current filters", "", "", "")) # Or similar msg
        else:
            logger.debug(f"Populating threat table for {self.source_ip} with {len(threat_data_for_table)} entries.")
            for row in threat_data_for_table:
                self.threat_tree.insert("", tk.END, values=row)

        # Restore selection and scroll
        if selected_threat_id and self.threat_tree.exists(selected_threat_id):
            self.threat_tree.focus(selected_threat_id)
            self.threat_tree.selection_set(selected_threat_id)
        self.threat_tree.yview_moveto(scroll_threat_pos[0])


    def sort_data(self, data, column, ascending, columns, extra_data_indices=None):
        """Sorts data for destination or protocol tables."""
        try:
            col_index = columns.index(column)
            reverse_sort = not ascending

            def sort_key(item):
                # Ensure item has enough elements before accessing index
                if item is None or len(item) <= col_index:
                    # Define behavior for invalid items, e.g., treat as smallest/largest or error
                    if column in ["total", "per_second", "max_per_sec", "count"]: return 0.0
                    if column in ["dst_ip", "mal_ip"]: return ipaddress.ip_address("0.0.0.0")
                    return "" # Default empty string

                value = item[col_index]
                # Determine sort type based on column name convention
                if column in ["total", "per_second", "max_per_sec", "count"]:
                    try: return float(value)
                    except (ValueError, TypeError): return 0.0 # Treat errors as 0
                elif column in ["dst_ip", "mal_ip"]:
                    try: return ipaddress.ip_address(str(value))
                    except (ValueError, TypeError): return ipaddress.ip_address("0.0.0.0") # Treat errors as 0.0.0.0
                else: # Default to string sort (e.g., proto_port)
                    return str(value)

            # Apply sorting
            # Note: Using extra_data_indices for secondary sort isn't fully implemented here,
            #       it would require modifying the key function further.
            #       Basic single-column sort:
            return sorted(data, key=sort_key, reverse=reverse_sort)

        except (ValueError, IndexError, ipaddress.AddressValueError) as e:
            logger.error(f"Sorting error in detail view on column '{column}': {e}", exc_info=True)
            return data # Return unsorted data on error

    def sort_column(self, tree, column, columns):
        """Handles clicking column headers in detail view tables for sorting."""
        # Determine which table's sort state to update
        if tree == self.dest_tree:
            sort_col_attr = "dest_sort_column"
            sort_asc_attr = "dest_sort_ascending"
        elif tree == self.proto_tree:
            sort_col_attr = "proto_sort_column"
            sort_asc_attr = "proto_sort_ascending"
        else:
            return # Should not happen for threat_tree

        current_sort_column = getattr(self, sort_col_attr)
        current_sort_ascending = getattr(self, sort_asc_attr)

        if column == current_sort_column:
            # Toggle direction
            new_ascending = not current_sort_ascending
        else:
            # New column, default to ascending
            new_ascending = True

        # Update the sort state attributes for the specific tree
        setattr(self, sort_col_attr, column)
        setattr(self, sort_asc_attr, new_ascending)
        logger.debug(f"Set detail table sort: Column='{column}', Ascending={new_ascending}")
        # The actual sorting happens in the next update_gui call