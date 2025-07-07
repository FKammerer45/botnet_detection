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
# NetworkDataManager will be passed in, so no direct import of its data structures here.
from core.blocklist_integration import download_blocklists, load_blocklists

# Import UI components
from ui.gui_unsafe import UnsafeConfigWindow
from ui.gui_temporal import TemporalAnalysisWindow
import ui.gui_blocklist_manager as gui_blocklist_manager
from ui.gui_detail import DetailWindow
# DnsMonitorWindow is removed
from ui.gui_scan_config import ScanConfigWindow
from ui.gui_whitelist_manager import WhitelistManagerWindow
from ui.gui_beaconing_config import BeaconingConfigWindow
from ui.gui_tooltip import Tooltip

logger = logging.getLogger(__name__)
whitelist = get_whitelist() # Get the singleton instance

# --- Constants ---
UPDATE_INTERVAL_MS = 1000
AGGREGATION_INTERVAL_MS = 60000 # This will trigger data_manager.aggregate_minute_data()
PRUNE_SECONDS = 61 
TAG_ALERT = "red" 
COLOR_ALERT_BG = "#FF9999"
WINDOW_GEOMETRY = "950x600"
# --- End Constants ---

class PacketStatsGUI:
    def __init__(self, master, data_manager): # Added data_manager
        self.master = master
        self.data_manager = data_manager # Store data_manager instance
        self.master.title("Network Monitor")
        self.master.geometry(WINDOW_GEOMETRY)
        logger.info("Initializing PacketStatsGUI...")

        # References to open Toplevel windows
        self.temporal_window_ref = None
        # self.dns_monitor_window_ref = None # Removed
        self.detail_window_refs = [] 
        self.unsafe_config_window_ref = None
        self.scan_config_window_ref = None
        self.blocklist_manager_window_ref = None
        self.whitelist_manager_window_ref = None
        self.beaconing_config_window_ref = None

        try:
            logger.info("Downloading/loading blocklists (if needed)...")
            download_blocklists(force_download=False)
            load_blocklists()
            logger.info("Blocklists processed.")
        except Exception as e:
            logger.error(f"Blocklist initialization error: {e}", exc_info=True)
            messagebox.showerror("Blocklist Error", f"Failed to load blocklists: {e}\nBlocklist features may be disabled.")

        self.current_sort_column = "max_per_sec" 
        self.current_sort_ascending = False

        top_frame = tk.Frame(self.master)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        self.add_description_frame(top_frame)
        self.add_configuration_frame(top_frame)

        table_frame = tk.Frame(self.master)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.add_table_frame(table_frame)

        self.schedule_aggregation()
        self._update_scheduled = None 
        self.update_gui() 

        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
        logger.info("PacketStatsGUI initialized.")

    def on_close(self):
        logger.info("Main application on_close triggered.")
        if self._update_scheduled:
            try:
                self.master.after_cancel(self._update_scheduled)
                logger.debug("Main GUI update loop cancelled.")
            except tk.TclError:
                logger.debug("TclError cancelling main GUI update (already cancelled/invalid).")
            self._update_scheduled = None
        
        window_refs_to_close = [
            self.temporal_window_ref, 
            self.unsafe_config_window_ref, self.scan_config_window_ref,
            self.blocklist_manager_window_ref, self.whitelist_manager_window_ref
        ]
        # For detail_window_refs, we stored tuples (window, ip), so extract window
        for ref_tuple in self.detail_window_refs:
            if isinstance(ref_tuple, tuple) and len(ref_tuple) > 0 and isinstance(ref_tuple[0], tk.Toplevel):
                 window_refs_to_close.append(ref_tuple[0])
            elif isinstance(ref_tuple, tk.Toplevel): # Should not happen if logic is consistent
                 window_refs_to_close.append(ref_tuple)


        for window_instance in window_refs_to_close:
            if window_instance and window_instance.winfo_exists():
                try:
                    logger.info(f"Attempting to close child window: {window_instance.title()}")
                    window_instance.destroy() 
                except tk.TclError as e:
                    logger.warning(f"TclError closing child window {window_instance.title()}: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error closing child window {window_instance.title()}: {e}", exc_info=True)
        
        self.detail_window_refs.clear()

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

    def _clear_window_reference(self, window_instance, ref_attr_name=None, ref_list_name=None, item_in_list=None):
        logger.debug(f"Clearing reference for window: {window_instance}, attr: {ref_attr_name}, list: {ref_list_name}, item: {item_in_list}")
        if ref_attr_name and hasattr(self, ref_attr_name) and getattr(self, ref_attr_name) == window_instance:
            setattr(self, ref_attr_name, None)
            logger.debug(f"Cleared attribute reference: {ref_attr_name}")
        elif ref_list_name and hasattr(self, ref_list_name):
            list_to_modify = getattr(self, ref_list_name)
            item_to_remove = item_in_list if item_in_list else window_instance
            if item_to_remove in list_to_modify:
                try:
                    list_to_modify.remove(item_to_remove)
                    logger.debug(f"Removed {item_to_remove} from list reference: {ref_list_name}")
                except ValueError: # Should not happen if 'in' check passed
                    logger.debug(f"Item {item_to_remove} not found in list {ref_list_name} during remove.")
            else:
                logger.debug(f"Item {item_to_remove} not in list {ref_list_name} for removal.")

        # Ensure the window is actually destroyed if its own protocol didn't fully handle it
        # This is a safeguard.
        if window_instance and window_instance.winfo_exists():
            try:
                window_instance.destroy()
            except tk.TclError:
                pass # Already destroyed


    def add_description_frame(self, parent_frame):
        desc_text = ("Monitor network activity. Double-click IP for details.\n"
                     f"Rows flagged {TAG_ALERT} based on Threshold and enabled Flags.")
        tk.Label(parent_frame, text=desc_text, justify=tk.LEFT).pack(side=tk.TOP, anchor="w", pady=(0, 5))

    def add_configuration_frame(self, parent_frame):
        config_frame = tk.Frame(parent_frame)
        config_frame.pack(side=tk.TOP, fill=tk.X, anchor='w')
        row1_frame = tk.Frame(config_frame)
        row1_frame.pack(fill=tk.X, pady=2)
        tk.Label(row1_frame, text="Pkts/Min Threshold:").pack(side=tk.LEFT, padx=(0, 2))
        self.threshold_var = tk.StringVar(value=str(config.max_packets_per_minute))
        self.threshold_entry = tk.Entry(row1_frame, width=8, textvariable=self.threshold_var)
        self.threshold_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.threshold_var.trace_add("write", self.update_threshold_config)
        self.flag_unsafe_var = tk.BooleanVar(value=True)
        cb_unsafe = tk.Checkbutton(row1_frame, text="Flag Insecure Protocols", variable=self.flag_unsafe_var)
        cb_unsafe.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_unsafe, "Flags traffic on unencrypted or legacy ports/protocols (e.g., Telnet, FTP).")
        self.flag_malicious_var = tk.BooleanVar(value=True)
        cb_malicious = tk.Checkbutton(row1_frame, text="Flag Malicious IP", variable=self.flag_malicious_var)
        cb_malicious.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_malicious, "Flags traffic to/from IPs found on configured blocklists.")
        self.flag_dns_var = tk.BooleanVar(value=True)
        cb_dns = tk.Checkbutton(row1_frame, text="Flag Malicious DNS", variable=self.flag_dns_var)
        cb_dns.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_dns, "Flags DNS queries for domains found on configured blocklists.")
        self.flag_scan_var = tk.BooleanVar(value=True)
        cb_scan = tk.Checkbutton(row1_frame, text="Flag Port Scan", variable=self.flag_scan_var)
        cb_scan.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_scan, "Flags hosts that appear to be performing port or host scans.")
        self.flag_rate_anomaly_var = tk.BooleanVar(value=True)
        cb_rate_anomaly = tk.Checkbutton(row1_frame, text="Flag Rate Anomaly", variable=self.flag_rate_anomaly_var)
        cb_rate_anomaly.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_rate_anomaly, "Flags hosts with unusual traffic rates for specific protocols.")
        self.flag_ja3_var = tk.BooleanVar(value=True)
        cb_ja3 = tk.Checkbutton(row1_frame, text="Flag JA3/S", variable=self.flag_ja3_var)
        cb_ja3.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_ja3, "Flags hosts with malicious JA3/JA3S fingerprints.")
        row2_frame = tk.Frame(config_frame)
        row2_frame.pack(fill=tk.X, pady=2)
        tk.Button(row2_frame, text="Conf Unsafe", command=self.configure_unsafe).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Conf Scan", command=self.configure_scan).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Conf Beaconing", command=self.configure_beaconing).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Blocklists", command=self.open_blocklist_manager).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Whitelist", command=self.open_whitelist_manager).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Temporal", command=self.open_temporal_analysis).pack(side=tk.LEFT, padx=3)

    def add_table_frame(self, parent_frame):
        columns = ("ip", "total", "per_minute", "per_second", "max_per_sec")
        self.tree = ttk.Treeview(parent_frame, columns=columns, show="headings")
        headers = {"ip": "IP Address", "total": "Total Pkts", "per_minute": "Pkts/Min",
                   "per_second": "Pkts/Sec", "max_per_sec": "Max P/S"}
        widths = {"ip": 150, "total": 100, "per_minute": 100, "per_second": 100, "max_per_sec": 100}
        anchors = {"ip": tk.W, "total": tk.CENTER, "per_minute": tk.CENTER,
                   "per_second": tk.CENTER, "max_per_sec": tk.CENTER}
        for col in columns:
            self.tree.heading(col, text=headers[col], anchor=tk.CENTER,
                              command=lambda c=col: self.sort_column(c))
            self.tree.column(col, width=widths[col], anchor=anchors[col])
        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.tag_configure(TAG_ALERT, background=COLOR_ALERT_BG)
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def create_tooltip(self, widget, text):
        tooltip = Tooltip(widget, text)
        widget.bind("<Enter>", lambda event: tooltip.showtip())
        widget.bind("<Leave>", lambda event: tooltip.hidetip())

    def update_threshold_config(self, *args):
        try:
            new_thresh = int(self.threshold_var.get())
            if new_thresh >= 0: config.max_packets_per_minute = new_thresh
            else: self.threshold_var.set(str(config.max_packets_per_minute))
        except ValueError: self.threshold_var.set(str(config.max_packets_per_minute))
        except Exception as e: logger.error(f"Error updating threshold: {e}", exc_info=True)

    def schedule_aggregation(self):
        logger.debug("Scheduling next data aggregation...")
        try:
            self.data_manager.aggregate_minute_data() # Use data_manager
        except Exception as e:
            logger.error(f"Error during scheduled aggregation: {e}", exc_info=True)
        finally:
            if self.master.winfo_exists():
                self.master.after(AGGREGATION_INTERVAL_MS, self.schedule_aggregation)

    def configure_unsafe(self):
        logger.debug("Opening Unsafe Configuration window.")
        if self.unsafe_config_window_ref and self.unsafe_config_window_ref.winfo_exists():
            self.unsafe_config_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.unsafe_config_window_ref = top 
        unsafe_instance = UnsafeConfigWindow(top) 
        top.protocol("WM_DELETE_WINDOW", lambda t=top, ui=unsafe_instance: (ui.master.destroy(), self._clear_window_reference(t, "unsafe_config_window_ref")))

    def open_temporal_analysis(self):
        logger.debug("Opening Temporal Analysis window.")
        if self.temporal_window_ref and self.temporal_window_ref.winfo_exists():
            self.temporal_window_ref.lift() 
            return
        top = tk.Toplevel(self.master)
        self.temporal_window_ref = top 
        temporal_instance = TemporalAnalysisWindow(top, self.data_manager) # Pass data_manager
        top.protocol("WM_DELETE_WINDOW", lambda t=top, ti=temporal_instance: (ti.on_close(), self._clear_window_reference(t, "temporal_window_ref")))

    def configure_scan(self):
        logger.debug("Opening Scan Detection Configuration window.")
        if self.scan_config_window_ref and self.scan_config_window_ref.winfo_exists():
            self.scan_config_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.scan_config_window_ref = top
        scan_instance = ScanConfigWindow(top) 
        top.protocol("WM_DELETE_WINDOW", lambda t=top, si=scan_instance: (si.master.destroy(), self._clear_window_reference(t, "scan_config_window_ref")))

    def open_blocklist_manager(self):
        logger.debug("Opening Blocklist Manager window.")
        if self.blocklist_manager_window_ref and self.blocklist_manager_window_ref.winfo_exists():
            self.blocklist_manager_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.blocklist_manager_window_ref = top
        blm_instance = gui_blocklist_manager.BlocklistManagerWindow(top)
        top.protocol("WM_DELETE_WINDOW", lambda t=top, bi=blm_instance: (bi.master.destroy(), self._clear_window_reference(t, "blocklist_manager_window_ref")))

    def open_whitelist_manager(self):
        logger.debug("Opening Whitelist Manager window.")
        if self.whitelist_manager_window_ref and self.whitelist_manager_window_ref.winfo_exists():
            self.whitelist_manager_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.whitelist_manager_window_ref = top
        wlm_instance = WhitelistManagerWindow(top)
        top.protocol("WM_DELETE_WINDOW", lambda t=top, wi=wlm_instance: (wi.master.destroy(), self._clear_window_reference(t, "whitelist_manager_window_ref")))

    def configure_beaconing(self):
        logger.debug("Opening Beaconing Detection Configuration window.")
        if self.beaconing_config_window_ref and self.beaconing_config_window_ref.winfo_exists():
            self.beaconing_config_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.beaconing_config_window_ref = top
        beaconing_instance = BeaconingConfigWindow(top)
        top.protocol("WM_DELETE_WINDOW", lambda t=top, bi=beaconing_instance: (bi.master.destroy(), self._clear_window_reference(t, "beaconing_config_window_ref")))

    def get_flag_unsafe(self): return self.flag_unsafe_var.get()
    def get_flag_malicious(self): return self.flag_malicious_var.get()
    def get_flag_dns(self): return self.flag_dns_var.get()
    def get_flag_scan(self): return self.flag_scan_var.get()

    def on_double_click(self, event):
        focused_item_id = self.tree.focus() 
        if not focused_item_id: return
        try:
            item_values = self.tree.item(focused_item_id)["values"]
            source_ip = item_values[0] if item_values else None
            if not source_ip: return
            logger.info(f"Double-clicked IP: {source_ip}. Opening detail window.")
            
            # Check if a detail window for this IP is already open
            # self.detail_window_refs stores tuples of (Toplevel, ip_string)
            for detail_top_ref, ip_str_ref in self.detail_window_refs:
                if ip_str_ref == source_ip and detail_top_ref.winfo_exists():
                    detail_top_ref.lift()
                    return

            detail_top = tk.Toplevel(self.master)
            detail_ref_tuple = (detail_top, source_ip) # Store the Toplevel and IP
            self.detail_window_refs.append(detail_ref_tuple)

            detail_instance = DetailWindow(
                detail_top,
                source_ip,
                self.data_manager, # Pass data_manager
                self.get_flag_unsafe, 
                self.get_flag_malicious,
                self.get_flag_scan
            )
            detail_top.protocol("WM_DELETE_WINDOW", 
                lambda t=detail_top, dt_instance=detail_instance, ref=detail_ref_tuple: (
                    dt_instance.on_close() if hasattr(dt_instance, 'on_close') else t.destroy(), 
                    self._clear_window_reference(t, ref_list_name="detail_window_refs", item_in_list=ref)
                )
            )
        except Exception as e:
            logger.error(f"Error opening detail window for IP {source_ip if 'source_ip' in locals() else 'Unknown'}: {e}", exc_info=True)
            messagebox.showerror("Error", f"Could not open detail window:\n{e}")

    def update_gui(self):
        if not self.master.winfo_exists():
            self._update_scheduled = None
            return
        try:
            threshold = config.max_packets_per_minute
            flag_unsafe_enabled = self.get_flag_unsafe()
            flag_malicious_enabled = self.get_flag_malicious()
            flag_dns_enabled = self.get_flag_dns()
            flag_scan_enabled = self.get_flag_scan()
            now = time.time()
            
            # Get data from NetworkDataManager
            current_ip_data_snapshot = self.data_manager.get_data_for_main_table_snapshot(now, PRUNE_SECONDS)
            data_for_table = []

            for ip, data in current_ip_data_snapshot.items():
                if whitelist.is_ip_whitelisted(ip):
                    logger.debug(f"Skipping whitelisted source IP {ip}")
                    continue

                total_packets = data.get("total", 0)
                # 'timestamps' in snapshot is already pruned and ready for len()
                packets_per_minute = len(data.get("timestamps", [])) 
                
                # Calculate packets in the last second from the snapshot's timestamps
                one_second_ago = now - 1.0
                packets_per_second = sum(1 for t in data.get("timestamps", []) if t >= one_second_ago)
                
                # Max per second is managed by DataManager, just retrieve
                max_packets_sec = data.get("max_per_sec", 0) 

                is_over_threshold = packets_per_minute > threshold
                is_unsafe_triggered = False
                if flag_unsafe_enabled:
                    ports_used = set(p[1] for p in data.get("protocols", {}).keys() if p[1] is not None)
                    protocols_used = set(p[0] for p in data.get("protocols", {}).keys() if p[0] is not None)
                    if not config.unsafe_ports.isdisjoint(ports_used) or \
                       not config.unsafe_protocols.isdisjoint(protocols_used):
                        is_unsafe_triggered = True
                
                is_malicious_triggered = flag_malicious_enabled and data.get("contacted_malicious_ip", False)
                is_dns_triggered = flag_dns_enabled and bool(data.get("suspicious_dns"))
                is_scan_detected = flag_scan_enabled and (data.get("detected_scan_ports", False) or data.get("detected_scan_hosts", False))
                is_rate_anomaly_detected = self.flag_rate_anomaly_var.get() and data.get("rate_anomaly_detected", False)
                is_ja3_detected = self.flag_ja3_var.get() and (data.get("malicious_ja3") or data.get("malicious_ja3s"))
                
                should_flag_row = (is_over_threshold or is_unsafe_triggered or
                                   is_malicious_triggered or is_dns_triggered or is_scan_detected or is_rate_anomaly_detected or is_ja3_detected)
                data_for_table.append((ip, total_packets, packets_per_minute,
                                       packets_per_second, max_packets_sec, should_flag_row))

            if self.current_sort_column:
                data_for_table = self.sort_data(data_for_table, self.current_sort_column, self.current_sort_ascending)

            selected_ip_address = None
            focused_item_id = self.tree.focus()
            if focused_item_id:
                item_values = self.tree.item(focused_item_id, "values")
                if item_values and len(item_values) > 0: selected_ip_address = item_values[0]
            
            scroll_position = self.tree.yview()
            self.tree.delete(*self.tree.get_children())
            new_item_id_to_select = None
            for row_data in data_for_table:
                ip_val, total_val, pmin_val, psec_val, maxp_val, flag_val = row_data
                tags_to_apply = (TAG_ALERT,) if flag_val else ()
                current_item_id = self.tree.insert("", tk.END, values=(ip_val, total_val, pmin_val, psec_val, maxp_val), tags=tags_to_apply)
                if selected_ip_address and ip_val == selected_ip_address:
                    new_item_id_to_select = current_item_id
            
            if new_item_id_to_select:
                self.tree.focus(new_item_id_to_select)
                self.tree.selection_set(new_item_id_to_select)
            
            self.tree.yview_moveto(scroll_position[0])
        except Exception as e:
            logger.error(f"Error during main GUI update: {e}", exc_info=True)
        finally:
            if self.master.winfo_exists():
                self._update_scheduled = self.master.after(UPDATE_INTERVAL_MS, self.update_gui)
            else:
                self._update_scheduled = None

    def sort_data(self, data, column, ascending):
        column_map = {"ip": 0, "total": 1, "per_minute": 2, "per_second": 3, "max_per_sec": 4}
        try:
            col_index = column_map[column]
            reverse_sort = not ascending
            if column == "ip": key_func = lambda x: ipaddress.ip_address(str(x[col_index]))
            else: key_func = lambda x: float(x[col_index]) if isinstance(x[col_index], (int, float)) else 0.0
            return sorted(data, key=key_func, reverse=reverse_sort)
        except Exception as e:
            logger.error(f"Sorting error on column '{column}': {e}", exc_info=True)
            return data

    def sort_column(self, column):
        if column == self.current_sort_column:
            self.current_sort_ascending = not self.current_sort_ascending
        else:
            self.current_sort_column = column
            self.current_sort_ascending = True
