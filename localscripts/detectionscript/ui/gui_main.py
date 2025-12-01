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
from ui.gui_dns_config import DnsConfigWindow
from ui.gui_local_network_config import LocalNetworkConfigWindow
from ui.gui_scoring_config import ScoringConfigWindow
from ui.gui_documentation import DocumentationWindow
from ui.gui_testing_suite import TestingSuiteWindow
from ui.gui_tooltip import Tooltip
from ui.components.configuration_frame import ConfigurationFrame
from ui.gui_config_hub import ConfigHubWindow

logger = logging.getLogger(__name__)
whitelist = get_whitelist() # Get the singleton instance

# --- Constants ---
UPDATE_INTERVAL_MS = 1000
AGGREGATION_INTERVAL_MS = 60000 # This will trigger data_manager.aggregate_minute_data()
PRUNE_SECONDS = 61 
TAG_ALERT = "red" 
COLOR_ALERT_BG = "#FF9999"
WINDOW_GEOMETRY = "1150x600"
# --- End Constants ---

class PacketStatsGUI:
    def __init__(self, master, data_manager): # Added data_manager
        self.master = master
        self.data_manager = data_manager # Store data_manager instance
        self.master.title("Network Monitor")
        self.master.geometry(WINDOW_GEOMETRY)
        logger.info("Initializing PacketStatsGUI...")

        # Flag toggles (now controlled via Config Hub)
        self.flag_unsafe_var = tk.BooleanVar(value=True)
        self.flag_malicious_var = tk.BooleanVar(value=True)
        self.flag_dns_var = tk.BooleanVar(value=True)
        self.flag_scan_var = tk.BooleanVar(value=True)
        self.flag_rate_anomaly_var = tk.BooleanVar(value=True)
        self.flag_ja3_var = tk.BooleanVar(value=True)
        self.flag_dns_analysis_var = tk.BooleanVar(value=True)
        self.flag_local_threat_var = tk.BooleanVar(value=True)

        # References to open Toplevel windows
        self.temporal_window_ref = None
        # self.dns_monitor_window_ref = None # Removed
        self.detail_window_refs = [] 
        self.unsafe_config_window_ref = None
        self.scan_config_window_ref = None
        self.blocklist_manager_window_ref = None
        self.whitelist_manager_window_ref = None
        self.beaconing_config_window_ref = None
        self.dns_config_window_ref = None
        self.local_network_config_window_ref = None
        self.scoring_config_window_ref = None
        self.documentation_window_ref = None
        self.testing_suite_window_ref = None
        self.config_hub_window_ref = None

        try:
            logger.info("Downloading/loading blocklists (if needed)...")
            download_blocklists(force_download=False)
            load_blocklists()
            logger.info("Blocklists processed.")
        except Exception as e:
            logger.error(f"Blocklist initialization error: {e}", exc_info=True)
            messagebox.showerror("Blocklist Error", f"Failed to load blocklists: {e}\nBlocklist features may be disabled.")

        self.current_sort_column = "score" 
        self.current_sort_ascending = False

        top_frame = tk.Frame(self.master)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        self.add_description_frame(top_frame)
        self.configuration_frame = ConfigurationFrame(top_frame, self)
        self.configuration_frame.pack(fill=tk.X)


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
        if self.config_hub_window_ref:
            window_refs_to_close.append(self.config_hub_window_ref)
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

    def add_table_frame(self, parent_frame):
        paned_window = tk.PanedWindow(parent_frame, orient=tk.VERTICAL, sashrelief=tk.RAISED)
        paned_window.pack(fill=tk.BOTH, expand=True)

        internal_frame = ttk.LabelFrame(paned_window, text="Internal IPs")
        paned_window.add(internal_frame)
        self.internal_tree = self.create_treeview(internal_frame)

        external_frame = ttk.LabelFrame(paned_window, text="External IPs")
        paned_window.add(external_frame)
        self.external_tree = self.create_treeview(external_frame)

    def create_treeview(self, parent_frame):
        columns = ("ip", "score", "total", "per_minute", "per_second", "max_per_min")
        tree = ttk.Treeview(parent_frame, columns=columns, show="headings")
        headers = {"ip": "IP Address", "score": "Score", "total": "Total Pkts", "per_minute": "Pkts/Min",
                   "per_second": "Pkts/Sec", "max_per_min": "Max P/Min"}
        widths = {"ip": 150, "score": 50, "total": 100, "per_minute": 100, "per_second": 100, "max_per_min": 100}
        anchors = {"ip": tk.W, "score": tk.CENTER, "total": tk.CENTER, "per_minute": tk.CENTER,
                   "per_second": tk.CENTER, "max_per_min": tk.CENTER}
        for col in columns:
            tree.heading(col, text=headers[col], anchor=tk.CENTER,
                              command=lambda c=col: self.sort_column(c))
            tree.column(col, width=widths[col], anchor=anchors[col])
        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.tag_configure(TAG_ALERT, background=COLOR_ALERT_BG)
        tree.bind("<Double-1>", self.on_double_click)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        return tree

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

    def configure_dns(self):
        logger.debug("Opening DNS Analysis Configuration window.")
        if self.dns_config_window_ref and self.dns_config_window_ref.winfo_exists():
            self.dns_config_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.dns_config_window_ref = top
        dns_instance = DnsConfigWindow(top)
        top.protocol("WM_DELETE_WINDOW", lambda t=top, di=dns_instance: (di.master.destroy(), self._clear_window_reference(t, "dns_config_window_ref")))

    def configure_local_network(self):
        logger.debug("Opening Local Network Detection Configuration window.")
        if self.local_network_config_window_ref and self.local_network_config_window_ref.winfo_exists():
            self.local_network_config_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.local_network_config_window_ref = top
        local_net_instance = LocalNetworkConfigWindow(top)
        top.protocol("WM_DELETE_WINDOW", lambda t=top, lni=local_net_instance: (lni.master.destroy(), self._clear_window_reference(t, "local_network_config_window_ref")))

    def configure_scoring(self):
        logger.debug("Opening Scoring Configuration window.")
        if self.scoring_config_window_ref and self.scoring_config_window_ref.winfo_exists():
            self.scoring_config_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.scoring_config_window_ref = top
        scoring_instance = ScoringConfigWindow(top)
        top.protocol("WM_DELETE_WINDOW", lambda t=top, si=scoring_instance: (si.master.destroy(), self._clear_window_reference(t, "scoring_config_window_ref")))

    def open_documentation(self):
        logger.debug("Opening Documentation window.")
        if self.documentation_window_ref and self.documentation_window_ref.winfo_exists():
            self.documentation_window_ref.lift()
            return
        doc_instance = DocumentationWindow(self.master)
        self.documentation_window_ref = doc_instance
        doc_instance.protocol("WM_DELETE_WINDOW", lambda t=doc_instance: self._clear_window_reference(t, "documentation_window_ref"))

    def open_testing_suite(self):
        logger.debug("Opening Testing Suite window.")
        if self.testing_suite_window_ref and self.testing_suite_window_ref.winfo_exists():
            self.testing_suite_window_ref.lift()
            return
        
        testing_suite_instance = TestingSuiteWindow(self.master)
        self.testing_suite_window_ref = testing_suite_instance
        testing_suite_instance.protocol("WM_DELETE_WINDOW", lambda t=testing_suite_instance: (t.on_close(), self._clear_window_reference(t, "testing_suite_window_ref")))

    def open_config_hub(self):
        logger.debug("Opening Config Hub window.")
        if self.config_hub_window_ref and self.config_hub_window_ref.winfo_exists():
            self.config_hub_window_ref.lift()
            return
        top = tk.Toplevel(self.master)
        self.config_hub_window_ref = top
        hub_instance = ConfigHubWindow(top, self)
        top.protocol("WM_DELETE_WINDOW", lambda t=top, h=hub_instance: (hub_instance.on_close(), self._clear_window_reference(t, "config_hub_window_ref")))

    def get_flag_unsafe(self): return self.flag_unsafe_var.get()
    def get_flag_malicious(self): return self.flag_malicious_var.get()
    def get_flag_dns(self): return self.flag_dns_var.get()
    def get_flag_scan(self): return self.flag_scan_var.get()

    def on_double_click(self, event):
        tree = event.widget
        focused_item_id = tree.focus() 
        if not focused_item_id: return
        try:
            item_values = tree.item(focused_item_id)["values"]
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
            internal_data = []
            external_data = []

            for ip, data in current_ip_data_snapshot.items():
                if whitelist.is_ip_whitelisted(ip):
                    logger.debug(f"Skipping whitelisted source IP {ip}")
                    continue

                total_packets = data.get("total", 0)
                
                # packets/second and packets/minute from recent timestamps
                one_minute_ago = now - 60.0
                one_second_ago = now - 1.0
                timestamps_recent = data.get("timestamps", [])
                packets_per_minute = sum(1 for t in timestamps_recent if t >= one_minute_ago)
                packets_per_second = sum(1 for t in timestamps_recent if t >= one_second_ago)
                max_packets_min = data.get("max_per_min", packets_per_minute)
                score = data.get("score", 0)
                ip_type = "Internal" if self.data_manager._is_internal_ip(ip) else "External"

                is_over_score_threshold = score > config.score_threshold
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
                is_dns_analysis_detected = self.flag_dns_analysis_var.get() and (data.get("dga_detected") or data.get("dns_tunneling_detected"))
                is_local_threat_detected = self.flag_local_threat_var.get() and (data.get("arp_spoof_detected") or data.get("ping_sweep_detected") or data.get("icmp_tunneling_detected"))
                
                should_flag_row = (
                    is_over_score_threshold or
                    is_unsafe_triggered or
                    is_malicious_triggered or
                    is_dns_triggered or
                    is_scan_detected or
                    is_rate_anomaly_detected or
                    is_ja3_detected or
                    is_dns_analysis_detected or
                    is_local_threat_detected
                )

                row_data = (ip, score, total_packets, packets_per_minute,
                                       packets_per_second, max_packets_min, should_flag_row)

                if ip_type == "Internal":
                    internal_data.append(row_data)
                else:
                    external_data.append(row_data)

            self.update_treeview(self.internal_tree, internal_data)
            self.update_treeview(self.external_tree, external_data)
        except Exception as e:
            logger.error(f"Error during main GUI update: {e}", exc_info=True)
        finally:
            if self.master.winfo_exists():
                self._update_scheduled = self.master.after(UPDATE_INTERVAL_MS, self.update_gui)
            else:
                self._update_scheduled = None

    def update_treeview(self, tree, data):
        if self.current_sort_column:
            data = self.sort_data(data, self.current_sort_column, self.current_sort_ascending)

        selected_ip_address = None
        focused_item_id = tree.focus()
        if focused_item_id:
            item_values = tree.item(focused_item_id, "values")
            if item_values and len(item_values) > 0: selected_ip_address = item_values[0]
        
        scroll_position = tree.yview()
        tree.delete(*tree.get_children())
        new_item_id_to_select = None
        for row_data in data:
            ip_val, score_val, total_val, pmin_val, psec_val, maxp_val, flag_val = row_data
            tags_to_apply = (TAG_ALERT,) if flag_val else ()
            current_item_id = tree.insert("", tk.END, values=(ip_val, score_val, total_val, pmin_val, psec_val, maxp_val), tags=tags_to_apply)
            if selected_ip_address and ip_val == selected_ip_address:
                new_item_id_to_select = current_item_id
        
        if new_item_id_to_select:
            tree.focus(new_item_id_to_select)
            tree.selection_set(new_item_id_to_select)
        
        tree.yview_moveto(scroll_position[0])

    def sort_data(self, data, column, ascending):
        column_map = {"ip": 0, "score": 1, "total": 2, "per_minute": 3, "per_second": 4, "max_per_min": 5}
        try:
            col_index = column_map[column]
            reverse_sort = not ascending
            if column == "ip":
                def ip_key(item):
                    try:
                        ip = ipaddress.ip_address(str(item[col_index]))
                        return (ip.version, ip)
                    except ValueError:
                        return (-1, item[col_index]) # Fallback for invalid IPs
                key_func = ip_key
            else:
                key_func = lambda x: float(x[col_index]) if isinstance(x[col_index], (int, float)) else 0.0
            
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
