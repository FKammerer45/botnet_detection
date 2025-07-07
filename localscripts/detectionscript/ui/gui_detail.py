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
from ui.gui_tooltip import Tooltip
from ui.tabs.destinations_tab import DestinationsTab
from ui.tabs.protocols_tab import ProtocolsTab
from ui.tabs.threat_info_tab import ThreatInfoTab
from ui.tabs.dns_queries_tab import DnsQueriesTab
from ui.tabs.scan_activity_tab import ScanActivityTab
from ui.tabs.rate_anomaly_tab import RateAnomalyTab
from ui.tabs.beaconing_tab import BeaconingTab
from ui.tabs.dns_analysis_tab import DnsAnalysisTab
from ui.tabs.local_network_tab import LocalNetworkTab
from ui.tabs.scoring_tab import ScoringTab

logger = logging.getLogger(__name__)
whitelist = get_whitelist() # Get the singleton instance

# --- Constants ---
UPDATE_INTERVAL_MS = 1000
PRUNE_SECONDS = 61 
# --- End Constants ---

class DetailWindow:
    def __init__(self, master, source_ip, data_manager, get_flag_unsafe_func, get_flag_malicious_func=None, get_flag_scan_func=None):
        self.master = master
        self.master.title(f"Details for {source_ip}")
        self.source_ip = source_ip
        self.data_manager = data_manager # Store data_manager instance
        logger.info(f"Opening detail window for IP: {self.source_ip}")

        self.get_flag_unsafe_func = get_flag_unsafe_func
        self.get_flag_malicious_func = get_flag_malicious_func
        self.get_flag_scan_func = get_flag_scan_func

        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.destinations_tab = DestinationsTab(self.notebook, self.data_manager, self.source_ip)
        self.protocols_tab = ProtocolsTab(self.notebook, self.data_manager, self.source_ip)
        self.threat_info_tab = ThreatInfoTab(self.notebook, self.data_manager, self.source_ip)
        self.dns_queries_tab = DnsQueriesTab(self.notebook, self.data_manager, self.source_ip)
        self.scan_activity_tab = ScanActivityTab(self.notebook, self.data_manager, self.source_ip)
        self.rate_anomaly_tab = RateAnomalyTab(self.notebook, self.data_manager, self.source_ip)
        self.beaconing_tab = BeaconingTab(self.notebook, self.data_manager, self.source_ip)
        self.dns_analysis_tab = DnsAnalysisTab(self.notebook, self.data_manager, self.source_ip)
        self.local_network_tab = LocalNetworkTab(self.notebook, self.data_manager, self.source_ip)
        self.scoring_tab = ScoringTab(self.notebook, self.data_manager, self.source_ip)

        self._update_scheduled = None
        self.update_gui() 
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        logger.info(f"Closing detail window for IP: {self.source_ip}")
        if self._update_scheduled:
            try: self.master.after_cancel(self._update_scheduled)
            except tk.TclError: pass
            self._update_scheduled = None
        try:
            if self.master.winfo_exists(): self.master.destroy()
        except tk.TclError: pass

    def update_gui(self):
        if not self.master.winfo_exists():
            logger.warning(f"Detail window for {self.source_ip} closed, stopping updates.")
            return
        try:
            flag_unsafe_enabled = self.get_flag_unsafe_func() if callable(self.get_flag_unsafe_func) else False
            flag_malicious_enabled = self.get_flag_malicious_func() if callable(self.get_flag_malicious_func) else False
            flag_scan_enabled = self.get_flag_scan_func() if callable(self.get_flag_scan_func) else False
            
            now = time.time()
            prune_timestamp = now - PRUNE_SECONDS

            ip_entry_snapshot = self.data_manager.get_full_ip_entry_snapshot(self.source_ip)
            source_ip_exists = ip_entry_snapshot is not None

            scan_ports_detected = ip_entry_snapshot.get("detected_scan_ports", False) if source_ip_exists else False
            scan_hosts_detected = ip_entry_snapshot.get("detected_scan_hosts", False) if source_ip_exists else False

            self.destinations_tab.update_tab(ip_entry_snapshot, now, prune_timestamp)
            self.protocols_tab.update_tab(ip_entry_snapshot, flag_unsafe_enabled, now, prune_timestamp)
            self.threat_info_tab.update_tab(ip_entry_snapshot, flag_malicious_enabled)
            self.dns_queries_tab.update_tab(ip_entry_snapshot)
            self.scan_activity_tab.update_tab(ip_entry_snapshot, flag_scan_enabled, scan_ports_detected, scan_hosts_detected)
            self.rate_anomaly_tab.update_tab(ip_entry_snapshot)
            self.beaconing_tab.update_tab(ip_entry_snapshot)
            self.dns_analysis_tab.update_tab(ip_entry_snapshot)
            self.local_network_tab.update_tab(ip_entry_snapshot)
            self.scoring_tab.update_tab(ip_entry_snapshot)

        except Exception as e:
            logger.error(f"Error during detail GUI update for {self.source_ip}: {e}", exc_info=True)
        finally:
            if self.master.winfo_exists():
                self._update_scheduled = self.master.after(UPDATE_INTERVAL_MS, self.update_gui)
            else:
                self._update_scheduled = None
