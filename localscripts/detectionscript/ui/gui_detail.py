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
# NetworkDataManager will be passed in via __init__

logger = logging.getLogger(__name__)
whitelist = get_whitelist() # Get the singleton instance

# --- Constants ---
UPDATE_INTERVAL_MS = 1000
PRUNE_SECONDS = 61 
TAG_ALERT = "red" 
COLOR_ALERT_BG = "#FF9999"
COLOR_SCAN_DETECTED = "red"
COLOR_SCAN_DISABLED = "grey"
COLOR_SCAN_NONE = "green"
COLOR_SCAN_DEFAULT = "black"
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

        self.dest_frame = ttk.Frame(self.notebook) # Use ttk.Frame for consistency
        self.notebook.add(self.dest_frame, text="Destinations")
        self._setup_destinations_tab()
        self.dest_sort_column = None 
        self.dest_sort_ascending = True

        self.proto_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.proto_frame, text="Protocols")
        self._setup_protocols_tab()
        self.proto_sort_column = None
        self.proto_sort_ascending = True

        self.threat_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.threat_frame, text="Threat Info")
        self._setup_threat_tab()

        self.dns_query_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dns_query_frame, text="DNS Queries")
        self._setup_dns_query_tab()

        self.scan_activity_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_activity_frame, text="Scan Activity")
        self._setup_scan_activity_tab()

        self.anomaly_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.anomaly_frame, text="Rate Anomaly")
        self._setup_anomaly_tab()

        self.beaconing_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.beaconing_frame, text="Beaconing")
        self._setup_beaconing_tab()

        self.dns_analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dns_analysis_frame, text="DNS Analysis")
        self._setup_dns_analysis_tab()

        self.local_network_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.local_network_frame, text="Local Network")
        self._setup_local_network_tab()

        self.scoring_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scoring_frame, text="Scoring")
        self._setup_scoring_tab()

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

    def _setup_destinations_tab(self):
        explanation = "Shows all destination IPs this host has communicated with, along with packet counts."
        ttk.Label(self.dest_frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        columns = ("dst_ip", "total", "per_second", "max_per_sec")
        self.dest_tree = ttk.Treeview(self.dest_frame, columns=columns, show='headings')
        headers = {"dst_ip": "Destination IP", "total": "Total Packets", "per_second": "Packets/Sec", "max_per_sec": "Max P/S"}
        widths = {"dst_ip": 150, "total": 100, "per_second": 100, "max_per_sec": 100}
        anchors = {"dst_ip": tk.W, "total": tk.CENTER, "per_second": tk.CENTER, "max_per_sec": tk.CENTER}
        for col in columns:
            self.dest_tree.heading(col, text=headers[col], anchor=tk.CENTER, command=lambda c=col: self.sort_column(self.dest_tree, c, columns))
            self.dest_tree.column(col, width=widths[col], anchor=anchors[col])
        self.dest_tree.tag_configure(TAG_ALERT, background=COLOR_ALERT_BG)
        self.dest_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _setup_protocols_tab(self):
        explanation = "Shows all protocols and ports used by this host, along with packet counts."
        ttk.Label(self.proto_frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        columns = ("proto_port", "total", "per_second", "max_per_sec")
        self.proto_tree = ttk.Treeview(self.proto_frame, columns=columns, show='headings')
        headers = {"proto_port": "Protocol/Port", "total": "Total Packets", "per_second": "Packets/Sec", "max_per_sec": "Max P/S"}
        widths = {"proto_port": 150, "total": 100, "per_second": 100, "max_per_sec": 100}
        anchors = {"proto_port": tk.W, "total": tk.CENTER, "per_second": tk.CENTER, "max_per_sec": tk.CENTER}
        for col in columns:
            self.proto_tree.heading(col, text=headers[col], anchor=tk.CENTER, command=lambda c=col: self.sort_column(self.proto_tree, c, columns))
            self.proto_tree.column(col, width=widths[col], anchor=anchors[col])
        self.proto_tree.tag_configure(TAG_ALERT, background=COLOR_ALERT_BG)
        self.proto_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _setup_threat_tab(self):
        explanation = "Shows all malicious IPs, domains, and JA3/S fingerprints this host has communicated with, based on loaded blocklists."
        ttk.Label(self.threat_frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        columns = ("mal_ip", "blocklists", "direction", "count")
        self.threat_tree = ttk.Treeview(self.threat_frame, columns=columns, show="headings")
        headers = {"mal_ip": "Malicious IP", "blocklists": "Blocklists", "direction": "Dir", "count": "Count"}
        widths = {"mal_ip": 130, "blocklists": 150, "direction": 60, "count": 60}
        anchors = {"mal_ip": tk.W, "blocklists": tk.W, "direction": tk.CENTER, "count": tk.CENTER}
        for col in columns:
            self.threat_tree.heading(col, text=headers[col], anchor=tk.CENTER)
            self.threat_tree.column(col, width=widths[col], anchor=anchors[col])
        self.threat_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _setup_dns_query_tab(self):
        explanation = "Shows all suspicious DNS queries made by this host that were found in the blocklists."
        ttk.Label(self.dns_query_frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        columns = ("timestamp", "qname", "reason")
        self.dns_tree = ttk.Treeview(self.dns_query_frame, columns=columns, show="headings")
        headers = {"timestamp": "Timestamp", "qname": "Queried Domain", "reason": "Reason"}
        widths = {"timestamp": 150, "qname": 250, "reason": 150}
        for col in columns:
            self.dns_tree.heading(col, text=headers[col], anchor=tk.W)
            self.dns_tree.column(col, width=widths[col], anchor=tk.W)
        self.dns_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _setup_scan_activity_tab(self):
        explanation = "Shows detected port and host scan activity originating from this host."
        ttk.Label(self.scan_activity_frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        status_frame = ttk.Frame(self.scan_activity_frame, padding=(5,5))
        status_frame.pack(fill=tk.X)
        self.port_scan_status_var = tk.StringVar(value="Port Scan: Unknown")
        ttk.Label(status_frame, textvariable=self.port_scan_status_var).pack(anchor=tk.W)
        self.host_scan_status_var = tk.StringVar(value="Host Scan: Unknown")
        ttk.Label(status_frame, textvariable=self.host_scan_status_var).pack(anchor=tk.W)
        ttk.Separator(self.scan_activity_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        targets_frame = ttk.LabelFrame(self.scan_activity_frame, text="Detected Scan Targets/Ports")
        targets_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        columns = ("target_ip", "scanned_ports", "scan_types")
        self.scan_targets_tree = ttk.Treeview(targets_frame, columns=columns, show="headings")
        headers = {"target_ip": "Target IP", "scanned_ports": "Scanned Ports", "scan_types": "Scan Types"}
        widths = {"target_ip": 150, "scanned_ports": 250, "scan_types": 100}
        for col in columns:
            self.scan_targets_tree.heading(col, text=headers[col], anchor=tk.W)
            self.scan_targets_tree.column(col, width=widths[col], anchor=tk.W)
        self.scan_targets_tree.pack(fill=tk.BOTH, expand=True)

    def _setup_anomaly_tab(self):
        explanation = "Shows detected traffic rate anomalies for specific protocols used by this host."
        ttk.Label(self.anomaly_frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        columns = ("protocol", "count", "mean", "std_dev", "threshold")
        self.anomaly_tree = ttk.Treeview(self.anomaly_frame, columns=columns, show="headings")
        headers = {"protocol": "Protocol", "count": "Packets", "mean": "Mean", "std_dev": "Std Dev", "threshold": "Threshold"}
        widths = {"protocol": 100, "count": 80, "mean": 80, "std_dev": 80, "threshold": 80}
        for col in columns:
            self.anomaly_tree.heading(col, text=headers[col], anchor=tk.W)
            self.anomaly_tree.column(col, width=widths[col], anchor=tk.W)
        self.anomaly_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _setup_beaconing_tab(self):
        explanation = "Shows detected Command & Control (C2) beaconing activity from this host to external destinations."
        ttk.Label(self.beaconing_frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        columns = ("destination", "interval", "tolerance", "occurrences")
        self.beaconing_tree = ttk.Treeview(self.beaconing_frame, columns=columns, show="headings")
        headers = {"destination": "Destination", "interval": "Interval (s)", "tolerance": "Tolerance (s)", "occurrences": "Occurrences"}
        widths = {"destination": 150, "interval": 100, "tolerance": 100, "occurrences": 100}
        for col in columns:
            self.beaconing_tree.heading(col, text=headers[col], anchor=tk.W)
            self.beaconing_tree.column(col, width=widths[col], anchor=tk.W)
        self.beaconing_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _setup_dns_analysis_tab(self):
        explanation = "Shows advanced DNS analysis, including DGA and DNS tunneling detection."
        ttk.Label(self.dns_analysis_frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        status_frame = ttk.Frame(self.dns_analysis_frame, padding=(5,5))
        status_frame.pack(fill=tk.X)
        self.dga_status_var = tk.StringVar(value="DGA Detected: Unknown")
        ttk.Label(status_frame, textvariable=self.dga_status_var).pack(anchor=tk.W)
        self.dns_tunneling_status_var = tk.StringVar(value="DNS Tunneling Detected: Unknown")
        ttk.Label(status_frame, textvariable=self.dns_tunneling_status_var).pack(anchor=tk.W)

    def _setup_local_network_tab(self):
        explanation = "Shows detected local network threats like ARP spoofing and ICMP anomalies."
        ttk.Label(self.local_network_frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        status_frame = ttk.Frame(self.local_network_frame, padding=(5,5))
        status_frame.pack(fill=tk.X)
        self.arp_spoof_status_var = tk.StringVar(value="ARP Spoofing Detected: Unknown")
        ttk.Label(status_frame, textvariable=self.arp_spoof_status_var).pack(anchor=tk.W)
        self.ping_sweep_status_var = tk.StringVar(value="Ping Sweep Detected: Unknown")
        ttk.Label(status_frame, textvariable=self.ping_sweep_status_var).pack(anchor=tk.W)
        self.icmp_tunneling_status_var = tk.StringVar(value="ICMP Tunneling Detected: Unknown")
        ttk.Label(status_frame, textvariable=self.icmp_tunneling_status_var).pack(anchor=tk.W)

    def _setup_scoring_tab(self):
        explanation = "Shows the threat score for this IP and a breakdown of how it was calculated."
        ttk.Label(self.scoring_frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        self.score_var = tk.StringVar(value="Score: 0/100")
        ttk.Label(self.scoring_frame, textvariable=self.score_var, font=("TkDefaultFont", 14, "bold")).pack(pady=5)

        columns = ("component", "points")
        self.score_tree = ttk.Treeview(self.scoring_frame, columns=columns, show="headings")
        self.score_tree.heading("component", text="Detection Component")
        self.score_tree.heading("points", text="Points")
        self.score_tree.column("component", anchor=tk.W)
        self.score_tree.column("points", anchor=tk.CENTER, width=100)
        self.score_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def update_gui(self):
        if not self.master.winfo_exists():
            logger.warning(f"Detail window for {self.source_ip} closed, stopping updates.")
            return
        try:
            flag_unsafe_enabled = self.get_flag_unsafe_func() if callable(self.get_flag_unsafe_func) else False
            flag_malicious_enabled = self.get_flag_malicious_func() if callable(self.get_flag_malicious_func) else False
            flag_scan_enabled = self.get_flag_scan_func() if callable(self.get_flag_scan_func) else False
            
            now = time.time()
            prune_timestamp = now - PRUNE_SECONDS # For live P/S calculation on copies

            ip_entry_snapshot = self.data_manager.get_full_ip_entry_snapshot(self.source_ip)
            source_ip_exists = ip_entry_snapshot is not None

            scan_ports_detected = ip_entry_snapshot.get("detected_scan_ports", False) if source_ip_exists else False
            scan_hosts_detected = ip_entry_snapshot.get("detected_scan_hosts", False) if source_ip_exists else False

            self._update_destinations_tab(source_ip_exists, ip_entry_snapshot, now, prune_timestamp)
            self._update_protocols_tab(source_ip_exists, ip_entry_snapshot, flag_unsafe_enabled, now, prune_timestamp)
            self._update_threat_tab(source_ip_exists, ip_entry_snapshot, flag_malicious_enabled)
            self._update_dns_queries_tab(source_ip_exists, ip_entry_snapshot)
            self._update_scan_activity_tab(source_ip_exists, ip_entry_snapshot, flag_scan_enabled, scan_ports_detected, scan_hosts_detected)
            self._update_anomaly_tab(source_ip_exists, ip_entry_snapshot)
            self._update_beaconing_tab(source_ip_exists, ip_entry_snapshot)
            self._update_dns_analysis_tab(source_ip_exists, ip_entry_snapshot)
            self._update_local_network_tab(source_ip_exists, ip_entry_snapshot)
            self._update_scoring_tab(source_ip_exists, ip_entry_snapshot)

        except Exception as e:
            logger.error(f"Error during detail GUI update for {self.source_ip}: {e}", exc_info=True)
        finally:
            if self.master.winfo_exists():
                self._update_scheduled = self.master.after(UPDATE_INTERVAL_MS, self.update_gui)
            else:
                self._update_scheduled = None

    def _update_destinations_tab(self, source_ip_exists, ip_snapshot, current_time, prune_timestamp):
        self.dest_tree.delete(*self.dest_tree.get_children())
        if not source_ip_exists:
            self.dest_tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))
            return

        dest_data_for_table = []
        destinations = ip_snapshot.get("destinations", {})
        for dst_ip, dest_details in destinations.items():
            timestamps_deque = dest_details.get("timestamps", deque())
            temp_timestamps = deque(timestamps_deque)
            while temp_timestamps and temp_timestamps[0] < prune_timestamp:
                temp_timestamps.popleft()
            
            packets_per_second = sum(1 for t in temp_timestamps if t >= current_time - 1.0)
            total_packets = dest_details.get("total", 0)
            max_packets_sec = dest_details.get("max_per_sec", 0)
            is_whitelisted = whitelist.is_ip_whitelisted(dst_ip)
            dest_data_for_table.append((dst_ip, total_packets, packets_per_second, max_packets_sec, is_whitelisted))

        if self.dest_sort_column:
            dest_data_for_table = self.sort_data(dest_data_for_table, self.dest_sort_column, self.dest_sort_ascending, ("dst_ip", "total", "per_second", "max_per_sec"))
        
        for row in dest_data_for_table:
            dst, total, p_sec, max_p, is_whitelisted = row
            tags = ()
            if not is_whitelisted and max_p > config.max_packets_per_second: # Using config directly
                tags = (TAG_ALERT,)
            self.dest_tree.insert("", tk.END, values=(dst, total, p_sec, max_p), tags=tags)

    def _update_protocols_tab(self, source_ip_exists, ip_snapshot, flag_unsafe_enabled, current_time, prune_timestamp):
        self.proto_tree.delete(*self.proto_tree.get_children())
        if not source_ip_exists:
            self.proto_tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))
            return

        proto_data_for_table = []
        protocols = ip_snapshot.get("protocols", {})
        for (proto, port), proto_details in protocols.items():
            timestamps_deque = proto_details.get("timestamps", deque())
            temp_timestamps = deque(timestamps_deque)
            while temp_timestamps and temp_timestamps[0] < prune_timestamp:
                temp_timestamps.popleft()

            packets_per_second = sum(1 for t in temp_timestamps if t >= current_time - 1.0)
            total_packets = proto_details.get("total", 0)
            max_packets_sec = proto_details.get("max_per_sec", 0)
            proto_str = f"{str(proto).upper()}:{port}" if port is not None else str(proto).upper()
            proto_data_for_table.append((proto_str, total_packets, packets_per_second, max_packets_sec, proto, port))

        if self.proto_sort_column:
            proto_data_for_table = self.sort_data(proto_data_for_table, self.proto_sort_column, self.proto_sort_ascending, 
                                               ("proto_port", "total", "per_second", "max_per_sec"), extra_data_indices=[4,5])
        
        for row in proto_data_for_table:
            proto_str_val, total_val, p_sec_val, max_p_val = row[:4]
            proto_val = row[4] if len(row) > 4 else None
            port_val = row[5] if len(row) > 5 else None
            tags = ()
            is_flagged = False
            if max_p_val > config.max_packets_per_second: is_flagged = True
            if not is_flagged and flag_unsafe_enabled:
                if (port_val is not None and port_val in config.unsafe_ports) or \
                   (proto_val is not None and proto_val in config.unsafe_protocols):
                    is_flagged = True
            if is_flagged: tags = (TAG_ALERT,)
            self.proto_tree.insert("", tk.END, values=(proto_str_val, total_val, p_sec_val, max_p_val), tags=tags)

    def _update_threat_tab(self, source_ip_exists, ip_snapshot, flag_malicious_enabled):
        self.threat_tree.delete(*self.threat_tree.get_children())
        if not flag_malicious_enabled:
            self.threat_tree.insert("", tk.END, values=("Malicious IP Flag Disabled", "", "", ""))
            return
        if not source_ip_exists:
            self.threat_tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))
            return

        threat_data_for_table = []
        if ip_snapshot:
            malicious_hits = ip_snapshot.get("malicious_hits", {})
            if ip_snapshot.get("malicious_ja3"):
                threat_data_for_table.append(("JA3", ip_snapshot["malicious_ja3"], "N/A", 1))
            if ip_snapshot.get("malicious_ja3s"):
                threat_data_for_table.append(("JA3S", ip_snapshot["malicious_ja3s"], "N/A", 1))

            if not malicious_hits and not ip_snapshot.get("malicious_ja3") and not ip_snapshot.get("malicious_ja3s"):
                self.threat_tree.insert("", tk.END, values=("No recorded malicious hits", "", "", ""))
                return
            for mal_ip, hit_info in malicious_hits.items():
                bl_descriptions = ', '.join(sorted(list(hit_info.get("blocklists", {}).values())))
                direction = hit_info.get("direction", "N/A")
                count = hit_info.get("count", 0)
                threat_data_for_table.append((mal_ip, bl_descriptions, direction, count))
        
        if not threat_data_for_table: # Should be caught by 'if not malicious_hits' earlier
            self.threat_tree.insert("", tk.END, values=("No malicious hits to display", "", "", ""))
        else:
            try: threat_data_for_table.sort(key=lambda x: ipaddress.ip_address(str(x[0])))
            except: pass # Ignore sort error if IP is invalid for some reason
            for row in threat_data_for_table:
                self.threat_tree.insert("", tk.END, values=row)

    def _update_dns_queries_tab(self, source_ip_exists, ip_snapshot):
        self.dns_tree.delete(*self.dns_tree.get_children())
        if not source_ip_exists:
            self.dns_tree.insert("", tk.END, values=("(Source IP data unavailable)", "", ""))
            return

        dns_queries_data = []
        if ip_snapshot:
            suspicious_dns_list = ip_snapshot.get("suspicious_dns", [])
            for query_info in suspicious_dns_list:
                ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(query_info.get("timestamp", 0)))
                qname = query_info.get("qname", "N/A")
                reason = query_info.get("reason", "N/A")
                dns_queries_data.append((ts, qname, reason))
        
        if not dns_queries_data:
            self.dns_tree.insert("", tk.END, values=("No suspicious DNS queries recorded", "", ""))
        else:
            dns_queries_data.sort(key=lambda x: x[0], reverse=True)
            for row in dns_queries_data:
                self.dns_tree.insert("", tk.END, values=row)

    def _update_scan_activity_tab(self, source_ip_exists, ip_snapshot, flag_scan_enabled, scan_ports_detected, scan_hosts_detected):
        self.scan_targets_tree.delete(*self.scan_targets_tree.get_children())
        if not flag_scan_enabled:
            self.port_scan_status_var.set("Port Scan: Detection Disabled")
            self.host_scan_status_var.set("Host Scan: Detection Disabled")
            self.scan_targets_tree.insert("", tk.END, values=("Scan detection disabled in main UI.", ""))
            return

        if not source_ip_exists:
            self.port_scan_status_var.set("Port Scan: Source IP data unavailable")
            self.host_scan_status_var.set("Host Scan: Source IP data unavailable")
            self.scan_targets_tree.insert("", tk.END, values=("Source IP data unavailable.", ""))
            return

        self.port_scan_status_var.set(f"Port Scan Detected: {'Yes' if scan_ports_detected else 'No'}")
        self.host_scan_status_var.set(f"Host Scan Detected: {'Yes' if scan_hosts_detected else 'No'}")

        scan_target_details = []
        if (scan_ports_detected or scan_hosts_detected) and ip_snapshot:
            scan_targets = ip_snapshot.get("scan_targets", {})
            for target_ip, details in scan_targets.items():
                ports_str = ", ".join(map(str, sorted(list(details.get("ports", set())))))
                scan_types_str = ", ".join(sorted(list(details.get("scan_types", set()))))
                if not ports_str: ports_str = "(Host scan)" if scan_hosts_detected else "N/A"
                scan_target_details.append((target_ip, ports_str, scan_types_str))
        
        if not scan_target_details and (scan_ports_detected or scan_hosts_detected):
             self.scan_targets_tree.insert("", tk.END, values=("Scan detected, but no specific targets/ports logged.", "", ""))
        elif not scan_target_details:
            self.scan_targets_tree.insert("", tk.END, values=("No scan targets to display.", "", ""))
        else:
            try: scan_target_details.sort(key=lambda x: ipaddress.ip_address(x[0]))
            except: pass # Ignore sort error
            for row in scan_target_details:
                self.scan_targets_tree.insert("", tk.END, values=row)

    def _update_anomaly_tab(self, source_ip_exists, ip_snapshot):
        self.anomaly_tree.delete(*self.anomaly_tree.get_children())
        if not source_ip_exists:
            self.anomaly_tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", "", ""))
            return

        anomaly_data_for_table = []
        if ip_snapshot:
            protocol_stats = ip_snapshot.get("protocol_stats", {})
            for proto, stats in protocol_stats.items():
                count = stats.get("count", 0)
                mean = stats.get("mean", 0)
                std_dev = stats.get("std", 0)
                threshold = mean + (std_dev * config.rate_anomaly_sensitivity)
                anomaly_data_for_table.append((proto, count, f"{mean:.2f}", f"{std_dev:.2f}", f"{threshold:.2f}"))
        
        if not anomaly_data_for_table:
            self.anomaly_tree.insert("", tk.END, values=("No anomaly data to display.", "", "", "", ""))
        else:
            for row in anomaly_data_for_table:
                self.anomaly_tree.insert("", tk.END, values=row)

    def _update_beaconing_tab(self, source_ip_exists, ip_snapshot):
        self.beaconing_tree.delete(*self.beaconing_tree.get_children())
        if not source_ip_exists:
            self.beaconing_tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))
            return

        beaconing_data_for_table = []
        if ip_snapshot and ip_snapshot.get("beaconing_detected"):
            for dest_ip, dest_data in ip_snapshot.get("destinations", {}).items():
                timestamps = sorted(list(dest_data["timestamps"]))
                if len(timestamps) < config.beaconing_min_occurrences:
                    continue
                
                intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
                if not intervals:
                    continue

                mean_interval = sum(intervals) / len(intervals)
                
                if abs(mean_interval - config.beaconing_interval_seconds) <= config.beaconing_tolerance_seconds:
                    consistent_beacons = 0
                    for interval in intervals:
                        if abs(interval - config.beaconing_interval_seconds) <= self.beaconing_tolerance_seconds:
                            consistent_beacons += 1
                    
                    if consistent_beacons + 1 >= self.beaconing_min_occurrences:
                        beaconing_data_for_table.append((dest_ip, f"{mean_interval:.2f}", config.beaconing_tolerance_seconds, len(timestamps)))

        if not beaconing_data_for_table:
            self.beaconing_tree.insert("", tk.END, values=("No beaconing detected.", "", "", ""))
        else:
            for row in beaconing_data_for_table:
                self.beaconing_tree.insert("", tk.END, values=row)

    def _update_dns_analysis_tab(self, source_ip_exists, ip_snapshot):
        if not source_ip_exists:
            self.dga_status_var.set("DGA Detected: Source IP data unavailable")
            self.dns_tunneling_status_var.set("DNS Tunneling Detected: Source IP data unavailable")
            return

        dga_detected = ip_snapshot.get("dga_detected", False)
        dns_tunneling_detected = ip_snapshot.get("dns_tunneling_detected", False)

        self.dga_status_var.set(f"DGA Detected: {'Yes' if dga_detected else 'No'}")
        self.dns_tunneling_status_var.set(f"DNS Tunneling Detected: {'Yes' if dns_tunneling_detected else 'No'}")

    def _update_local_network_tab(self, source_ip_exists, ip_snapshot):
        if not source_ip_exists:
            self.arp_spoof_status_var.set("ARP Spoofing Detected: Source IP data unavailable")
            self.ping_sweep_status_var.set("Ping Sweep Detected: Source IP data unavailable")
            self.icmp_tunneling_status_var.set("ICMP Tunneling Detected: Source IP data unavailable")
            return

        arp_spoof_detected = ip_snapshot.get("arp_spoof_detected", False)
        ping_sweep_detected = ip_snapshot.get("ping_sweep_detected", False)
        icmp_tunneling_detected = ip_snapshot.get("icmp_tunneling_detected", False)

        self.arp_spoof_status_var.set(f"ARP Spoofing Detected: {'Yes' if arp_spoof_detected else 'No'}")
        self.ping_sweep_status_var.set(f"Ping Sweep Detected: {'Yes' if ping_sweep_detected else 'No'}")
        self.icmp_tunneling_status_var.set(f"ICMP Tunneling Detected: {'Yes' if icmp_tunneling_detected else 'No'}")

    def _update_scoring_tab(self, source_ip_exists, ip_snapshot):
        if not source_ip_exists:
            self.score_var.set("Score: N/A")
            self.score_tree.delete(*self.score_tree.get_children())
            self.score_tree.insert("", tk.END, values=("Source IP data unavailable", ""))
            return

        score = ip_snapshot.get("score", 0)
        self.score_var.set(f"Score: {score}/100")

        self.score_tree.delete(*self.score_tree.get_children())
        score_components = ip_snapshot.get("score_components", {})
        if not score_components:
            self.score_tree.insert("", tk.END, values=("No scoring components", ""))
            return
        
        for component, points in sorted(score_components.items()):
            self.score_tree.insert("", tk.END, values=(component, points))

    def sort_data(self, data, column, ascending, columns, extra_data_indices=None):
        try:
            col_index = columns.index(column)
            reverse_sort = not ascending
            def sort_key(item):
                if item is None or len(item) <= col_index:
                    if column in ["total", "per_second", "max_per_sec", "count"]: return 0.0
                    if column in ["dst_ip", "mal_ip"]: return ipaddress.ip_address("0.0.0.0")
                    return ""
                value = item[col_index]
                if column in ["total", "per_second", "max_per_sec", "count"]:
                    try: return float(value)
                    except (ValueError, TypeError): return 0.0
                elif column in ["dst_ip", "mal_ip"]:
                    try: return ipaddress.ip_address(str(value))
                    except (ValueError, TypeError): return ipaddress.ip_address("0.0.0.0")
                else: return str(value)
            return sorted(data, key=sort_key, reverse=reverse_sort)
        except Exception as e:
            logger.error(f"Sorting error in detail view on column '{column}': {e}", exc_info=True)
            return data

    def sort_column(self, tree, column, columns):
        if tree == self.dest_tree:
            sort_col_attr, sort_asc_attr = "dest_sort_column", "dest_sort_ascending"
        elif tree == self.proto_tree:
            sort_col_attr, sort_asc_attr = "proto_sort_column", "proto_sort_ascending"
        else: return

        current_sort_column = getattr(self, sort_col_attr)
        current_sort_ascending = getattr(self, sort_asc_attr)
        new_ascending = not current_sort_ascending if column == current_sort_column else True
        setattr(self, sort_col_attr, column)
        setattr(self, sort_asc_attr, new_ascending)
        logger.debug(f"Set detail table sort: Column='{column}', Ascending={new_ascending}")
        self.update_gui()
