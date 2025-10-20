# ui/components/configuration_frame.py
import tkinter as tk
from tkinter import ttk
from core.config_manager import config
from ui.gui_tooltip import Tooltip

class ConfigurationFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        config_frame = self
        config_frame.pack(side=tk.TOP, fill=tk.X, anchor='w')
        row1_frame = tk.Frame(config_frame)
        row1_frame.pack(fill=tk.X, pady=2)
        tk.Label(row1_frame, text="Pkts/Min Threshold:").pack(side=tk.LEFT, padx=(0, 2))
        self.controller.threshold_var = tk.StringVar(value=str(config.max_packets_per_minute))
        self.controller.threshold_entry = tk.Entry(row1_frame, width=8, textvariable=self.controller.threshold_var)
        self.controller.threshold_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.controller.threshold_var.trace_add("write", self.controller.update_threshold_config)
        self.controller.flag_unsafe_var = tk.BooleanVar(value=True)
        cb_unsafe = tk.Checkbutton(row1_frame, text="Flag Insecure Protocols", variable=self.controller.flag_unsafe_var)
        cb_unsafe.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_unsafe, "Flags traffic on unencrypted or legacy ports/protocols (e.g., Telnet, FTP).")
        self.controller.flag_malicious_var = tk.BooleanVar(value=True)
        cb_malicious = tk.Checkbutton(row1_frame, text="Flag Malicious IP", variable=self.controller.flag_malicious_var)
        cb_malicious.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_malicious, "Flags traffic to/from IPs found on configured blocklists.")
        self.controller.flag_dns_var = tk.BooleanVar(value=True)
        cb_dns = tk.Checkbutton(row1_frame, text="Flag Malicious DNS", variable=self.controller.flag_dns_var)
        cb_dns.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_dns, "Flags DNS queries for domains found on configured blocklists.")
        self.controller.flag_scan_var = tk.BooleanVar(value=True)
        cb_scan = tk.Checkbutton(row1_frame, text="Flag Port Scan", variable=self.controller.flag_scan_var)
        cb_scan.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_scan, "Flags hosts that appear to be performing port or host scans.")
        self.controller.flag_rate_anomaly_var = tk.BooleanVar(value=True)
        cb_rate_anomaly = tk.Checkbutton(row1_frame, text="Flag Rate Anomaly", variable=self.controller.flag_rate_anomaly_var)
        cb_rate_anomaly.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_rate_anomaly, "Flags hosts with unusual traffic rates for specific protocols.")
        self.controller.flag_ja3_var = tk.BooleanVar(value=True)
        cb_ja3 = tk.Checkbutton(row1_frame, text="Flag JA3/S", variable=self.controller.flag_ja3_var)
        cb_ja3.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_ja3, "Flags hosts with malicious JA3/JA3S fingerprints.")
        self.controller.flag_dns_analysis_var = tk.BooleanVar(value=True)
        cb_dns_analysis = tk.Checkbutton(row1_frame, text="Flag DNS Analysis", variable=self.controller.flag_dns_analysis_var)
        cb_dns_analysis.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_dns_analysis, "Flags hosts with suspicious DNS activity (DGA, tunneling).")
        self.controller.flag_local_threat_var = tk.BooleanVar(value=True)
        cb_local_threat = tk.Checkbutton(row1_frame, text="Flag Local Threats", variable=self.controller.flag_local_threat_var)
        cb_local_threat.pack(side=tk.LEFT, padx=2)
        self.create_tooltip(cb_local_threat, "Flags local network threats like ARP spoofing and ICMP anomalies.")
        row2_frame = tk.Frame(config_frame)
        row2_frame.pack(fill=tk.X, pady=2)
        tk.Button(row2_frame, text="Conf Unsafe", command=self.controller.configure_unsafe).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Conf Scan", command=self.controller.configure_scan).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Conf Beaconing", command=self.controller.configure_beaconing).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Conf DNS", command=self.controller.configure_dns).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Conf Local Net", command=self.controller.configure_local_network).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Conf Scoring", command=self.controller.configure_scoring).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Blocklists", command=self.controller.open_blocklist_manager).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Whitelist", command=self.controller.open_whitelist_manager).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Temporal", command=self.controller.open_temporal_analysis).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Help", command=self.controller.open_documentation).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Testing Suite", command=self.controller.open_testing_suite).pack(side=tk.LEFT, padx=3)

    def create_tooltip(self, widget, text):
        tooltip = Tooltip(widget, text)
        widget.bind("<Enter>", lambda event: tooltip.showtip())
        widget.bind("<Leave>", lambda event: tooltip.hidetip())
