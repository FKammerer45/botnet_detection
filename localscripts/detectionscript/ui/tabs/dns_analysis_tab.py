# ui/tabs/dns_analysis_tab.py
import tkinter as tk
from tkinter import ttk

class DnsAnalysisTab:
    def __init__(self, notebook, data_manager, source_ip):
        self.frame = ttk.Frame(notebook)
        self.data_manager = data_manager
        self.source_ip = source_ip

        explanation = "Shows advanced DNS analysis, including DGA and DNS tunneling detection."
        ttk.Label(self.frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        status_frame = ttk.Frame(self.frame, padding=(5,5))
        status_frame.pack(fill=tk.X)
        self.dga_status_var = tk.StringVar(value="DGA Detected: Unknown")
        ttk.Label(status_frame, textvariable=self.dga_status_var).pack(anchor=tk.W)
        self.dns_tunneling_status_var = tk.StringVar(value="DNS Tunneling Detected: Unknown")
        ttk.Label(status_frame, textvariable=self.dns_tunneling_status_var).pack(anchor=tk.W)
        
        notebook.add(self.frame, text="DNS Analysis")

    def update_tab(self, ip_snapshot):
        if not ip_snapshot:
            self.dga_status_var.set("DGA Detected: Source IP data unavailable")
            self.dns_tunneling_status_var.set("DNS Tunneling Detected: Source IP data unavailable")
            return

        dga_detected = ip_snapshot.get("dga_detected", False)
        dns_tunneling_detected = ip_snapshot.get("dns_tunneling_detected", False)

        self.dga_status_var.set(f"DGA Detected: {'Yes' if dga_detected else 'No'}")
        self.dns_tunneling_status_var.set(f"DNS Tunneling Detected: {'Yes' if dns_tunneling_detected else 'No'}")
