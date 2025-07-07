# ui/tabs/local_network_tab.py
import tkinter as tk
from tkinter import ttk

class LocalNetworkTab:
    def __init__(self, notebook, data_manager, source_ip):
        self.frame = ttk.Frame(notebook)
        self.data_manager = data_manager
        self.source_ip = source_ip

        explanation = "Shows detected local network threats like ARP spoofing and ICMP anomalies."
        ttk.Label(self.frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        status_frame = ttk.Frame(self.frame, padding=(5,5))
        status_frame.pack(fill=tk.X)
        self.arp_spoof_status_var = tk.StringVar(value="ARP Spoofing Detected: Unknown")
        ttk.Label(status_frame, textvariable=self.arp_spoof_status_var).pack(anchor=tk.W)
        self.ping_sweep_status_var = tk.StringVar(value="Ping Sweep Detected: Unknown")
        ttk.Label(status_frame, textvariable=self.ping_sweep_status_var).pack(anchor=tk.W)
        self.icmp_tunneling_status_var = tk.StringVar(value="ICMP Tunneling Detected: Unknown")
        ttk.Label(status_frame, textvariable=self.icmp_tunneling_status_var).pack(anchor=tk.W)
        
        notebook.add(self.frame, text="Local Network")

    def update_tab(self, ip_snapshot):
        if not ip_snapshot:
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
