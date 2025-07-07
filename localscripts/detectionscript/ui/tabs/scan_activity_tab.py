# ui/tabs/scan_activity_tab.py
import tkinter as tk
from tkinter import ttk
import ipaddress

class ScanActivityTab:
    def __init__(self, notebook, data_manager, source_ip):
        self.frame = ttk.Frame(notebook)
        self.data_manager = data_manager
        self.source_ip = source_ip

        explanation = "Shows detected port and host scan activity originating from this host."
        ttk.Label(self.frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        status_frame = ttk.Frame(self.frame, padding=(5,5))
        status_frame.pack(fill=tk.X)
        self.port_scan_status_var = tk.StringVar(value="Port Scan: Unknown")
        ttk.Label(status_frame, textvariable=self.port_scan_status_var).pack(anchor=tk.W)
        self.host_scan_status_var = tk.StringVar(value="Host Scan: Unknown")
        ttk.Label(status_frame, textvariable=self.host_scan_status_var).pack(anchor=tk.W)
        
        ttk.Separator(self.frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        targets_frame = ttk.LabelFrame(self.frame, text="Detected Scan Targets/Ports")
        targets_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("target_ip", "scanned_ports", "scan_types")
        self.tree = ttk.Treeview(targets_frame, columns=columns, show="headings")
        headers = {"target_ip": "Target IP", "scanned_ports": "Scanned Ports", "scan_types": "Scan Types"}
        widths = {"target_ip": 150, "scanned_ports": 250, "scan_types": 100}
        
        for col in columns:
            self.tree.heading(col, text=headers[col], anchor=tk.W)
            self.tree.column(col, width=widths[col], anchor=tk.W)
            
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        notebook.add(self.frame, text="Scan Activity")

    def update_tab(self, ip_snapshot, flag_scan_enabled, scan_ports_detected, scan_hosts_detected):
        self.tree.delete(*self.tree.get_children())
        if not flag_scan_enabled:
            self.port_scan_status_var.set("Port Scan: Detection Disabled")
            self.host_scan_status_var.set("Host Scan: Detection Disabled")
            self.tree.insert("", tk.END, values=("Scan detection disabled in main UI.", ""))
            return

        if not ip_snapshot:
            self.port_scan_status_var.set("Port Scan: Source IP data unavailable")
            self.host_scan_status_var.set("Host Scan: Source IP data unavailable")
            self.tree.insert("", tk.END, values=("Source IP data unavailable.", ""))
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
             self.tree.insert("", tk.END, values=("Scan detected, but no specific targets/ports logged.", "", ""))
        elif not scan_target_details:
            self.tree.insert("", tk.END, values=("No scan targets to display.", "", ""))
        else:
            try: scan_target_details.sort(key=lambda x: ipaddress.ip_address(x[0]))
            except: pass
            for row in scan_target_details:
                self.tree.insert("", tk.END, values=row)
