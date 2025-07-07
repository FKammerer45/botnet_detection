# ui/tabs/threat_info_tab.py
import tkinter as tk
from tkinter import ttk
import ipaddress

class ThreatInfoTab:
    def __init__(self, notebook, data_manager, source_ip):
        self.frame = ttk.Frame(notebook)
        self.data_manager = data_manager
        self.source_ip = source_ip

        explanation = "Shows all malicious IPs, domains, and JA3/S fingerprints this host has communicated with, based on loaded blocklists."
        ttk.Label(self.frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        columns = ("mal_ip", "blocklists", "direction", "count")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings")
        headers = {"mal_ip": "Malicious IP", "blocklists": "Blocklists", "direction": "Dir", "count": "Count"}
        widths = {"mal_ip": 130, "blocklists": 150, "direction": 60, "count": 60}
        anchors = {"mal_ip": tk.W, "blocklists": tk.W, "direction": tk.CENTER, "count": tk.CENTER}
        
        for col in columns:
            self.tree.heading(col, text=headers[col], anchor=tk.CENTER)
            self.tree.column(col, width=widths[col], anchor=anchors[col])
            
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        notebook.add(self.frame, text="Threat Info")

    def update_tab(self, ip_snapshot, flag_malicious_enabled):
        self.tree.delete(*self.tree.get_children())
        if not flag_malicious_enabled:
            self.tree.insert("", tk.END, values=("Malicious IP Flag Disabled", "", "", ""))
            return
        if not ip_snapshot:
            self.tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))
            return

        threat_data_for_table = []
        if ip_snapshot:
            malicious_hits = ip_snapshot.get("malicious_hits", {})
            if ip_snapshot.get("malicious_ja3"):
                threat_data_for_table.append(("JA3", ip_snapshot["malicious_ja3"], "N/A", 1))
            if ip_snapshot.get("malicious_ja3s"):
                threat_data_for_table.append(("JA3S", ip_snapshot["malicious_ja3s"], "N/A", 1))

            if not malicious_hits and not ip_snapshot.get("malicious_ja3") and not ip_snapshot.get("malicious_ja3s"):
                self.tree.insert("", tk.END, values=("No recorded malicious hits", "", "", ""))
                return
            for mal_ip, hit_info in malicious_hits.items():
                bl_descriptions = ', '.join(sorted(list(hit_info.get("blocklists", {}).values())))
                direction = hit_info.get("direction", "N/A")
                count = hit_info.get("count", 0)
                threat_data_for_table.append((mal_ip, bl_descriptions, direction, count))
        
        if not threat_data_for_table:
            self.tree.insert("", tk.END, values=("No malicious hits to display", "", "", ""))
        else:
            try: threat_data_for_table.sort(key=lambda x: ipaddress.ip_address(str(x[0])))
            except: pass
            for row in threat_data_for_table:
                self.tree.insert("", tk.END, values=row)
