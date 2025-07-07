# ui/tabs/beaconing_tab.py
import tkinter as tk
from tkinter import ttk
from core.config_manager import config

class BeaconingTab:
    def __init__(self, notebook, data_manager, source_ip):
        self.frame = ttk.Frame(notebook)
        self.data_manager = data_manager
        self.source_ip = source_ip

        explanation = "Shows detected Command & Control (C2) beaconing activity from this host to external destinations."
        ttk.Label(self.frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        columns = ("destination", "interval", "tolerance", "occurrences")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings")
        headers = {"destination": "Destination", "interval": "Interval (s)", "tolerance": "Tolerance (s)", "occurrences": "Occurrences"}
        widths = {"destination": 150, "interval": 100, "tolerance": 100, "occurrences": 100}
        
        for col in columns:
            self.tree.heading(col, text=headers[col], anchor=tk.W)
            self.tree.column(col, width=widths[col], anchor=tk.W)
            
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        notebook.add(self.frame, text="Beaconing")

    def update_tab(self, ip_snapshot):
        self.tree.delete(*self.tree.get_children())
        if not ip_snapshot:
            self.tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))
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
                        if abs(interval - config.beaconing_interval_seconds) <= config.beaconing_tolerance_seconds:
                            consistent_beacons += 1
                    
                    if consistent_beacons + 1 >= config.beaconing_min_occurrences:
                        beaconing_data_for_table.append((dest_ip, f"{mean_interval:.2f}", config.beaconing_tolerance_seconds, len(timestamps)))

        if not beaconing_data_for_table:
            self.tree.insert("", tk.END, values=("No beaconing detected.", "", "", ""))
        else:
            for row in beaconing_data_for_table:
                self.tree.insert("", tk.END, values=row)
