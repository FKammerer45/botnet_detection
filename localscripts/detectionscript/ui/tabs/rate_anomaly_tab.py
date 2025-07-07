# ui/tabs/rate_anomaly_tab.py
import tkinter as tk
from tkinter import ttk
from core.config_manager import config

class RateAnomalyTab:
    def __init__(self, notebook, data_manager, source_ip):
        self.frame = ttk.Frame(notebook)
        self.data_manager = data_manager
        self.source_ip = source_ip

        explanation = "Shows detected traffic rate anomalies for specific protocols used by this host."
        ttk.Label(self.frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        columns = ("protocol", "count", "mean", "std_dev", "threshold")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings")
        headers = {"protocol": "Protocol", "count": "Packets", "mean": "Mean", "std_dev": "Std Dev", "threshold": "Threshold"}
        widths = {"protocol": 100, "count": 80, "mean": 80, "std_dev": 80, "threshold": 80}
        
        for col in columns:
            self.tree.heading(col, text=headers[col], anchor=tk.W)
            self.tree.column(col, width=widths[col], anchor=tk.W)
            
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        notebook.add(self.frame, text="Rate Anomaly")

    def update_tab(self, ip_snapshot):
        self.tree.delete(*self.tree.get_children())
        if not ip_snapshot:
            self.tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", "", ""))
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
            self.tree.insert("", tk.END, values=("No anomaly data to display.", "", "", "", ""))
        else:
            for row in anomaly_data_for_table:
                self.tree.insert("", tk.END, values=row)
