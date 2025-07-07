# ui/tabs/destinations_tab.py
import tkinter as tk
from tkinter import ttk
from collections import deque
from core.config_manager import config
from core.whitelist_manager import get_whitelist

class DestinationsTab:
    def __init__(self, notebook, data_manager, source_ip):
        self.frame = ttk.Frame(notebook)
        self.data_manager = data_manager
        self.source_ip = source_ip
        self.whitelist = get_whitelist()
        self.sort_column = None
        self.sort_ascending = True

        explanation = "Shows all destination IPs this host has communicated with, along with packet counts."
        ttk.Label(self.frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        columns = ("dst_ip", "total", "per_second", "max_per_sec")
        self.tree = ttk.Treeview(self.frame, columns=columns, show='headings')
        headers = {"dst_ip": "Destination IP", "total": "Total Packets", "per_second": "Packets/Sec", "max_per_sec": "Max P/S"}
        widths = {"dst_ip": 150, "total": 100, "per_second": 100, "max_per_sec": 100}
        anchors = {"dst_ip": tk.W, "total": tk.CENTER, "per_second": tk.CENTER, "max_per_sec": tk.CENTER}
        
        for col in columns:
            self.tree.heading(col, text=headers[col], anchor=tk.CENTER, command=lambda c=col: self.sort_column(c, columns))
            self.tree.column(col, width=widths[col], anchor=anchors[col])
            
        self.tree.tag_configure("red", background="#FF9999")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        notebook.add(self.frame, text="Destinations")

    def update_tab(self, ip_snapshot, now, prune_timestamp):
        self.tree.delete(*self.tree.get_children())
        if not ip_snapshot:
            self.tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))
            return

        dest_data_for_table = []
        destinations = ip_snapshot.get("destinations", {})
        for dst_ip, dest_details in destinations.items():
            timestamps_deque = dest_details.get("timestamps", [])
            temp_timestamps = deque(timestamps_deque)
            while temp_timestamps and temp_timestamps[0] < prune_timestamp:
                temp_timestamps.popleft()
            
            packets_per_second = sum(1 for t in temp_timestamps if t >= now - 1.0)
            total_packets = dest_details.get("total", 0)
            max_packets_sec = dest_details.get("max_per_sec", 0)
            is_whitelisted = self.whitelist.is_ip_whitelisted(dst_ip)
            dest_data_for_table.append((dst_ip, total_packets, packets_per_second, max_packets_sec, is_whitelisted))

        if self.sort_column:
            dest_data_for_table = self.sort_data(dest_data_for_table, self.sort_column, self.sort_ascending, ("dst_ip", "total", "per_second", "max_per_sec"))
        
        for row in dest_data_for_table:
            dst, total, p_sec, max_p, is_whitelisted = row
            tags = ()
            if not is_whitelisted and max_p > config.max_packets_per_second:
                tags = ("red",)
            self.tree.insert("", tk.END, values=(dst, total, p_sec, max_p), tags=tags)

    def sort_column(self, tree, column, columns):
        if self.sort_column == column:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = column
            self.sort_ascending = True
        self.update_tab(self.data_manager.get_full_ip_entry_snapshot(self.source_ip), time.time(), time.time() - 61)
