# ui/tabs/protocols_tab.py
import time
import tkinter as tk
from tkinter import ttk
from collections import deque
from core.config_manager import config

class ProtocolsTab:
    def __init__(self, notebook, data_manager, source_ip):
        self.frame = ttk.Frame(notebook)
        self.data_manager = data_manager
        self.source_ip = source_ip
        self.sort_column = None
        self.sort_ascending = True

        explanation = "Shows all protocols and ports used by this host, along with packet counts."
        ttk.Label(self.frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        columns = ("proto_port", "total", "per_second", "max_per_sec")
        self.tree = ttk.Treeview(self.frame, columns=columns, show='headings')
        headers = {"proto_port": "Protocol/Port", "total": "Total Packets", "per_second": "Packets/Sec", "max_per_sec": "Max P/S"}
        widths = {"proto_port": 150, "total": 100, "per_second": 100, "max_per_sec": 100}
        anchors = {"proto_port": tk.W, "total": tk.CENTER, "per_second": tk.CENTER, "max_per_sec": tk.CENTER}
        
        for col in columns:
            self.tree.heading(col, text=headers[col], anchor=tk.CENTER, command=lambda c=col: self.sort_column(c, columns))
            self.tree.column(col, width=widths[col], anchor=anchors[col])
            
        self.tree.tag_configure("red", background="#FF9999")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        notebook.add(self.frame, text="Protocols")

    def update_tab(self, ip_snapshot, flag_unsafe_enabled, now, prune_timestamp):
        self.tree.delete(*self.tree.get_children())
        if not ip_snapshot:
            self.tree.insert("", tk.END, values=("(Source IP data unavailable)", "", "", ""))
            return

        proto_data_for_table = []
        protocols = ip_snapshot.get("protocols", {})
        for (proto, port), proto_details in protocols.items():
            timestamps_deque = proto_details.get("timestamps", [])
            temp_timestamps = deque(timestamps_deque)
            while temp_timestamps and temp_timestamps[0] < prune_timestamp:
                temp_timestamps.popleft()

            packets_per_second = sum(1 for t in temp_timestamps if t >= now - 1.0)
            total_packets = proto_details.get("total", 0)
            max_packets_sec = proto_details.get("max_per_sec", 0)
            proto_str = f"{str(proto).upper()}:{port}" if port is not None else str(proto).upper()
            proto_data_for_table.append((proto_str, total_packets, packets_per_second, max_packets_sec, proto, port))

        if self.sort_column:
            proto_data_for_table = self.sort_data(proto_data_for_table, self.sort_column, self.sort_ascending, 
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
            if is_flagged: tags = ("red",)
            self.tree.insert("", tk.END, values=(proto_str_val, total_val, p_sec_val, max_p_val), tags=tags)

    def sort_column(self, tree, column, columns):
        if self.sort_column == column:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = column
            self.sort_ascending = True
        self.update_tab(self.data_manager.get_full_ip_entry_snapshot(self.source_ip), True, time.time(), time.time() - 61)
