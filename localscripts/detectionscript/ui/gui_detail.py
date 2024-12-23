#gui_detail.py
import time
import tkinter as tk
from tkinter import ttk
from core.capture import ip_data, lock

class DetailWindow:
    def __init__(self, master, source_ip,
             get_threshold_func,
             get_flag_unsafe_func,    
             get_flag_malicious_func=None):
        self.master = master
        self.master.title(f"Details for {source_ip}")
        self.source_ip = source_ip

        # Store callbacks 
        self.get_threshold_func = get_threshold_func
        self.get_flag_unsafe_func = get_flag_unsafe_func
        self.get_flag_malicious_func = get_flag_malicious_func

        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.dest_frame = tk.Frame(self.notebook)

        # Tab 1: Destinations
        self.notebook.add(self.dest_frame, text="Destinations")

        dest_columns = ("dst_ip", "total", "per_second", "max_per_sec")
        self.dest_tree = ttk.Treeview(self.dest_frame, columns=dest_columns, show='headings')
        self.dest_tree.heading("dst_ip", text="Destination IP", anchor=tk.CENTER,
                               command=lambda: self.sort_column(self.dest_tree, "dst_ip", dest_columns))
        self.dest_tree.heading("total", text="Total Packets", anchor=tk.CENTER,
                               command=lambda: self.sort_column(self.dest_tree, "total", dest_columns))
        self.dest_tree.heading("per_second", text="Packets/Sec", anchor=tk.CENTER,
                               command=lambda: self.sort_column(self.dest_tree, "per_second", dest_columns))
        self.dest_tree.heading("max_per_sec", text="Max P/S", anchor=tk.CENTER,
                               command=lambda: self.sort_column(self.dest_tree, "max_per_sec", dest_columns))
        self.dest_tree.column("dst_ip", width=150, anchor=tk.CENTER)
        self.dest_tree.column("total", width=100, anchor=tk.CENTER)
        self.dest_tree.column("per_second", width=100, anchor=tk.CENTER)
        self.dest_tree.column("max_per_sec", width=100, anchor=tk.CENTER)
        self.dest_tree.tag_configure("red", background="red")
        self.dest_tree.pack(fill=tk.BOTH, expand=True)

        self.dest_sort_column = None
        self.dest_sort_ascending = True

        self.proto_frame = tk.Frame(self.notebook)

        # Tab 2: Protocols
        self.notebook.add(self.proto_frame, text="Protocols")

        proto_columns = ("proto_port", "total", "per_second", "max_per_sec")
        self.proto_tree = ttk.Treeview(self.proto_frame, columns=proto_columns, show='headings')
        self.proto_tree.heading("proto_port", text="Protocol/Port", anchor=tk.CENTER,
                                command=lambda: self.sort_column(self.proto_tree, "proto_port", proto_columns))
        self.proto_tree.heading("total", text="Total Packets", anchor=tk.CENTER,
                                command=lambda: self.sort_column(self.proto_tree, "total", proto_columns))
        self.proto_tree.heading("per_second", text="Packets/Sec", anchor=tk.CENTER,
                                command=lambda: self.sort_column(self.proto_tree, "per_second", proto_columns))
        self.proto_tree.heading("max_per_sec", text="Max P/S", anchor=tk.CENTER,
                                command=lambda: self.sort_column(self.proto_tree, "max_per_sec", proto_columns))
        self.proto_tree.column("proto_port", width=150, anchor=tk.CENTER)
        self.proto_tree.column("total", width=100, anchor=tk.CENTER)
        self.proto_tree.column("per_second", width=100, anchor=tk.CENTER)
        self.proto_tree.column("max_per_sec", width=100, anchor=tk.CENTER)
        self.proto_tree.tag_configure("red", background="red")
        self.proto_tree.pack(fill=tk.BOTH, expand=True)

        self.proto_sort_column = None
        self.proto_sort_ascending = True
        
        # Tab 3: Threat Info (new)
        # Tab 3: Threat Info
        self.threat_frame = tk.Frame(self.notebook)
        self.notebook.add(self.threat_frame, text="Threat Info")

        columns = ("mal_ip", "blocklists", "direction", "count")
        self.threat_tree = ttk.Treeview(self.threat_frame, columns=columns, show="headings")
        self.threat_tree.heading("mal_ip", text="Malicious IP")
        self.threat_tree.heading("blocklists", text="Blocklists")
        self.threat_tree.heading("direction", text="Dir")
        self.threat_tree.heading("count", text="Count")

        self.threat_tree.column("mal_ip", width=130)
        self.threat_tree.column("blocklists", width=150)
        self.threat_tree.column("direction", width=60)
        self.threat_tree.column("count", width=60)

        self.threat_tree.pack(fill=tk.BOTH, expand=True)

        self.update_gui()


    def get_threshold(self):
        try:
            return int(self.get_threshold_func())
        except ValueError:
            return 0



    def update_gui(self):
        """
        Update the Destinations tab, Protocols tab, and Threat Info tab.
        Now uses 'Flag Unsafe Ports' logic for coloring rows in the Protocols tab,
        and includes threshold-based coloring. The old suspicious-protocol code is removed.
        """

        # 1) We'll fetch the new flags. If you still have a single suspicious function, rename or adapt as needed.
        threshold = self.get_threshold()
        flag_unsafe = self.get_flag_unsafe_func() if self.get_flag_unsafe_func else False
        flag_mal = self.get_flag_malicious_func() if self.get_flag_malicious_func else False
        now = time.time()

        # ========== Update Destinations Tab ==========
        dest_data = []
        with lock:
            if self.source_ip in ip_data:
                destinations = ip_data[self.source_ip]["destinations"]
                for dst_ip, d in destinations.items():
                    # Prune timestamps older than 60 seconds
                    d["timestamps"] = [t for t in d["timestamps"] if now - t <= 60]

                    # Packets/sec
                    one_sec_timestamps = [t for t in d["timestamps"] if now - t <= 1.0]
                    per_second = len(one_sec_timestamps)
                    if per_second > d["max_per_sec"]:
                        d["max_per_sec"] = per_second

                    total = d["total"]
                    max_ps = d["max_per_sec"]
                    dest_data.append((dst_ip, total, per_second, max_ps))

        # Sort if needed
        if self.dest_sort_column is not None:
            dest_data = self.sort_data(
                dest_data,
                self.dest_sort_column,
                self.dest_sort_ascending,
                ("dst_ip", "total", "per_second", "max_per_sec")
            )

        # Clear the Destinations tree
        for row_id in self.dest_tree.get_children():
            self.dest_tree.delete(row_id)

        # Insert rows for Destinations
        for row in dest_data:
            dst_ip, total, per_sec, max_ps = row
            tags = ()
            # Color row red if packets/sec exceed threshold
            if max_ps > threshold:
                tags = ("red",)
            self.dest_tree.insert("", tk.END, values=row, tags=tags)

        # ========== Update Protocols Tab ==========
        proto_data = []
        with lock:
            if self.source_ip in ip_data:
                protocols = ip_data[self.source_ip]["protocols"]
                for (proto, port), p in protocols.items():
                    # Prune old timestamps
                    p["timestamps"] = [t for t in p["timestamps"] if now - t <= 60]

                    # Packets/sec
                    one_sec_timestamps = [t for t in p["timestamps"] if now - t <= 1.0]
                    per_second = len(one_sec_timestamps)
                    if per_second > p["max_per_sec"]:
                        p["max_per_sec"] = per_second

                    total = p["total"]
                    max_ps = p["max_per_sec"]
                    proto_port_str = f"{proto.upper()}:{port}" if port is not None else proto.upper()

                    proto_data.append((proto_port_str, total, per_second, max_ps, proto, port))

        if self.proto_sort_column is not None:
            proto_data = self.sort_data(
                proto_data,
                self.proto_sort_column,
                self.proto_sort_ascending,
                ("proto_port", "total", "per_second", "max_per_sec")
            )

        # Clear Protocols tree
        for row_id in self.proto_tree.get_children():
            self.proto_tree.delete(row_id)

        # Insert rows for Protocols
        for row in proto_data:
            proto_port_str, total, per_sec, max_ps, proto, port = row

            # Check threshold
            tags = ()
            if max_ps > threshold:
                tags = ("red",)

            # If "Flag Unsafe Ports" is on, check if proto or port is in your unsafe sets
            if flag_unsafe:
                # e.g., from globals import UNSAFE_PORTS, UNSAFE_PROTOCOLS
                from config.globals import UNSAFE_PORTS, UNSAFE_PROTOCOLS
                if (port in UNSAFE_PORTS) or (proto in UNSAFE_PROTOCOLS):
                    tags = ("red",)

            self.proto_tree.insert(
                "",
                tk.END,
                values=(proto_port_str, total, per_sec, max_ps),
                tags=tags
            )

        # ========== Update Threat Info Tab ==========
        self.update_threat_info()

        # Re-run after 1 second
        self.master.after(1000, self.update_gui)


    def update_threat_info(self):
        with lock:
            if self.source_ip not in ip_data:
                return
            
            # Clear existing rows first
            for row in self.threat_tree.get_children():
                self.threat_tree.delete(row)

            info = ip_data[self.source_ip]

            # malicious_hits is now a dict like:
            # {
            #    "185.106.92.110": {
            #       "blocklists": {"firehol_level1.netset", "abusech_feodo"},
            #       "count": 5,
            #       "direction": "outbound"
            #    },
            #    ...
            # }
            hits_dict = info.get("malicious_hits", {})

            for mal_ip, hit_info in hits_dict.items():
                blocklist_names = ','.join(hit_info["blocklists"])
                direction = hit_info["direction"]
                count = hit_info["count"]

                # Insert a single row for each malicious IP
                self.threat_tree.insert(
                    "",
                    tk.END,
                    values=(mal_ip, blocklist_names, direction, count)
                )

    def sort_data(self, data, column, ascending, columns, extra_offset=0):
        col_index = columns.index(column) + extra_offset
        return sorted(data, key=lambda x: x[col_index], reverse=not ascending)

    def sort_column(self, tree, column, columns):
        if tree == self.dest_tree:
            sort_col = self.dest_sort_column
            sort_asc = self.dest_sort_ascending
        else:
            sort_col = self.proto_sort_column
            sort_asc = self.proto_sort_ascending

        tree_data = []
        for row_id in tree.get_children():
            vals = tree.item(row_id)["values"]
            tree_data.append(vals)

        if column == sort_col:
            sort_asc = not sort_asc
        else:
            sort_col = column
            sort_asc = True

        col_index = columns.index(column)
        tree_data = sorted(tree_data, key=lambda x: x[col_index], reverse=not sort_asc)

        for row_id in tree.get_children():
            tree.delete(row_id)
        for vals in tree_data:
            tree.insert("", tk.END, values=vals)

        if tree == self.dest_tree:
            self.dest_sort_column = sort_col
            self.dest_sort_ascending = sort_asc
        else:
            self.proto_sort_column = sort_col
            self.proto_sort_ascending = sort_asc
