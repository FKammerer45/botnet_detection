#gui_main
import time
import tkinter as tk
from tkinter import ttk
from core.capture import ip_data, lock, aggregate_minute_data
from ui.gui_unsafe import UnsafeConfigWindow
from ui.gui_temporal import TemporalAnalysisWindow
from core.blocklist_integration import download_blocklists, load_blocklists
from config.globals import UNSAFE_PORTS, UNSAFE_PROTOCOLS



class PacketStatsGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Network Users by Source IP")

        # 1. Download & Load blocklists at script startup
        download_blocklists()
        load_blocklists()

        # Track sorting
        self.current_sort_column = None
        self.current_sort_ascending = True

        # Description frame
        desc_frame = tk.Frame(master)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)

        desc_label_text = (
            "This table shows network participants by their source IP.\n"
            "Double-click an IP to view details.\n"
            "Click 'Temporal Analysis' to see traffic trends over time.\n\n"
            "Enter a Max P/S threshold and optionally flag unsafe ports or malicious IPs.\n"
            "Use 'Configure Unsafe Ports' to add or remove flagged ports."
        )
        desc_label = tk.Label(desc_frame, text=desc_label_text, justify=tk.LEFT, anchor="w")
        desc_label.pack(anchor="w")

        # Top frame for threshold and checkboxes
        top_frame = tk.Frame(master)
        top_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(top_frame, text="Max P/S Threshold:").pack(side=tk.LEFT)
        self.threshold_entry = tk.Entry(top_frame, width=10)
        self.threshold_entry.pack(side=tk.LEFT, padx=5)
        self.threshold_entry.insert(0, "1000")

        # Flag Unsafe Ports
        self.flag_unsafe_var = tk.BooleanVar(value=False)
        flag_unsafe_checkbox = tk.Checkbutton(
            top_frame,
            text="Flag Unsafe Ports/Protocols",
            variable=self.flag_unsafe_var
        )
        flag_unsafe_checkbox.pack(side=tk.LEFT, padx=5)

        # Flag Malicious IPs
        self.flag_malicious_var = tk.BooleanVar(value=False)
        flag_mal_checkbox = tk.Checkbutton(
            top_frame,
            text="Flag Malicious IPs",
            variable=self.flag_malicious_var
        )
        flag_mal_checkbox.pack(side=tk.LEFT, padx=5)

        # Configure Unsafe Ports button
        unsafe_button = tk.Button(top_frame, text="Configure Unsafe Ports/Protocols", command=self.configure_unsafe)
        unsafe_button.pack(side=tk.LEFT, padx=5)

        # Temporal Analysis button
        temporal_button = tk.Button(top_frame, text="Temporal Analysis", command=self.open_temporal_analysis)
        temporal_button.pack(side=tk.LEFT, padx=5)

        # Main table
        table_frame = tk.Frame(master)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("ip", "total", "per_minute", "per_second", "max_per_sec")
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings')
        self.tree.heading("ip", text="IP Address", anchor=tk.CENTER)
        self.tree.heading("total", text="Total Packets", anchor=tk.CENTER,
                        command=lambda: self.sort_column("total"))
        self.tree.heading("per_minute", text="Packets/Min", anchor=tk.CENTER,
                        command=lambda: self.sort_column("per_minute"))
        self.tree.heading("per_second", text="Packets/Sec", anchor=tk.CENTER,
                        command=lambda: self.sort_column("per_second"))
        self.tree.heading("max_per_sec", text="Max P/S", anchor=tk.CENTER,
                        command=lambda: self.sort_column("max_per_sec"))

        self.tree.column("ip", width=150, anchor=tk.CENTER)
        self.tree.column("total", width=100, anchor=tk.CENTER)
        self.tree.column("per_minute", width=100, anchor=tk.CENTER)
        self.tree.column("per_second", width=100, anchor=tk.CENTER)
        self.tree.column("max_per_sec", width=100, anchor=tk.CENTER)

        # Tag for coloring rows red
        self.tree.tag_configure("red", background="red")

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Schedule aggregator
        self.schedule_aggregation()

        # Start the GUI updates
        self.update_gui()


    def schedule_aggregation(self):
        # Call aggregator and re-schedule every 5 seconds
        aggregate_minute_data()
        self.master.after(60000, self.schedule_aggregation)

    def configure_unsafe(self):
        """Open the 'Configure Unsafe Ports' window."""
        top = tk.Toplevel(self.master)
        from ui.gui_unsafe import UnsafeConfigWindow
        UnsafeConfigWindow(top)

    def open_temporal_analysis(self):
        top = tk.Toplevel(self.master)
        TemporalAnalysisWindow(top, self.get_flag_unsafe, self.get_threshold)  # CHANGED param if desired

    def get_threshold(self):
        try:
            return int(self.threshold_entry.get())
        except ValueError:
            return 0

    # Check if "Flag Unsafe Ports" is on
    def get_flag_unsafe(self):
        return self.flag_unsafe_var.get()

    # Check if "Flag Malicious IPs" is on
    def get_flag_malicious(self):
        return self.flag_malicious_var.get()

    def on_double_click(self, event):
        row_id = self.tree.focus()
        if not row_id:
            return
        row_values = self.tree.item(row_id)["values"]
        if not row_values:
            return
        source_ip = row_values[0]
        top = tk.Toplevel(self.master)
        from ui.gui_detail import DetailWindow
        # Pass 'get_flag_unsafe' and 'get_flag_malicious' 
        DetailWindow(top, source_ip, self.get_threshold, self.get_flag_unsafe, self.get_flag_malicious)

    def update_gui(self):
        """
        Update the main table with current device stats.
        We flag a row in red if:
        1) Packets/sec exceeds threshold
        2) "Flag Unsafe Ports" is on AND (an unsafe port OR unsafe protocol) is found
        3) "Flag Malicious IPs" is on AND device contacted malicious IP
        """
        threshold = self.get_threshold()
        flag_unsafe = self.get_flag_unsafe()       # Single checkbox for unsafe ports/protocols
        flag_mal = self.get_flag_malicious()
        now = time.time()

        data = []
        with lock:
            for ip, d in ip_data.items():
                # Prune timestamps older than 60 seconds
                d["timestamps"] = [t for t in d["timestamps"] if now - t <= 60]

                total = d["total"]
                per_min = len(d["timestamps"])
                one_sec_timestamps = [t for t in d["timestamps"] if now - t <= 1.0]
                per_second = len(one_sec_timestamps)

                # Update max_per_sec if needed
                if per_second > d["max_per_sec"]:
                    d["max_per_sec"] = per_second
                max_ps = d["max_per_sec"]

                # Check for unsafe port usage
                unsafe_port_found = any(
                    port in UNSAFE_PORTS
                    for (proto, port) in d["protocols"].keys()
                )

                # Check for unsafe protocol usage
                unsafe_protocol_found = any(
                    proto in UNSAFE_PROTOCOLS
                    for (proto, port) in d["protocols"].keys()
                )

                # Check if device contacted malicious IP
                malicious_flag = d.get("contacted_malicious_ip", False)

                # Collect all info for sorting & insertion
                data.append((
                    ip,              # 0
                    total,           # 1
                    per_min,         # 2
                    per_second,      # 3
                    max_ps,          # 4
                    unsafe_port_found,      # 5
                    unsafe_protocol_found,  # 6
                    malicious_flag          # 7
                ))

        # If there's a sort column, apply it
        if self.current_sort_column is not None:
            data = self.sort_data(data, self.current_sort_column, self.current_sort_ascending)

        # Clear the current rows
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)

        # Re-insert rows
        for row in data:
            (ip_val,
            total_val,
            per_min_val,
            per_sec_val,
            max_ps_val,
            unsafe_port_found,
            unsafe_protocol_found,
            malicious_flag) = row

            # Decide if we color row in red
            # 1) max_ps_val > threshold
            # 2) if "Flag Unsafe Ports" is on & (unsafe_port_found OR unsafe_protocol_found)
            # 3) if "Flag Malicious IPs" is on & malicious_flag
            tags = ()
            if (
                max_ps_val > threshold
                or (flag_unsafe and (unsafe_port_found or unsafe_protocol_found))
                or (flag_mal and malicious_flag)
            ):
                tags = ("red",)

            self.tree.insert(
                "",
                tk.END,
                values=(ip_val, total_val, per_min_val, per_sec_val, max_ps_val),
                tags=tags
            )

        # Schedule the next update
        self.master.after(1000, self.update_gui)


    def sort_data(self, data, column, ascending):
        col_map = {"ip":0, "total":1, "per_minute":2, "per_second":3, "max_per_sec":4}
        col_index = col_map[column]
        return sorted(data, key=lambda x: x[col_index], reverse=not ascending)

    def sort_column(self, column):
        """
        Sort the table by the given column. Then re-run update_gui to refresh rows.
        """
        if column == self.current_sort_column:
            self.current_sort_ascending = not self.current_sort_ascending
        else:
            self.current_sort_column = column
            self.current_sort_ascending = True

        self.update_gui()