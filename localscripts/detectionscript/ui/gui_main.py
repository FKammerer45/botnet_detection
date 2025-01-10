#gui_main.
import time
import tkinter as tk
from tkinter import ttk
from core.capture import ip_data, lock, aggregate_minute_data
from ui.gui_unsafe import UnsafeConfigWindow
from ui.gui_temporal import TemporalAnalysisWindow
from ui.gui_blocklist_manager import open_blocklist_manager
from core.blocklist_integration import blocklists,download_blocklists, load_blocklists
from config.globals import UNSAFE_PORTS, UNSAFE_PROTOCOLS


class PacketStatsGUI:
    def __init__(self, master):
        """
        Initialize the main GUI window for monitoring network statistics.
        """
        self.master = master
        self.master.title("Network Users by Source IP")

        # Download and load blocklists during startup
        download_blocklists()
        load_blocklists()

        # Track sorting state
        self.current_sort_column = None
        self.current_sort_ascending = True

        # Add description label
        self.add_description_frame()

        # Add configuration options
        self.add_configuration_frame()

        # Add the main data table
        self.add_table_frame()

        # Schedule periodic data aggregation and GUI updates
        self.schedule_aggregation()
        self.update_gui()

    def add_description_frame(self):
        """
        Add a description frame with instructions.
        """
        desc_frame = tk.Frame(self.master)
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

    def add_configuration_frame(self):
        """
        Add configuration options like threshold, unsafe ports, and blocklist settings.
        """
        top_frame = tk.Frame(self.master)
        top_frame.pack(fill=tk.X, padx=5, pady=5)

        # Max P/S threshold input
        tk.Label(top_frame, text="Max P/S Threshold:").pack(side=tk.LEFT)
        self.threshold_entry = tk.Entry(top_frame, width=10)
        self.threshold_entry.pack(side=tk.LEFT, padx=5)
        self.threshold_entry.insert(0, "1000")

        # Flag unsafe ports checkbox
        self.flag_unsafe_var = tk.BooleanVar(value=False)
        flag_unsafe_checkbox = tk.Checkbutton(
            top_frame, text="Flag Unsafe Ports/Protocols", variable=self.flag_unsafe_var
        )
        flag_unsafe_checkbox.pack(side=tk.LEFT, padx=5)

        # Manage blocklists button
        blocklist_button = tk.Button(top_frame, text="Manage Blocklists", command=open_blocklist_manager)
        blocklist_button.pack(side=tk.LEFT, padx=5)

        # Flag malicious IPs checkbox
        self.flag_malicious_var = tk.BooleanVar(value=False)
        flag_mal_checkbox = tk.Checkbutton(
            top_frame, text="Flag Malicious IPs from Blocklist", variable=self.flag_malicious_var
        )
        flag_mal_checkbox.pack(side=tk.LEFT, padx=5)

        # Configure unsafe ports button
        unsafe_button = tk.Button(top_frame, text="Configure Unsafe Ports/Protocols", command=self.configure_unsafe)
        unsafe_button.pack(side=tk.LEFT, padx=5)

        # Temporal analysis button
        temporal_button = tk.Button(top_frame, text="Temporal Analysis", command=self.open_temporal_analysis)
        temporal_button.pack(side=tk.LEFT, padx=5)

    def add_table_frame(self):
        """
        Add the main table for displaying network statistics.
        """
        table_frame = tk.Frame(self.master)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("ip", "total", "per_minute", "per_second", "max_per_sec")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        # Configure table headings
        self.tree.heading("ip", text="IP Address", anchor=tk.CENTER)
        self.tree.heading("total", text="Total Packets", anchor=tk.CENTER, command=lambda: self.sort_column("total"))
        self.tree.heading("per_minute", text="Packets/Min", anchor=tk.CENTER, command=lambda: self.sort_column("per_minute"))
        self.tree.heading("per_second", text="Packets/Sec", anchor=tk.CENTER, command=lambda: self.sort_column("per_second"))
        self.tree.heading("max_per_sec", text="Max P/S", anchor=tk.CENTER, command=lambda: self.sort_column("max_per_sec"))

        # Configure column widths
        self.tree.column("ip", width=150, anchor=tk.CENTER)
        self.tree.column("total", width=100, anchor=tk.CENTER)
        self.tree.column("per_minute", width=100, anchor=tk.CENTER)
        self.tree.column("per_second", width=100, anchor=tk.CENTER)
        self.tree.column("max_per_sec", width=100, anchor=tk.CENTER)

        # Add red tag for flagged rows
        self.tree.tag_configure("red", background="red")
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.pack(fill=tk.BOTH, expand=True)

    def schedule_aggregation(self):
        """
        Schedule periodic data aggregation.
        """
        aggregate_minute_data()
        self.master.after(60000, self.schedule_aggregation)

    def configure_unsafe(self):
        """
        Open the 'Configure Unsafe Ports' window.
        """
        top = tk.Toplevel(self.master)
        UnsafeConfigWindow(top)

    def open_temporal_analysis(self):
        """
        Open the temporal analysis window to view traffic trends.
        """
        top = tk.Toplevel(self.master)
        TemporalAnalysisWindow(top, self.get_flag_unsafe, self.get_threshold)

    def get_threshold(self):
        """
        Retrieve the Max P/S threshold entered by the user.
        """
        try:
            return int(self.threshold_entry.get())
        except ValueError:
            return 0

    def get_flag_unsafe(self):
        """
        Check if 'Flag Unsafe Ports/Protocols' is enabled.
        """
        return self.flag_unsafe_var.get()

    def get_flag_malicious(self):
        """
        Check if 'Flag Malicious IPs from Blocklist' is enabled.
        """
        return self.flag_malicious_var.get()

    def on_double_click(self, event):
        """
        Handle double-click events on a row to show details for the selected IP.
        """
        row_id = self.tree.focus()
        if not row_id:
            return
        row_values = self.tree.item(row_id)["values"]
        if not row_values:
            return
        source_ip = row_values[0]
        top = tk.Toplevel(self.master)
        from ui.gui_detail import DetailWindow
        DetailWindow(top, source_ip, self.get_threshold, self.get_flag_unsafe, self.get_flag_malicious)

    def update_gui(self):
        """
        Update the main table with the latest data, applying flags for:
        - Exceeding Max P/S threshold.
        - Contacting malicious IPs based on active blocklists.
        - Using unsafe ports or protocols.
        """
        threshold = self.get_threshold()
        flag_unsafe = self.get_flag_unsafe()
        flag_mal = self.get_flag_malicious()
        now = time.time()

        data = []
        with lock:
            for ip, d in ip_data.items():
                # Prune timestamps older than 60 seconds
                d["timestamps"] = [t for t in d["timestamps"] if now - t <= 60]

                # Basic metrics
                total = d["total"]
                per_min = len(d["timestamps"])
                one_sec_timestamps = [t for t in d["timestamps"] if now - t <= 1.0]
                per_second = len(one_sec_timestamps)

                # Update max P/S
                d["max_per_sec"] = max(d["max_per_sec"], per_second)
                max_ps = d["max_per_sec"]

                # Check for unsafe ports or protocols
                unsafe_port_found = any(
                    port in UNSAFE_PORTS for (proto, port) in d["protocols"].keys()
                )
                unsafe_protocol_found = any(
                    proto in UNSAFE_PROTOCOLS for (proto, port) in d["protocols"].keys()
                )

                # Check for malicious IPs based on active blocklists
                malicious_flag = False
                if "malicious_hits" in d:
                    for mal_ip, hit_info in d["malicious_hits"].items():
                        active_blocklists = [
                            bl for bl in hit_info["blocklists"] if blocklists.get(bl, False)
                        ]
                        if active_blocklists:
                            malicious_flag = True
                            break

                # Update `contacted_malicious_ip` flag
                d["contacted_malicious_ip"] = malicious_flag

                # Collect data for the table
                data.append((
                    ip, total, per_min, per_second, max_ps,
                    unsafe_port_found, unsafe_protocol_found, malicious_flag
                ))

        # Apply sorting if needed
        if self.current_sort_column:
            data = self.sort_data(data, self.current_sort_column, self.current_sort_ascending)

        # Clear the table rows
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)

        # Insert updated rows with red flagging logic
        for row in data:
            ip_val, total_val, per_min_val, per_sec_val, max_ps_val, unsafe_port_found, unsafe_protocol_found, malicious_flag = row

            # Decide if the row should be flagged red
            tags = ()
            if (
                max_ps_val > threshold  # Exceeds Max P/S threshold
                or (flag_unsafe and (unsafe_port_found or unsafe_protocol_found))  # Unsafe ports/protocols
                or (flag_mal and malicious_flag)  # Malicious IPs
            ):
                tags = ("red",)

            self.tree.insert(
                "", tk.END,
                values=(ip_val, total_val, per_min_val, per_sec_val, max_ps_val),
                tags=tags
            )

        # Schedule the next update
        self.master.after(1000, self.update_gui)

    def sort_data(self, data, column, ascending):
        """
        Sort the table data by the given column.
        """
        col_map = {"ip": 0, "total": 1, "per_minute": 2, "per_second": 3, "max_per_sec": 4}
        col_index = col_map[column]
        return sorted(data, key=lambda x: x[col_index], reverse=not ascending)

    def sort_column(self, column):
        """
        Sort the table by the specified column.
        """
        if column == self.current_sort_column:
            self.current_sort_ascending = not self.current_sort_ascending
        else:
            self.current_sort_column = column
            self.current_sort_ascending = True
        self.update_gui()
