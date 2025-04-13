# gui_detail.py
import time
import tkinter as tk
from tkinter import ttk
import logging
from collections import deque, defaultdict
from core.capture import ip_data, lock
# *** FIX: Import the correct name 'blocklists' ***
from core.blocklist_integration import blocklists
from config.globals import UNSAFE_PORTS, UNSAFE_PROTOCOLS
import datetime
import ipaddress

logger = logging.getLogger(__name__)

class DetailWindow:
    def __init__(self, master, source_ip,
                 get_threshold_func,
                 get_flag_unsafe_func,
                 get_flag_malicious_func=None):
        """Initialize the detail view window."""
        self.master = master
        self.master.title(f"Details for {source_ip}")
        self.source_ip = source_ip
        logger.info(f"Opening detail window for IP: {self.source_ip}")

        self.get_threshold_func = get_threshold_func
        self.get_flag_unsafe_func = get_flag_unsafe_func
        self.get_flag_malicious_func = get_flag_malicious_func

        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.dest_frame = tk.Frame(self.notebook)
        self.notebook.add(self.dest_frame, text="Destinations")
        self._setup_destinations_tab()

        self.proto_frame = tk.Frame(self.notebook)
        self.notebook.add(self.proto_frame, text="Protocols")
        self._setup_protocols_tab()

        self.threat_frame = tk.Frame(self.notebook)
        self.notebook.add(self.threat_frame, text="Threat Info")
        self._setup_threat_tab()

        self._update_scheduled = None
        self.update_gui()
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Handle window closing actions."""
        logger.info(f"Closing detail window for IP: {self.source_ip}")
        if self._update_scheduled:
            try: self.master.after_cancel(self._update_scheduled)
            except tk.TclError: pass
            self._update_scheduled = None
        try: self.master.destroy()
        except tk.TclError: pass

    def _setup_destinations_tab(self):
        """Configure the widgets for the Destinations tab."""
        dest_columns = ("dst_ip", "total", "per_second", "max_per_sec")
        self.dest_tree = ttk.Treeview(self.dest_frame, columns=dest_columns, show='headings')
        self.dest_tree.heading("dst_ip", text="Destination IP", anchor=tk.CENTER, command=lambda: self.sort_column(self.dest_tree, "dst_ip", dest_columns))
        self.dest_tree.heading("total", text="Total Packets", anchor=tk.CENTER, command=lambda: self.sort_column(self.dest_tree, "total", dest_columns))
        self.dest_tree.heading("per_second", text="Packets/Sec", anchor=tk.CENTER, command=lambda: self.sort_column(self.dest_tree, "per_second", dest_columns))
        self.dest_tree.heading("max_per_sec", text="Max P/S", anchor=tk.CENTER, command=lambda: self.sort_column(self.dest_tree, "max_per_sec", dest_columns))
        self.dest_tree.column("dst_ip", width=150, anchor=tk.W); self.dest_tree.column("total", width=100, anchor=tk.CENTER)
        self.dest_tree.column("per_second", width=100, anchor=tk.CENTER); self.dest_tree.column("max_per_sec", width=100, anchor=tk.CENTER)
        self.dest_tree.tag_configure("red", background="#FF9999"); self.dest_tree.pack(fill=tk.BOTH, expand=True)
        self.dest_sort_column = None; self.dest_sort_ascending = True

    def _setup_protocols_tab(self):
        """Configure the widgets for the Protocols tab."""
        proto_columns = ("proto_port", "total", "per_second", "max_per_sec")
        self.proto_tree = ttk.Treeview(self.proto_frame, columns=proto_columns, show='headings')
        self.proto_tree.heading("proto_port", text="Protocol/Port", anchor=tk.CENTER, command=lambda: self.sort_column(self.proto_tree, "proto_port", proto_columns))
        self.proto_tree.heading("total", text="Total Packets", anchor=tk.CENTER, command=lambda: self.sort_column(self.proto_tree, "total", proto_columns))
        self.proto_tree.heading("per_second", text="Packets/Sec", anchor=tk.CENTER, command=lambda: self.sort_column(self.proto_tree, "per_second", proto_columns))
        self.proto_tree.heading("max_per_sec", text="Max P/S", anchor=tk.CENTER, command=lambda: self.sort_column(self.proto_tree, "max_per_sec", proto_columns))
        self.proto_tree.column("proto_port", width=150, anchor=tk.W); self.proto_tree.column("total", width=100, anchor=tk.CENTER)
        self.proto_tree.column("per_second", width=100, anchor=tk.CENTER); self.proto_tree.column("max_per_sec", width=100, anchor=tk.CENTER)
        self.proto_tree.tag_configure("red", background="#FF9999"); self.proto_tree.pack(fill=tk.BOTH, expand=True)
        self.proto_sort_column = None; self.proto_sort_ascending = True

    def _setup_threat_tab(self):
        """Configure the widgets for the Threat Info tab."""
        columns = ("mal_ip", "blocklists", "direction", "count")
        self.threat_tree = ttk.Treeview(self.threat_frame, columns=columns, show="headings")
        self.threat_tree.heading("mal_ip", text="Malicious IP"); self.threat_tree.heading("blocklists", text="Blocklists")
        self.threat_tree.heading("direction", text="Dir"); self.threat_tree.heading("count", text="Count")
        self.threat_tree.column("mal_ip", width=130, anchor=tk.W); self.threat_tree.column("blocklists", width=150, anchor=tk.W)
        self.threat_tree.column("direction", width=60, anchor=tk.CENTER); self.threat_tree.column("count", width=60, anchor=tk.CENTER)
        self.threat_tree.pack(fill=tk.BOTH, expand=True)

    def get_threshold(self):
        """Safely get the threshold value."""
        try:
            if callable(self.get_threshold_func): return int(self.get_threshold_func())
            else: logger.warning("get_threshold_func is not callable."); return 0
        except (ValueError, TypeError): logger.warning("Invalid threshold value obtained.", exc_info=False); return 0

    def update_gui(self):
        """Update all tabs in the detail GUI."""
        if not self.master.winfo_exists(): logger.warning(f"Detail window {self.source_ip} closed."); return

        try:
            threshold = self.get_threshold()
            flag_unsafe = self.get_flag_unsafe_func() if callable(self.get_flag_unsafe_func) else False
            flag_mal = self.get_flag_malicious_func() if callable(self.get_flag_malicious_func) else False
            now = time.time()
            prune_time_60s = now - 61

            dest_data = []
            proto_data = []

            with lock:
                if self.source_ip in ip_data:
                    ip_entry = ip_data[self.source_ip]
                    destinations = ip_entry.get("destinations", {}).copy()
                    for dst_ip, d in destinations.items():
                        timestamps_deque = d.get("timestamps", deque())
                        while timestamps_deque and timestamps_deque[0] < prune_time_60s: timestamps_deque.popleft()
                        one_sec_ago = now - 1.0
                        per_second = sum(1 for t in timestamps_deque if t >= one_sec_ago)
                        d["max_per_sec"] = max(d.get("max_per_sec", 0), per_second)
                        total = d.get("total", 0); max_ps = d["max_per_sec"]
                        dest_data.append((dst_ip, total, per_second, max_ps))

                    protocols = ip_entry.get("protocols", {}).copy()
                    for (proto, port), p in protocols.items():
                        timestamps_deque = p.get("timestamps", deque())
                        while timestamps_deque and timestamps_deque[0] < prune_time_60s: timestamps_deque.popleft()
                        one_sec_ago = now - 1.0
                        per_second = sum(1 for t in timestamps_deque if t >= one_sec_ago)
                        p["max_per_sec"] = max(p.get("max_per_sec", 0), per_second)
                        total = p.get("total", 0); max_ps = p["max_per_sec"]
                        proto_port_str = f"{proto.upper()}:{port}" if port is not None else proto.upper()
                        proto_data.append((proto_port_str, total, per_second, max_ps, proto, port))
                else:
                    logger.warning(f"Source IP {self.source_ip} not found in ip_data during GUI update.")

            # --- Update Destinations TreeView ---
            if self.dest_sort_column is not None: dest_data = self.sort_data(dest_data, self.dest_sort_column, self.dest_sort_ascending, ("dst_ip", "total", "per_second", "max_per_sec"))
            selected_item = self.dest_tree.focus(); scroll_pos = self.dest_tree.yview()
            self.dest_tree.delete(*self.dest_tree.get_children())
            for row in dest_data:
                dst_ip, total, per_sec, max_ps = row
                tags = ("red",) if max_ps > threshold else ()
                self.dest_tree.insert("", tk.END, values=row, tags=tags)
            if selected_item and self.dest_tree.exists(selected_item): self.dest_tree.focus(selected_item); self.dest_tree.selection_set(selected_item)
            self.dest_tree.yview_moveto(scroll_pos[0])

            # --- Update Protocols TreeView ---
            if self.proto_sort_column is not None: proto_data = self.sort_data(proto_data, self.proto_sort_column, self.proto_sort_ascending, ("proto_port", "total", "per_second", "max_per_sec"), extra_data_indices=[4, 5])
            selected_item_proto = self.proto_tree.focus(); scroll_pos_proto = self.proto_tree.yview()
            self.proto_tree.delete(*self.proto_tree.get_children())
            for row in proto_data:
                proto_port_str, total, per_sec, max_ps = row[:4]; proto = row[4] if len(row) > 4 else None; port = row[5] if len(row) > 5 else None
                tags = ()
                if max_ps > threshold: tags = ("red",)
                if flag_unsafe:
                    is_unsafe_port = port in UNSAFE_PORTS if port is not None else False
                    is_unsafe_proto = proto in UNSAFE_PROTOCOLS if proto is not None else False
                    if is_unsafe_port or is_unsafe_proto: tags = ("red",)
                self.proto_tree.insert("", tk.END, values=(proto_port_str, total, per_sec, max_ps), tags=tags)
            if selected_item_proto and self.proto_tree.exists(selected_item_proto): self.proto_tree.focus(selected_item_proto); self.proto_tree.selection_set(selected_item_proto)
            self.proto_tree.yview_moveto(scroll_pos_proto[0])

            # --- Update Threat Info Tab ---
            self.update_threat_info(flag_mal)

        except Exception as e:
            logger.error(f"Error updating detail GUI for {self.source_ip}: {e}", exc_info=True)
        finally:
            if self.master.winfo_exists(): self._update_scheduled = self.master.after(1000, self.update_gui)
            else: self._update_scheduled = None

    def update_threat_info(self, flag_malicious_enabled):
        """Update the threat info tab."""
        logger.debug(f"Updating Threat Info tab for {self.source_ip}. Flag enabled: {flag_malicious_enabled}")
        selected_item_threat = self.threat_tree.focus(); scroll_pos_threat = self.threat_tree.yview()
        self.threat_tree.delete(*self.threat_tree.get_children())

        if not flag_malicious_enabled:
            logger.debug("Malicious flag disabled, skipping threat info."); self.threat_tree.insert("", tk.END, values=("Flag disabled in main view", "", "", "")); return

        threat_data = []
        with lock:
            if self.source_ip not in ip_data: logger.warning(f"IP {self.source_ip} not found for threat info."); self.threat_tree.insert("", tk.END, values=(f"Data for {self.source_ip} not found", "", "", "")); return
            info = ip_data[self.source_ip]; hits_dict = info.get("malicious_hits", {})
            logger.debug(f"Malicious hits dictionary for {self.source_ip}: {hits_dict}")
            if not hits_dict: logger.debug(f"No malicious hits for {self.source_ip}."); self.threat_tree.insert("", tk.END, values=("No recorded hits found", "", "", "")); return

            for mal_ip, hit_info in hits_dict.items():
                blocklist_set = hit_info.get("blocklists", set())
                # *** FIX: Check against the imported 'blocklists' dictionary ***
                active_blocklists = {bl for bl in blocklist_set if blocklists.get(bl, False)}
                logger.debug(f"Checking hit: {self.source_ip} -> {mal_ip}. Raw lists: {blocklist_set}. Active lists: {active_blocklists}")
                if not active_blocklists: logger.debug(f"Skipping {mal_ip}, lists not active."); continue
                # Display the URL (bl) which is the key in the main blocklists dict
                blocklist_names = ', '.join(sorted(list(active_blocklists)))
                direction = hit_info.get("direction", "N/A"); count = hit_info.get("count", 0)
                threat_data.append((mal_ip, blocklist_names, direction, count))

        threat_data.sort(key=lambda x: x[0])
        if not threat_data: logger.debug(f"No hits for {self.source_ip} after filtering."); self.threat_tree.insert("", tk.END, values=("No hits from *active* lists", "", "", ""))
        else:
            logger.debug(f"Populating threat table: {len(threat_data)} entries for {self.source_ip}.")
            for row in threat_data: self.threat_tree.insert("", tk.END, values=row)

        if selected_item_threat and self.threat_tree.exists(selected_item_threat): self.threat_tree.focus(selected_item_threat); self.threat_tree.selection_set(selected_item_threat)
        self.threat_tree.yview_moveto(scroll_pos_threat[0])

    def sort_data(self, data, column, ascending, columns, extra_data_indices=None):
        """Sort list of tuples based on a column index."""
        try:
            col_index = columns.index(column)
            def sort_key(x):
                val = x[col_index]
                if column in ["total", "per_second", "max_per_sec", "count"]:
                    try: return float(val)
                    except (ValueError, TypeError): return 0.0
                elif column in ["dst_ip", "mal_ip"]:
                     try: return ipaddress.ip_address(str(val))
                     except ValueError: return ipaddress.ip_address("0.0.0.0")
                return str(val)
            return sorted(data, key=sort_key, reverse=not ascending)
        except (ValueError, IndexError, ipaddress.AddressValueError) as e:
            logger.error(f"Error sorting data by column '{column}': {e}", exc_info=True)
            return data

    def sort_column(self, tree, column, columns):
        """Handle column header click for sorting."""
        if tree == self.dest_tree: sort_col_attr, sort_asc_attr = "dest_sort_column", "dest_sort_ascending"
        elif tree == self.proto_tree: sort_col_attr, sort_asc_attr = "proto_sort_column", "proto_sort_ascending"
        else: return

        current_sort_col = getattr(self, sort_col_attr); current_sort_asc = getattr(self, sort_asc_attr)
        new_sort_asc = not current_sort_asc if column == current_sort_col else True
        setattr(self, sort_col_attr, column); setattr(self, sort_asc_attr, new_sort_asc)
        logger.debug(f"Sorting detail table by column '{column}', ascending={new_sort_asc}")
