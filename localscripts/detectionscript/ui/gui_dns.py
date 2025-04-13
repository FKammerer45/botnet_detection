# ui/gui_dns.py
import tkinter as tk
from tkinter import ttk
import logging
from collections import defaultdict
import datetime

from core.capture import ip_data, lock # Access shared data

# Get a logger for this module
logger = logging.getLogger(__name__)

class DnsMonitorWindow:
    def __init__(self, master):
        """
        Initialize the DNS Monitor window.
        """
        self.master = master
        self.master.title("DNS Monitor")
        self.master.geometry("700x500")
        logger.info("Initializing DnsMonitorWindow.")

        # --- Main Frame ---
        main_frame = tk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Left Pane: Source IPs List ---
        left_pane = ttk.LabelFrame(main_frame, text="Sources with Suspicious DNS Activity")
        left_pane.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))

        self.source_list_tree = ttk.Treeview(left_pane, columns=("ip", "count"), show="headings")
        self.source_list_tree.heading("ip", text="Source IP")
        self.source_list_tree.heading("count", text="Count")
        self.source_list_tree.column("ip", width=150, anchor=tk.W)
        self.source_list_tree.column("count", width=60, anchor=tk.CENTER)
        self.source_list_tree.pack(fill=tk.BOTH, expand=True)
        self.source_list_tree.bind("<<TreeviewSelect>>", self.on_source_select)

        # --- Right Pane: DNS Query Details ---
        right_pane = ttk.LabelFrame(main_frame, text="Suspicious Queries")
        right_pane.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.detail_tree = ttk.Treeview(right_pane, columns=("timestamp", "qname", "reason"), show="headings")
        self.detail_tree.heading("timestamp", text="Time")
        self.detail_tree.heading("qname", text="Queried Domain")
        self.detail_tree.heading("reason", text="Reason")
        self.detail_tree.column("timestamp", width=150, anchor=tk.W)
        self.detail_tree.column("qname", width=200, anchor=tk.W)
        self.detail_tree.column("reason", width=100, anchor=tk.W)
        # Add scrollbar
        scrollbar = ttk.Scrollbar(right_pane, orient="vertical", command=self.detail_tree.yview)
        self.detail_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.detail_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # --- Update Loop ---
        self._update_scheduled = None
        self.update_gui()

        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Handle window closing."""
        logger.info("Closing DNS Monitor window.")
        if self._update_scheduled:
            try:
                self.master.after_cancel(self._update_scheduled)
            except tk.TclError: pass
            self._update_scheduled = None
        try:
            self.master.destroy()
        except tk.TclError: pass

    def on_source_select(self, event):
        """Update detail view when a source IP is selected."""
        selected_item = self.source_list_tree.focus()
        if not selected_item:
            return
        try:
            selected_ip = self.source_list_tree.item(selected_item)["values"][0]
            self.update_detail_view(selected_ip)
        except (IndexError, KeyError):
             logger.warning("Could not get IP from selected item in source list.")
             self.update_detail_view(None) # Clear detail view

    def update_detail_view(self, source_ip):
        """Populate the detail Treeview for the selected source IP."""
        self.detail_tree.delete(*self.detail_tree.get_children()) # Clear previous details

        if not source_ip:
            return

        logger.debug(f"Updating DNS detail view for source IP: {source_ip}")
        with lock:
            if source_ip in ip_data:
                suspicious_dns_list = ip_data[source_ip].get("suspicious_dns", [])
                # Sort by timestamp descending (most recent first)
                suspicious_dns_list.sort(key=lambda x: x.get("timestamp", 0), reverse=True)

                for item in suspicious_dns_list:
                    ts = item.get("timestamp", 0)
                    qname = item.get("qname", "N/A")
                    reason = item.get("reason", "N/A")
                    time_str = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else "N/A"
                    self.detail_tree.insert("", tk.END, values=(time_str, qname, reason))
            else:
                logger.warning(f"Source IP {source_ip} not found in ip_data when updating DNS detail view.")


    def update_gui(self):
        """Periodically update the list of source IPs with suspicious DNS activity."""
        if not self.master.winfo_exists():
            logger.warning("DNS Monitor window closed unexpectedly during update.")
            return

        logger.debug("Updating DNS Monitor source IP list.")
        sources = {} # ip -> count
        with lock:
            for ip, data in ip_data.items():
                suspicious_list = data.get("suspicious_dns", [])
                if suspicious_list:
                    sources[ip] = len(suspicious_list) # Count number of suspicious events

        # --- Update Source List TreeView ---
        selected_item = self.source_list_tree.focus()
        selected_ip = None
        if selected_item:
             try:
                 selected_ip = self.source_list_tree.item(selected_item)["values"][0]
             except (IndexError, KeyError):
                 selected_ip = None

        self.source_list_tree.delete(*self.source_list_tree.get_children())
        sorted_sources = sorted(sources.items(), key=lambda item: item[1], reverse=True) # Sort by count desc

        new_selection_id = None
        for ip, count in sorted_sources:
            item_id = self.source_list_tree.insert("", tk.END, values=(ip, count))
            if ip == selected_ip:
                 new_selection_id = item_id # Store the new item ID if it matches old selection

        # Restore selection if possible
        if new_selection_id:
             self.source_list_tree.focus(new_selection_id)
             self.source_list_tree.selection_set(new_selection_id)
        elif selected_ip: # If previous selection is gone, clear detail view
             self.update_detail_view(None)


        # Schedule next update
        if self.master.winfo_exists():
            self._update_scheduled = self.master.after(5000, self.update_gui) # Update every 5 seconds
        else:
            self._update_scheduled = None
