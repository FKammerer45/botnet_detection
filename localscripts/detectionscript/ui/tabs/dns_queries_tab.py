# ui/tabs/dns_queries_tab.py
import tkinter as tk
from tkinter import ttk
import time

class DnsQueriesTab:
    def __init__(self, notebook, data_manager, source_ip):
        self.frame = ttk.Frame(notebook)
        self.data_manager = data_manager
        self.source_ip = source_ip

        explanation = "Shows all suspicious DNS queries made by this host that were found in the blocklists."
        ttk.Label(self.frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        columns = ("timestamp", "qname", "reason")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings")
        headers = {"timestamp": "Timestamp", "qname": "Queried Domain", "reason": "Reason"}
        widths = {"timestamp": 150, "qname": 250, "reason": 150}
        
        for col in columns:
            self.tree.heading(col, text=headers[col], anchor=tk.W)
            self.tree.column(col, width=widths[col], anchor=tk.W)
            
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        notebook.add(self.frame, text="DNS Queries")

    def update_tab(self, ip_snapshot):
        self.tree.delete(*self.tree.get_children())
        if not ip_snapshot:
            self.tree.insert("", tk.END, values=("(Source IP data unavailable)", "", ""))
            return

        dns_queries_data = []
        if ip_snapshot:
            suspicious_dns_list = ip_snapshot.get("suspicious_dns", [])
            for query_info in suspicious_dns_list:
                ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(query_info.get("timestamp", 0)))
                qname = query_info.get("qname", "N/A")
                reason = query_info.get("reason", "N/A")
                dns_queries_data.append((ts, qname, reason))
        
        if not dns_queries_data:
            self.tree.insert("", tk.END, values=("No suspicious DNS queries recorded", "", ""))
        else:
            dns_queries_data.sort(key=lambda x: x[0], reverse=True)
            for row in dns_queries_data:
                self.tree.insert("", tk.END, values=row)
