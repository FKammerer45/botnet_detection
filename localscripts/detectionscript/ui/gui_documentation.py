# ui/gui_documentation.py
import tkinter as tk
from tkinter import ttk, font
import os
import markdown2
from PIL import Image, ImageTk
from tkhtmlview import HTMLLabel

class DocumentationWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Documentation")
        self.geometry("1600x1200")

        self.docs_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..","..", "docs"))
        self.assets_path = os.path.join(self.docs_path, "assets")

        self.paned_window = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        self.tree_frame = ttk.Frame(self.paned_window, width=200)
        self.paned_window.add(self.tree_frame, weight=1)

        self.text_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.text_frame, weight=3)

        self.tree = ttk.Treeview(self.tree_frame)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        self.html_label = HTMLLabel(self.text_frame, html=self._welcome_html())
        self.html_label.pack(fill=tk.BOTH, expand=True)
        self.html_label.fit_height()

        self.populate_tree()
        # Auto-resize after initial render
        self.after(120, self._resize_to_content)

    def _welcome_html(self):
        return """
        <h1>Botnet Detection Tool Documentation</h1>
        <p>Choose a topic from the tree on the left, or read this quick overview.</p>
        <h2>What this tool does</h2>
        <ul>
          <li>Captures traffic from selected interfaces (requires admin/root and Npcap on Windows).</li>
          <li>Detects threats: scans, rate anomalies, beaconing, DNS tunneling/DGA, unsafe protocols, blocklist hits, JA3/JA3S, ARP spoof, ICMP anomalies.</li>
          <li>Scores each IP and flags risky hosts in the UI.</li>
          <li>Lets you manage blocklists/whitelists and tweak detection thresholds.</li>
          <li>Includes a Testing Suite to generate test traffic.</li>
        </ul>
        <h2>Quick start</h2>
        <ol>
          <li>Open the app (run as admin/root for packet capture).</li>
          <li>Select interfaces when prompted.</li>
          <li>Use <b>Config</b> to enable/disable detections, adjust thresholds, manage blocklists/whitelist.</li>
          <li>Watch the main table; double-click an IP for details/tabs (threat info, beaconing, DNS, scans, scoring, etc.).</li>
          <li>Use <b>Testing Suite</b> to trigger sample attacks (port/host scan, beaconing, DGA, DNS tunneling, ICMP tunneling, rate anomaly).</li>
          <li>Temporal view shows packets/minute over time per IP.</li>
        </ol>
        <h2>Interface reference</h2>
        <ul>
          <li><b>Main table</b>: Internal/External IPs, score, totals, pkts/min, pkts/sec, max pkts/min. Rows highlight on detections/toggles.</li>
          <li><b>Detail window</b> (double-click an IP):
            <ul>
              <li>Destinations, Protocols (unsafe highlights), Threat Info (blocklists/JA3), DNS Queries, Scan Activity, Rate Anomaly, Beaconing, DNS Analysis (DGA/tunneling), Local Network (ARP/ICMP), Scoring (per-component).</li>
            </ul>
          </li>
          <li><b>Config</b>:
            <ul>
              <li>Unsafe: unsafe ports/protocols & UI flag.</li>
              <li>Scan: enable, thresholds, stealth detection, internal/external flags.</li>
              <li>Beaconing: enable, interval, tolerance, min occurrences.</li>
              <li>DNS: enable analysis, DGA entropy/length, NXDOMAIN rate/min count.</li>
              <li>Local Net: ARP/ICMP detection, thresholds, UI flag.</li>
              <li>Scoring: UI flags (malicious IP/DNS, JA3, rate) and score weights.</li>
              <li>Blocklists: enable/disable lists, add URLs (IP/DNS/JA3/JA3S), update interval, reload on save.</li>
              <li>Whitelist: managed via whitelist.txt / Whitelist Manager.</li>
            </ul>
          </li>
          <li><b>Temporal</b>: pkts/min over time, optional protocol breakdown.</li>
          <li><b>Testing Suite</b>: generate controlled traffic toward chosen targets.</li>
        </ul>
        <h2>Operational tips</h2>
        <ul>
          <li>Run as admin/root; install Npcap (WinPcap mode) on Windows.</li>
          <li>Set <code>ip_data_prune_timeout=-1</code> to retain history during long runs.</li>
          <li>Use whitelists to suppress noise from known-good services.</li>
          <li>Tune DGA entropy/length and NXDOMAIN thresholds to reduce false positives on enterprise domains.</li>
          <li>For beaconing, set interval/tolerance to match your test beacons; multicast/unspecified destinations are ignored.</li>
        </ul>
        """

    def populate_tree(self):
        for section in os.listdir(self.docs_path):
            if os.path.isdir(os.path.join(self.docs_path, section)) and section != "assets":
                section_node = self.tree.insert("", "end", text=section.replace("_", " ").title(), open=True)
                for doc in os.listdir(os.path.join(self.docs_path, section)):
                    if doc.endswith(".md"):
                        self.tree.insert(section_node, "end", text=doc.replace(".md", "").replace("_", " ").title(), values=[os.path.join(self.docs_path, section, doc)])
                    elif os.path.isdir(os.path.join(self.docs_path, section, doc)):
                        sub_section_node = self.tree.insert(section_node, "end", text=doc.replace("_", " ").title(), open=True)
                        for sub_doc in os.listdir(os.path.join(self.docs_path, section, doc)):
                            if sub_doc.endswith(".md"):
                                self.tree.insert(sub_section_node, "end", text=sub_doc.replace(".md", "").replace("_", " ").title(), values=[os.path.join(self.docs_path, section, doc, sub_doc)])

    def on_tree_select(self, event):
        selected_item = self.tree.selection()[0]
        filepath = self.tree.item(selected_item, "values")
        if filepath:
            self.display_markdown(filepath[0])

    def display_markdown(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                md_content = f.read()
            
            # The tkhtmlview library does not support local image rendering, so we'll replace image tags with a placeholder.
            import re
            md_content = re.sub(r'!\[(.*?)\]\((.*?)\)', r'[Image: \1]', md_content)

            html_content = markdown2.markdown(md_content, extras=["fenced-code-blocks", "tables", "cuddled-lists", "markdown-in-html", "smarty-pants"])
            self.html_label.set_html(html_content)
            self._resize_to_content()
        except Exception as e:
            self.html_label.set_html(f"<h1>Error</h1><p>Error loading documentation file: {e}</p>")
            self._resize_to_content()

    def _resize_to_content(self):
        """Resize the documentation window to fit current content for readability."""
        try:
            self.update_idletasks()
            req_w = self.html_label.winfo_reqwidth() + 120  # padding for tree/panes
            req_h = self.html_label.winfo_reqheight() + 80
            min_w, min_h = 900, 650
            max_w, max_h = 1400, 1000
            new_w = min(max(req_w, min_w), max_w)
            new_h = min(max(req_h, min_h), max_h)
            self.geometry(f"{int(new_w)}x{int(new_h)}")
        except Exception:
            pass
