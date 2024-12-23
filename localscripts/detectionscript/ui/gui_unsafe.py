# gui_unsafe_protocols.py
import tkinter as tk
from tkinter import ttk
# We'll import the UNSAFE_PORTS set from your main or capture module
# If you keep it in gui_main, do: from gui_main import UNSAFE_PORTS
# If you keep it in capture.py, do: from capture import UNSAFE_PORTS
# For this example, let's assume it's in gui_main:
from config.globals import UNSAFE_PORTS, UNSAFE_PROTOCOLS

class UnsafeConfigWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Configure Unsafe Ports & Protocols")

        desc_label_text = (
            "Below are the currently flagged 'unsafe' ports and protocols.\n"
            "Add or remove entries as needed.\n"
        )

        desc_frame = tk.Frame(self.master)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)

        desc_label = tk.Label(desc_frame, text=desc_label_text, justify=tk.LEFT, anchor="w")
        desc_label.pack(anchor="w")

        # Table frame
        table_frame = tk.Frame(self.master)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # We'll have two TreeViews: one for ports, one for protocols
        self.ports_tree = ttk.Treeview(table_frame, columns=("port",), show='headings', height=6)
        self.ports_tree.heading("port", text="Unsafe Port", anchor=tk.CENTER)
        self.ports_tree.column("port", width=100, anchor=tk.CENTER)
        self.ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.protocols_tree = ttk.Treeview(table_frame, columns=("proto",), show='headings', height=6)
        self.protocols_tree.heading("proto", text="Unsafe Protocol", anchor=tk.CENTER)
        self.protocols_tree.column("proto", width=120, anchor=tk.CENTER)
        self.protocols_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.refresh_trees()

        # Add & remove ports
        port_frame = tk.Frame(self.master)
        port_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(port_frame, text="Port:").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(port_frame, width=5)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        add_port_button = tk.Button(port_frame, text="Add Port", command=self.add_port)
        add_port_button.pack(side=tk.LEFT, padx=5)
        remove_port_button = tk.Button(port_frame, text="Remove Port", command=self.remove_selected_port)
        remove_port_button.pack(side=tk.LEFT, padx=5)

        # Add & remove protocols
        proto_frame = tk.Frame(self.master)
        proto_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(proto_frame, text="Protocol:").pack(side=tk.LEFT)
        self.proto_entry = tk.Entry(proto_frame, width=8)
        self.proto_entry.pack(side=tk.LEFT, padx=5)
        add_proto_button = tk.Button(proto_frame, text="Add Protocol", command=self.add_protocol)
        add_proto_button.pack(side=tk.LEFT, padx=5)
        remove_proto_button = tk.Button(proto_frame, text="Remove Protocol", command=self.remove_selected_protocol)
        remove_proto_button.pack(side=tk.LEFT, padx=5)

    def refresh_trees(self):
        """Reload the ports and protocols from the global sets."""
        for row_id in self.ports_tree.get_children():
            self.ports_tree.delete(row_id)
        for port in sorted(UNSAFE_PORTS):
            self.ports_tree.insert("", tk.END, values=(port,))

        for row_id in self.protocols_tree.get_children():
            self.protocols_tree.delete(row_id)
        for proto in sorted(UNSAFE_PROTOCOLS):
            self.protocols_tree.insert("", tk.END, values=(proto,))

    def add_port(self):
        """Add a user-specified port number."""
        port_str = self.port_entry.get().strip()
        if not port_str.isdigit():
            return
        port_val = int(port_str)
        UNSAFE_PORTS.add(port_val)
        self.refresh_trees()
        # Optionally trigger main GUI update if you have a reference

    def remove_selected_port(self):
        """Remove selected ports from the TreeView + UNSAFE_PORTS."""
        selection = self.ports_tree.selection()
        if not selection:
            return
        for sel in selection:
            port_val = self.ports_tree.item(sel)["values"][0]
            if port_val in UNSAFE_PORTS:
                UNSAFE_PORTS.remove(port_val)
        self.refresh_trees()

    def add_protocol(self):
        """Add a user-specified protocol string."""
        p = self.proto_entry.get().strip().lower()
        if not p:
            return
        UNSAFE_PROTOCOLS.add(p)
        self.refresh_trees()

    def remove_selected_protocol(self):
        """Remove selected protocols from the TreeView + UNSAFE_PROTOCOLS."""
        selection = self.protocols_tree.selection()
        if not selection:
            return
        for sel in selection:
            proto_val = self.protocols_tree.item(sel)["values"][0]
            if proto_val in UNSAFE_PROTOCOLS:
                UNSAFE_PROTOCOLS.remove(proto_val)
        self.refresh_trees()

