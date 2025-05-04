# gui_unsafe.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
# Import config manager
from core.config_manager import config

logger = logging.getLogger(__name__)

class UnsafeConfigWindow:
    def __init__(self, master):
        """Initialize the configuration window using config manager."""
        self.master = master
        self.master.title("Configure Unsafe Ports & Protocols")
        self.master.geometry("450x400")
        logger.info("Initializing UnsafeConfigWindow.")

        # --- Description ---
        desc_text = ("Manage ports/protocols flagged as 'unsafe' (affects highlighting).\n"
                     "Changes are saved to config.ini.")
        ttk.Label(self.master, text=desc_text, padding=10, justify=tk.LEFT).pack(fill=tk.X)

        # --- Paned Window ---
        paned_window = tk.PanedWindow(self.master, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # --- Ports Section ---
        ports_frame = ttk.LabelFrame(paned_window, text="Unsafe Ports")
        paned_window.add(ports_frame); self._setup_ports_section(ports_frame)

        # --- Protocols Section ---
        protocols_frame = ttk.LabelFrame(paned_window, text="Unsafe Protocols")
        paned_window.add(protocols_frame); self._setup_protocols_section(protocols_frame)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("UnsafeConfigWindow closed."), self.master.destroy()))

    def _setup_ports_section(self, parent_frame):
        """Configure widgets for the Unsafe Ports section."""
        tree_frame = tk.Frame(parent_frame); tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.ports_tree = ttk.Treeview(tree_frame, columns=("port",), show='headings')
        self.ports_tree.heading("port", text="Port Number"); self.ports_tree.column("port", width=100, anchor=tk.CENTER)
        port_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.ports_tree.yview); self.ports_tree.configure(yscrollcommand=port_scrollbar.set)
        port_scrollbar.pack(side=tk.RIGHT, fill=tk.Y); self.ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.refresh_ports_tree()

        control_frame = tk.Frame(parent_frame); control_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        ttk.Label(control_frame, text="Port:").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(control_frame, width=8); self.port_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Add", command=self.add_port).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Remove Sel.", command=self.remove_selected_port).pack(side=tk.LEFT)

    def _setup_protocols_section(self, parent_frame):
        """Configure widgets for the Unsafe Protocols section."""
        tree_frame = tk.Frame(parent_frame); tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.protocols_tree = ttk.Treeview(tree_frame, columns=("proto",), show='headings')
        self.protocols_tree.heading("proto", text="Protocol Name"); self.protocols_tree.column("proto", width=120, anchor=tk.W)
        proto_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.protocols_tree.yview); self.protocols_tree.configure(yscrollcommand=proto_scrollbar.set)
        proto_scrollbar.pack(side=tk.RIGHT, fill=tk.Y); self.protocols_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.refresh_protocols_tree()

        control_frame = tk.Frame(parent_frame); control_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        ttk.Label(control_frame, text="Protocol:").pack(side=tk.LEFT)
        self.proto_entry = ttk.Entry(control_frame, width=10); self.proto_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Add", command=self.add_protocol).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Remove Sel.", command=self.remove_selected_protocol).pack(side=tk.LEFT)

    def refresh_ports_tree(self):
        """Reload the ports from the config object."""
        logger.debug("Refreshing unsafe ports tree from config.")
        self.ports_tree.delete(*self.ports_tree.get_children())
        try:
            # *** Read from config ***
            for port in sorted(list(config.unsafe_ports)):
                self.ports_tree.insert("", tk.END, values=(port,))
        except Exception as e: logger.error(f"Error refreshing ports tree: {e}", exc_info=True)

    def refresh_protocols_tree(self):
        """Reload the protocols from the config object."""
        logger.debug("Refreshing unsafe protocols tree from config.")
        self.protocols_tree.delete(*self.protocols_tree.get_children())
        try:
            # *** Read from config ***
            for proto in sorted(list(config.unsafe_protocols)):
                self.protocols_tree.insert("", tk.END, values=(proto,))
        except Exception as e: logger.error(f"Error refreshing protocols tree: {e}", exc_info=True)

    def add_port(self):
        """Add port to config object, save config, refresh tree."""
        port_str = self.port_entry.get().strip()
        if not port_str.isdigit(): messagebox.showwarning("Invalid Input", "Port must be a number.", parent=self.master); return
        try:
            port_val = int(port_str)
            if 0 <= port_val <= 65535:
                # *** Modify config object ***
                if port_val not in config.unsafe_ports:
                     logger.info(f"Adding unsafe port: {port_val}")
                     config.unsafe_ports.add(port_val)
                     config.save_config() # Save changes to file
                     self.refresh_ports_tree()
                     self.port_entry.delete(0, tk.END)
                else: logger.info(f"Port {port_val} already in unsafe list.")
            else: messagebox.showwarning("Invalid Input", "Port must be 0-65535.", parent=self.master)
        except ValueError: messagebox.showerror("Error", "Invalid port number.", parent=self.master)
        except Exception as e: logger.error(f"Error adding port: {e}", exc_info=True); messagebox.showerror("Error", f"Could not add port:\n{e}", parent=self.master)

    def remove_selected_port(self):
        """Remove selected ports from config object, save config, refresh tree."""
        selection = self.ports_tree.selection()
        if not selection: messagebox.showinfo("No Selection", "Select port(s) to remove.", parent=self.master); return
        removed_count = 0
        ports_to_remove = set()
        for sel_id in selection:
            try: ports_to_remove.add(int(self.ports_tree.item(sel_id)["values"][0]))
            except (IndexError, ValueError): logger.warning(f"Could not parse port from selection {sel_id}")
        # *** Modify config object ***
        original_len = len(config.unsafe_ports)
        config.unsafe_ports.difference_update(ports_to_remove) # Remove the ports
        removed_count = original_len - len(config.unsafe_ports)

        if removed_count > 0:
            logger.info(f"Removing {removed_count} unsafe port(s): {ports_to_remove}")
            config.save_config() # Save changes to file
            self.refresh_ports_tree()
        else: logger.warning("No matching ports found in config set for removal.")

    def add_protocol(self):
        """Add protocol to config object, save config, refresh tree."""
        proto_str = self.proto_entry.get().strip().lower()
        if not proto_str: messagebox.showwarning("Invalid Input", "Protocol name cannot be empty.", parent=self.master); return
        if not all(c.isalnum() or c == '-' for c in proto_str): messagebox.showwarning("Invalid Input", "Use letters, numbers, hyphens.", parent=self.master); return
        # *** Modify config object ***
        if proto_str not in config.unsafe_protocols:
             logger.info(f"Adding unsafe protocol: {proto_str}")
             config.unsafe_protocols.add(proto_str)
             config.save_config() # Save changes to file
             self.refresh_protocols_tree()
             self.proto_entry.delete(0, tk.END)
        else: logger.info(f"Protocol '{proto_str}' already in unsafe list.")

    def remove_selected_protocol(self):
        """Remove selected protocols from config object, save config, refresh tree."""
        selection = self.protocols_tree.selection()
        if not selection: messagebox.showinfo("No Selection", "Select protocol(s) to remove.", parent=self.master); return
        removed_count = 0
        protos_to_remove = set()
        for sel_id in selection:
            try: protos_to_remove.add(self.protocols_tree.item(sel_id)["values"][0])
            except IndexError: logger.warning(f"Could not parse protocol from selection {sel_id}")
        # *** Modify config object ***
        original_len = len(config.unsafe_protocols)
        config.unsafe_protocols.difference_update(protos_to_remove)
        removed_count = original_len - len(config.unsafe_protocols)

        if removed_count > 0:
            logger.info(f"Removing {removed_count} unsafe protocol(s): {protos_to_remove}")
            config.save_config() # Save changes to file
            self.refresh_protocols_tree()
        else: logger.warning("No matching protocols found in config set for removal.")

