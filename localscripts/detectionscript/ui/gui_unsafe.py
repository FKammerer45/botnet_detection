# gui_unsafe.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging # Import logging module
from config.globals import UNSAFE_PORTS, UNSAFE_PROTOCOLS

# Get a logger for this module
logger = logging.getLogger(__name__)

class UnsafeConfigWindow:
    def __init__(self, master):
        """
        Initialize the configuration window for unsafe ports and protocols.

        Args:
            master: The parent Tkinter window.
        """
        self.master = master
        self.master.title("Configure Unsafe Ports & Protocols")
        self.master.geometry("450x400") # Adjusted size
        logger.info("Initializing UnsafeConfigWindow.")

        # --- Description ---
        desc_label_text = (
            "Manage ports and protocols flagged as 'unsafe'.\n"
            "These flags affect highlighting in the main and detail views."
        )
        desc_frame = tk.Frame(self.master)
        desc_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        desc_label = tk.Label(desc_frame, text=desc_label_text, justify=tk.LEFT, anchor="w")
        desc_label.pack(anchor="w")

        # --- Paned Window for Resizable Sections ---
        paned_window = tk.PanedWindow(self.master, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # --- Ports Section ---
        ports_frame = ttk.LabelFrame(paned_window, text="Unsafe Ports")
        # *** FIX: Removed weight=1 ***
        paned_window.add(ports_frame)
        self._setup_ports_section(ports_frame)

        # --- Protocols Section ---
        protocols_frame = ttk.LabelFrame(paned_window, text="Unsafe Protocols")
        # *** FIX: Removed weight=1 ***
        paned_window.add(protocols_frame)
        self._setup_protocols_section(protocols_frame)

        # Log window closure
        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("UnsafeConfigWindow closed."), self.master.destroy()))

    def _setup_ports_section(self, parent_frame):
        """Configure widgets for the Unsafe Ports section."""
        # Treeview for ports
        tree_frame = tk.Frame(parent_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.ports_tree = ttk.Treeview(tree_frame, columns=("port",), show='headings')
        self.ports_tree.heading("port", text="Port Number", anchor=tk.CENTER)
        self.ports_tree.column("port", width=100, anchor=tk.CENTER)
        port_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.ports_tree.yview)
        self.ports_tree.configure(yscrollcommand=port_scrollbar.set)
        port_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.refresh_ports_tree() # Initial population

        # Add/Remove controls for ports
        control_frame = tk.Frame(parent_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        tk.Label(control_frame, text="Port:").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(control_frame, width=8)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        add_port_button = tk.Button(control_frame, text="Add", command=self.add_port)
        add_port_button.pack(side=tk.LEFT, padx=(0, 5))
        remove_port_button = tk.Button(control_frame, text="Remove Sel.", command=self.remove_selected_port)
        remove_port_button.pack(side=tk.LEFT)

    def _setup_protocols_section(self, parent_frame):
        """Configure widgets for the Unsafe Protocols section."""
        # Treeview for protocols
        tree_frame = tk.Frame(parent_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.protocols_tree = ttk.Treeview(tree_frame, columns=("proto",), show='headings')
        self.protocols_tree.heading("proto", text="Protocol Name", anchor=tk.CENTER)
        self.protocols_tree.column("proto", width=120, anchor=tk.W) # Anchor West
        proto_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.protocols_tree.yview)
        self.protocols_tree.configure(yscrollcommand=proto_scrollbar.set)
        proto_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.protocols_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.refresh_protocols_tree() # Initial population

        # Add/Remove controls for protocols
        control_frame = tk.Frame(parent_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        tk.Label(control_frame, text="Protocol:").pack(side=tk.LEFT)
        self.proto_entry = tk.Entry(control_frame, width=10)
        self.proto_entry.pack(side=tk.LEFT, padx=5)
        add_proto_button = tk.Button(control_frame, text="Add", command=self.add_protocol)
        add_proto_button.pack(side=tk.LEFT, padx=(0, 5))
        remove_proto_button = tk.Button(control_frame, text="Remove Sel.", command=self.remove_selected_protocol)
        remove_proto_button.pack(side=tk.LEFT)

    def refresh_ports_tree(self):
        """Reload the ports from the global UNSAFE_PORTS set."""
        logger.debug("Refreshing unsafe ports tree.")
        self.ports_tree.delete(*self.ports_tree.get_children())
        try:
            # Sort numerically for display
            for port in sorted(list(UNSAFE_PORTS)):
                self.ports_tree.insert("", tk.END, values=(port,))
        except Exception as e:
            logger.error(f"Error refreshing ports tree: {e}", exc_info=True)

    def refresh_protocols_tree(self):
        """Reload the protocols from the global UNSAFE_PROTOCOLS set."""
        logger.debug("Refreshing unsafe protocols tree.")
        self.protocols_tree.delete(*self.protocols_tree.get_children())
        try:
            # Sort alphabetically for display
            for proto in sorted(list(UNSAFE_PROTOCOLS)):
                self.protocols_tree.insert("", tk.END, values=(proto,))
        except Exception as e:
            logger.error(f"Error refreshing protocols tree: {e}", exc_info=True)

    def add_port(self):
        """Add a user-specified port number to the UNSAFE_PORTS set."""
        port_str = self.port_entry.get().strip()
        if not port_str.isdigit():
            logger.warning(f"Invalid port entered: '{port_str}'. Must be numeric.")
            messagebox.showwarning("Invalid Input", "Port must be a number.")
            return
        try:
            port_val = int(port_str)
            if 0 <= port_val <= 65535:
                if port_val in UNSAFE_PORTS:
                     logger.info(f"Port {port_val} is already in the unsafe list.")
                else:
                     logger.info(f"Adding unsafe port: {port_val}")
                     UNSAFE_PORTS.add(port_val)
                     self.refresh_ports_tree()
                     self.port_entry.delete(0, tk.END) # Clear entry after adding
            else:
                logger.warning(f"Invalid port range: {port_val}. Must be 0-65535.")
                messagebox.showwarning("Invalid Input", "Port must be between 0 and 65535.")
        except ValueError: # Should be caught by isdigit, but as safety
            logger.error(f"Could not convert port '{port_str}' to integer.", exc_info=True)
            messagebox.showerror("Error", "Invalid port number entered.")

    def remove_selected_port(self):
        """Remove selected ports from the TreeView and UNSAFE_PORTS set."""
        selection = self.ports_tree.selection()
        if not selection:
            logger.debug("Remove port called but no selection.")
            messagebox.showinfo("No Selection", "Please select a port to remove.")
            return

        removed_count = 0
        for sel_id in selection:
            try:
                port_val_str = self.ports_tree.item(sel_id)["values"][0]
                port_val = int(port_val_str) # Ports are stored as ints in the set
                if port_val in UNSAFE_PORTS:
                    logger.info(f"Removing unsafe port: {port_val}")
                    UNSAFE_PORTS.remove(port_val)
                    removed_count += 1
                else:
                     logger.warning(f"Port {port_val} from selection not found in UNSAFE_PORTS set.")
            except (IndexError, ValueError) as e:
                logger.error(f"Error processing selection {sel_id} for port removal: {e}", exc_info=True)

        if removed_count > 0:
            self.refresh_ports_tree()
        else:
             logger.warning("No matching ports found in the set for removal based on selection.")


    def add_protocol(self):
        """Add a user-specified protocol string to the UNSAFE_PROTOCOLS set."""
        proto_str = self.proto_entry.get().strip().lower() # Convert to lower case
        if not proto_str:
            logger.warning("Attempted to add empty protocol string.")
            messagebox.showwarning("Invalid Input", "Protocol name cannot be empty.")
            return
        # Basic validation: allow letters, numbers, hyphen (e.g., for 'ipsec-esp')
        if not all(c.isalnum() or c == '-' for c in proto_str):
             logger.warning(f"Invalid characters in protocol name: '{proto_str}'")
             messagebox.showwarning("Invalid Input", "Protocol name can only contain letters, numbers, and hyphens.")
             return

        if proto_str in UNSAFE_PROTOCOLS:
             logger.info(f"Protocol '{proto_str}' is already in the unsafe list.")
        else:
             logger.info(f"Adding unsafe protocol: {proto_str}")
             UNSAFE_PROTOCOLS.add(proto_str)
             self.refresh_protocols_tree()
             self.proto_entry.delete(0, tk.END) # Clear entry after adding

    def remove_selected_protocol(self):
        """Remove selected protocols from the TreeView and UNSAFE_PROTOCOLS set."""
        selection = self.protocols_tree.selection()
        if not selection:
            logger.debug("Remove protocol called but no selection.")
            messagebox.showinfo("No Selection", "Please select a protocol to remove.")
            return

        removed_count = 0
        for sel_id in selection:
            try:
                proto_val = self.protocols_tree.item(sel_id)["values"][0]
                # Protocols are stored as strings (already lowercased on add)
                if proto_val in UNSAFE_PROTOCOLS:
                    logger.info(f"Removing unsafe protocol: {proto_val}")
                    UNSAFE_PROTOCOLS.remove(proto_val)
                    removed_count += 1
                else:
                    logger.warning(f"Protocol '{proto_val}' from selection not found in UNSAFE_PROTOCOLS set.")
            except (IndexError, ValueError) as e: # ValueError unlikely here but safe
                logger.error(f"Error processing selection {sel_id} for protocol removal: {e}", exc_info=True)

        if removed_count > 0:
            self.refresh_protocols_tree()
        else:
            logger.warning("No matching protocols found in the set for removal based on selection.")

