# ui/gui_whitelist_manager.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
# Import the whitelist function
from core.whitelist_manager import get_whitelist

logger = logging.getLogger(__name__)
whitelist = get_whitelist() # Get the singleton instance

class WhitelistManagerWindow:
    def __init__(self, master):
        """Initialize the Whitelist Manager window."""
        self.master = master
        self.master.title("Whitelist Manager")
        self.master.geometry("500x400")
        logger.info("Initializing WhitelistManagerWindow.")

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Description
        desc_text = f"Entries loaded from '{whitelist.filepath}'.\nIPs/Domains in this list will not be flagged.\n(Modify the file directly to add/remove entries)."
        ttk.Label(main_frame, text=desc_text, wraplength=480, justify=tk.LEFT).pack(pady=(0, 10), anchor=tk.W)

        # Paned Window for IPs and Domains
        paned_window = tk.PanedWindow(main_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        paned_window.pack(fill=tk.BOTH, expand=True, pady=5)

        # --- IP/Network Whitelist Section ---
        ip_frame = ttk.LabelFrame(paned_window, text="Whitelisted IPs/Networks")
        paned_window.add(ip_frame) # Removed weight
        self._setup_ip_list(ip_frame)

        # --- Domain Whitelist Section ---
        domain_frame = ttk.LabelFrame(paned_window, text="Whitelisted Domains")
        paned_window.add(domain_frame) # Removed weight
        self._setup_domain_list(domain_frame)

        # --- Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        reload_button = ttk.Button(button_frame, text="Reload Whitelist File", command=self.reload_and_refresh)
        reload_button.pack(side=tk.LEFT, padx=5)

        close_button = ttk.Button(button_frame, text="Close", command=self.master.destroy)
        close_button.pack(side=tk.LEFT, padx=5)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("WhitelistManagerWindow closed."), self.master.destroy()))

    def _setup_ip_list(self, parent_frame):
        """Setup the Treeview for IPs/Networks."""
        tree_frame = tk.Frame(parent_frame); tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.ip_tree = ttk.Treeview(tree_frame, columns=("entry",), show="headings")
        self.ip_tree.heading("entry", text="IP Address / CIDR"); self.ip_tree.column("entry", anchor=tk.W)
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.ip_tree.yview); self.ip_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y); self.ip_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.refresh_ip_list()

    def _setup_domain_list(self, parent_frame):
        """Setup the Treeview for Domains."""
        tree_frame = tk.Frame(parent_frame); tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.domain_tree = ttk.Treeview(tree_frame, columns=("entry",), show="headings")
        self.domain_tree.heading("entry", text="Domain Name"); self.domain_tree.column("entry", anchor=tk.W)
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.domain_tree.yview); self.domain_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y); self.domain_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.refresh_domain_list()

    def refresh_ip_list(self):
        """Reload data into the IP Treeview."""
        self.ip_tree.delete(*self.ip_tree.get_children())
        # *** Use the whitelist instance ***
        sorted_networks = sorted([str(net) for net in whitelist.ip_networks])
        for entry in sorted_networks: self.ip_tree.insert("", tk.END, values=(entry,))

    def refresh_domain_list(self):
        """Reload data into the Domain Treeview."""
        self.domain_tree.delete(*self.domain_tree.get_children())
        # *** Use the whitelist instance ***
        sorted_domains = sorted(list(whitelist.domains))
        for entry in sorted_domains: self.domain_tree.insert("", tk.END, values=(entry,))

    def reload_and_refresh(self):
        """Reload whitelist from file and refresh GUI lists."""
        logger.info("Reloading whitelist file...")
        try:
            # *** Use the whitelist instance ***
            whitelist.load_whitelist() # Reload data
            self.refresh_ip_list(); self.refresh_domain_list()
            messagebox.showinfo("Reloaded", "Whitelist reloaded successfully.", parent=self.master)
        except Exception as e:
            logger.error(f"Failed to reload whitelist: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to reload whitelist:\n{e}", parent=self.master)
