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
        self.master.geometry("600x550") # Adjusted size
        logger.info("Initializing WhitelistManagerWindow.")

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Description
        desc_text = f"Manage entries in '{whitelist.filepath}'.\nIPs/Networks/Domains in this list will not be flagged by detection rules."
        ttk.Label(main_frame, text=desc_text, wraplength=580, justify=tk.LEFT).pack(pady=(0, 10), anchor=tk.W)

        # --- Add Entry Section ---
        add_entry_frame = ttk.LabelFrame(main_frame, text="Add New Whitelist Entry", padding="5")
        add_entry_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(add_entry_frame, text="Entry (IP, CIDR, or Domain):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.new_entry_var = tk.StringVar()
        new_entry_widget = ttk.Entry(add_entry_frame, textvariable=self.new_entry_var, width=50)
        new_entry_widget.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        add_button = ttk.Button(add_entry_frame, text="Add Entry", command=self.add_whitelist_entry)
        add_button.grid(row=0, column=2, padx=5, pady=5)
        add_entry_frame.columnconfigure(1, weight=1)


        # Paned Window for IPs and Domains
        paned_window = tk.PanedWindow(main_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        paned_window.pack(fill=tk.BOTH, expand=True, pady=5)

        # --- IP/Network Whitelist Section ---
        ip_frame = ttk.LabelFrame(paned_window, text="Whitelisted IPs/Networks")
        paned_window.add(ip_frame) # Removed weight=1
        self._setup_ip_list_ui(ip_frame) # Renamed for clarity

        # --- Domain Whitelist Section ---
        domain_frame = ttk.LabelFrame(paned_window, text="Whitelisted Domains")
        paned_window.add(domain_frame) # Removed weight=1
        self._setup_domain_list_ui(domain_frame) # Renamed for clarity

        # --- Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10, fill=tk.X) # Fill X for better button placement

        save_button = ttk.Button(button_frame, text="Save Changes to File", command=self.save_changes)
        save_button.pack(side=tk.LEFT, padx=5)
        
        # reload_button = ttk.Button(button_frame, text="Reload From File", command=self.reload_and_refresh)
        # reload_button.pack(side=tk.LEFT, padx=5) # Reload is implicit on open, explicit save is key

        close_button = ttk.Button(button_frame, text="Close", command=self.master.destroy)
        close_button.pack(side=tk.RIGHT, padx=5) # Move close to right

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("WhitelistManagerWindow closed."), self.master.destroy()))

    def _setup_ip_list_ui(self, parent_frame):
        """Setup the UI for IPs/Networks, including list and remove button."""
        logger.debug("Entering _setup_ip_list_ui.")
        try:
            list_area_frame = ttk.Frame(parent_frame)
            list_area_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            logger.debug("list_area_frame created and packed.")

            self.ip_tree = ttk.Treeview(list_area_frame, columns=("entry",), show="headings", height=5)
            logger.debug(f"self.ip_tree created: {self.ip_tree}")
            self.ip_tree.heading("entry", text="IP Address / CIDR")
            self.ip_tree.column("entry", anchor=tk.W)
            logger.debug("ip_tree headings and columns configured.")

            scrollbar = ttk.Scrollbar(list_area_frame, orient="vertical", command=self.ip_tree.yview)
            self.ip_tree.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            self.ip_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            logger.debug("ip_tree and scrollbar packed.")
            
            remove_ip_button = ttk.Button(parent_frame, text="Remove Selected IP/Network", command=self.remove_selected_ip)
            remove_ip_button.pack(pady=5)
            logger.debug("Remove IP button created and packed.")

            self.refresh_ip_list()
            logger.debug("Exiting _setup_ip_list_ui successfully.")
        except Exception as e:
            logger.error(f"Error in _setup_ip_list_ui: {e}", exc_info=True)


    def _setup_domain_list_ui(self, parent_frame):
        """Setup the UI for Domains, including list and remove button."""
        logger.debug("Entering _setup_domain_list_ui.")
        try:
            list_area_frame = ttk.Frame(parent_frame)
            list_area_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            logger.debug("domain list_area_frame created and packed.")

            self.domain_tree = ttk.Treeview(list_area_frame, columns=("entry",), show="headings", height=5)
            logger.debug(f"self.domain_tree created: {self.domain_tree}")
            self.domain_tree.heading("entry", text="Domain Name")
            self.domain_tree.column("entry", anchor=tk.W)
            logger.debug("domain_tree headings and columns configured.")

            scrollbar = ttk.Scrollbar(list_area_frame, orient="vertical", command=self.domain_tree.yview)
            self.domain_tree.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            self.domain_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            logger.debug("domain_tree and scrollbar packed.")

            remove_domain_button = ttk.Button(parent_frame, text="Remove Selected Domain", command=self.remove_selected_domain)
            remove_domain_button.pack(pady=5)
            logger.debug("Remove Domain button created and packed.")

            self.refresh_domain_list()
            logger.debug("Exiting _setup_domain_list_ui successfully.")
        except Exception as e:
            logger.error(f"Error in _setup_domain_list_ui: {e}", exc_info=True)


    def refresh_ip_list(self):
        """Reload data into the IP Treeview."""
        logger.debug(f"Attempting to refresh IP list. hasattr(self, 'ip_tree'): {hasattr(self, 'ip_tree')}")
        if hasattr(self, 'ip_tree'):
            logger.debug(f"Inside refresh_ip_list. Current whitelist IP Networks: {whitelist.ip_networks}")
            try:
                self.ip_tree.delete(*self.ip_tree.get_children())
                sorted_networks = sorted([str(net) for net in whitelist.ip_networks])
                logger.debug(f"IPs to display: {sorted_networks}")
                for entry in sorted_networks:
                    self.ip_tree.insert("", tk.END, values=(entry,))
                logger.debug("Finished populating IP tree.")
            except Exception as e:
                logger.error(f"Error populating IP Treeview: {e}", exc_info=True)
        else:
            logger.warning("refresh_ip_list called but ip_tree does not exist.")

    def refresh_domain_list(self):
        """Reload data into the Domain Treeview."""
        logger.debug(f"Attempting to refresh Domain list. hasattr(self, 'domain_tree'): {hasattr(self, 'domain_tree')}")
        if hasattr(self, 'domain_tree'):
            logger.debug(f"Inside refresh_domain_list. Current whitelist Domains: {whitelist.domains}")
            try:
                self.domain_tree.delete(*self.domain_tree.get_children())
                sorted_domains = sorted(list(whitelist.domains))
                logger.debug(f"Domains to display: {sorted_domains}")
                for entry in sorted_domains:
                    self.domain_tree.insert("", tk.END, values=(entry,))
                logger.debug("Finished populating Domain tree.")
            except Exception as e:
                logger.error(f"Error populating Domain Treeview: {e}", exc_info=True)
        else:
            logger.warning("refresh_domain_list called but domain_tree does not exist.")

    def add_whitelist_entry(self):
        entry_str = self.new_entry_var.get().strip()
        if not entry_str:
            messagebox.showwarning("Input Error", "Entry cannot be empty.", parent=self.master)
            return

        success, msg_or_type = whitelist.add_entry(entry_str)
        if success:
            logger.info(f"UI: Added '{entry_str}' as {msg_or_type}.")
            if msg_or_type == "ip":
                self.refresh_ip_list()
            elif msg_or_type == "domain":
                self.refresh_domain_list()
            self.new_entry_var.set("") # Clear input
            # No immediate save, user must click "Save Changes"
        else:
            messagebox.showerror("Add Error", msg_or_type, parent=self.master)
            logger.warning(f"UI: Failed to add whitelist entry '{entry_str}': {msg_or_type}")

    def remove_selected_ip(self):
        selected_item = self.ip_tree.focus() # Get selected item ID
        if not selected_item:
            messagebox.showwarning("Selection Error", "No IP/Network selected to remove.", parent=self.master)
            return
        
        item_values = self.ip_tree.item(selected_item, "values")
        if not item_values: return # Should not happen if item is focused

        ip_network_str = item_values[0]
        if messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove '{ip_network_str}' from the IP whitelist?", parent=self.master):
            if whitelist.remove_ip_network(ip_network_str):
                self.refresh_ip_list()
                logger.info(f"UI: Removed IP/Network '{ip_network_str}'.")
            else:
                messagebox.showerror("Removal Error", f"Could not remove '{ip_network_str}'. It might have already been removed or is invalid.", parent=self.master)
                logger.warning(f"UI: Failed to remove IP/Network '{ip_network_str}'.")

    def remove_selected_domain(self):
        selected_item = self.domain_tree.focus() # Get selected item ID
        if not selected_item:
            messagebox.showwarning("Selection Error", "No domain selected to remove.", parent=self.master)
            return

        item_values = self.domain_tree.item(selected_item, "values")
        if not item_values: return

        domain_str = item_values[0]
        if messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove '{domain_str}' from the domain whitelist?", parent=self.master):
            if whitelist.remove_domain(domain_str):
                self.refresh_domain_list()
                logger.info(f"UI: Removed domain '{domain_str}'.")
            else:
                messagebox.showerror("Removal Error", f"Could not remove '{domain_str}'. It might have already been removed.", parent=self.master)
                logger.warning(f"UI: Failed to remove domain '{domain_str}'.")
                
    def save_changes(self):
        """Saves all current whitelist entries (in memory) to the file."""
        logger.info("UI: Attempting to save whitelist changes to file.")
        if whitelist.save_whitelist():
            messagebox.showinfo("Whitelist Saved", f"Whitelist successfully saved to '{whitelist.filepath}'.", parent=self.master)
            # Optionally, reload and refresh to confirm, though save should be source of truth now.
            # self.reload_and_refresh() 
        else:
            messagebox.showerror("Save Error", f"Failed to save whitelist to '{whitelist.filepath}'. Check logs for details.", parent=self.master)

    def reload_and_refresh(self): # Kept for now, though save is primary
        """Reload whitelist from file and refresh GUI lists."""
        logger.info("Reloading whitelist file...")
        try:
            whitelist.load_whitelist() # Reload data
            self.refresh_ip_list(); self.refresh_domain_list()
            messagebox.showinfo("Reloaded", "Whitelist reloaded successfully from file.", parent=self.master)
        except Exception as e:
            logger.error(f"Failed to reload whitelist: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to reload whitelist:\n{e}", parent=self.master)
