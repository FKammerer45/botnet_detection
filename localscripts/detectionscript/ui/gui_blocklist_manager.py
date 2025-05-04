# ui/gui_blocklist_manager.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
from core.config_manager import config # Import config instance
# Import blocklist functions (download/load are needed on apply)
from core.blocklist_integration import download_blocklists, load_blocklists

logger = logging.getLogger(__name__)

# *** Ensure class name matches the one used in gui_main.py ***
class BlocklistManagerWindow:
    def __init__(self, master):
        """Initialize the blocklist manager GUI using config."""
        self.master = master
        self.master.title("Blocklist Manager")
        self.master.geometry("750x600")
        logger.info("Initializing BlocklistManagerWindow.")

        # Store checkbox variables locally: {url: tk.BooleanVar}
        self.checkbox_vars = {}

        # --- Main Frame ---
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Explanation ---
        explanation_label = ttk.Label(
            main_frame,
            text=(
                "Manage IP and DNS blocklists defined in config.ini.\n"
                "- Check/Uncheck to activate/deactivate lists for the *next run* (requires saving).\n"
                "- Add new URLs directly to config.ini ([Blocklists_IP] or [Blocklists_DNS]).\n"
                "- Click 'Save & Apply' to update config.ini, re-download active lists, and reload data."
            ),
            wraplength=730, justify="left"
        )
        explanation_label.pack(pady=10, anchor=tk.W)

        # --- Paned Window for IP and DNS lists ---
        paned_window = tk.PanedWindow(main_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        paned_window.pack(fill=tk.BOTH, expand=True, pady=5)

        # --- IP Blocklist Section ---
        ip_list_frame = ttk.LabelFrame(paned_window, text="IP Blocklists (from config.ini)")
        paned_window.add(ip_list_frame) 
      
        self._setup_list_ui(ip_list_frame, config.ip_blocklist_urls, "ip")

        # --- DNS Blocklist Section ---
        dns_list_frame = ttk.LabelFrame(paned_window, text="DNS Blocklists (from config.ini)")
        paned_window.add(dns_list_frame) 
    
        self._setup_list_ui(dns_list_frame, config.dns_blocklist_urls, "dns")


        # --- Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=15)

        apply_button = ttk.Button(button_frame, text="Save & Apply Changes", command=self.save_and_apply_changes)
        apply_button.pack(side=tk.LEFT, padx=10)

        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.master.destroy)
        cancel_button.pack(side=tk.LEFT, padx=10)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("BlocklistManagerWindow closed."), self.master.destroy()))

    def _setup_list_ui(self, parent_frame, url_set, list_type):
        """Creates the scrollable checkbox list for a given set of URLs."""
        # Frame for checkboxes with scrollbar
        checkbox_area = tk.Frame(parent_frame)
        checkbox_area.pack(fill="both", expand=True, padx=5, pady=5)

        canvas = tk.Canvas(checkbox_area)
        scrollbar = ttk.Scrollbar(checkbox_area, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Populate checkboxes
        sorted_urls = sorted(list(url_set))
        for url in sorted_urls:
            # Checkboxes represent the *current* active state from the config object
            # The user modifies these, and on save, the config object is updated.
            is_active = url in (config.ip_blocklist_urls if list_type == "ip" else config.dns_blocklist_urls)
            var = tk.BooleanVar(value=is_active)
            self.checkbox_vars[url] = var # Store var keyed by URL

            # Shorten URL for display if too long
            display_url = url
            max_display_len = 60
            if len(url) > max_display_len:
                display_url = url[:max_display_len//2 - 2] + "..." + url[-max_display_len//2 + 1:]

            cb = ttk.Checkbutton(scrollable_frame, text=display_url, variable=var) # Removed tooltip for now
            cb.pack(anchor="w", padx=2)

            # Simple Tooltip implementation (Optional - can be complex)
            # def enter(event, text=url): ...
            # def leave(event): ...
            # cb.bind("<Enter>", enter)
            # cb.bind("<Leave>", leave)


    def save_and_apply_changes(self):
        """Update config object, save config.ini, re-download, re-load."""
        logger.info("Applying blocklist changes...")
        new_ip_urls = set()
        new_dns_urls = set()

        # Update the sets based on checkbox states
        for url, var in self.checkbox_vars.items():
             is_active = var.get()
             # Determine if it was originally an IP or DNS list to add back correctly
             # This relies on the initial population based on config sets
             # A more robust way might store type alongside checkbox_vars if lists could be added dynamically

             # Check if URL exists in either original config set
             is_ip_list = url in config.ip_blocklist_urls
             is_dns_list = url in config.dns_blocklist_urls

             if is_active:
                 if is_ip_list:
                     new_ip_urls.add(url)
                 elif is_dns_list: # Check if it was a DNS list
                     new_dns_urls.add(url)
                 else:
                     # Should not happen if list is only populated from config
                     logger.warning(f"URL '{url}' from checkbox_vars not found in initial config sets. Assuming IP list.")
                     new_ip_urls.add(url) # Default assumption or skip?

             # If inactive, it's simply not added to the new sets

        # Update the config object
        config.ip_blocklist_urls = new_ip_urls
        config.dns_blocklist_urls = new_dns_urls
        logger.debug(f"Updated config IP URLs: {config.ip_blocklist_urls}")
        logger.debug(f"Updated config DNS URLs: {config.dns_blocklist_urls}")

        # Save the updated config to config.ini
        config.save_config()

        # Re-download and re-load blocklists
        try:
            logger.info("Triggering blocklist re-download (force=True)...")
            download_blocklists(force_download=True) # Force download based on new active state
            logger.info("Triggering blocklist re-load...")
            load_blocklists() # Reload based on new active state
            logger.info("Blocklists updated and reloaded successfully.")
            messagebox.showinfo("Blocklists Updated", "Config saved, blocklists re-downloaded and reloaded!", parent=self.master)
            self.master.destroy() # Close manager window after applying
        except Exception as e:
            logger.error(f"Error applying blocklist changes: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to apply blocklist changes:\n{e}", parent=self.master)

