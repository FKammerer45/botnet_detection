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
        self.master.geometry("750x700") # Increased height
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
                "Manage IP and DNS blocklists.\n"
                "- Check/Uncheck to activate/deactivate lists for the *next run* (requires saving).\n"
                "- Use the form below to add new blocklist URLs.\n"
                "- Click 'Save & Apply' to update config.ini, re-download active lists, and reload data."
            ),
            wraplength=730, justify="left"
        )
        explanation_label.pack(pady=10, anchor=tk.W)

        # --- Paned Window for IP and DNS lists ---
        paned_window = tk.PanedWindow(main_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        paned_window.pack(fill=tk.BOTH, expand=True, pady=5)

        # Store frames for easy clearing and rebuilding
        self.ip_list_frame_container = ttk.LabelFrame(paned_window, text="IP Blocklists")
        paned_window.add(self.ip_list_frame_container)
      
        self.dns_list_frame_container = ttk.LabelFrame(paned_window, text="DNS Blocklists")
        paned_window.add(self.dns_list_frame_container)
    
        self._refresh_all_blocklist_displays() # Initial population

        # --- Add New Blocklist Section ---
        add_frame = ttk.LabelFrame(main_frame, text="Add New Blocklist URL", padding="10")
        add_frame.pack(fill=tk.X, pady=10)

        ttk.Label(add_frame, text="URL:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.new_url_var = tk.StringVar()
        new_url_entry = ttk.Entry(add_frame, textvariable=self.new_url_var, width=60)
        new_url_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(add_frame, text="Type:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.new_url_type_var = tk.StringVar(value="IP") # Default to IP
        url_type_combo = ttk.Combobox(add_frame, textvariable=self.new_url_type_var, values=["IP", "DNS"], state="readonly", width=5)
        url_type_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        add_button = ttk.Button(add_frame, text="Add Blocklist", command=self.add_new_blocklist)
        add_button.grid(row=1, column=2, padx=10, pady=5, sticky=tk.E)
        add_frame.columnconfigure(1, weight=1)


        # --- Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=15)

        apply_button = ttk.Button(button_frame, text="Save & Apply Changes", command=self.save_and_apply_changes)
        apply_button.pack(side=tk.LEFT, padx=10)

        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.master.destroy)
        cancel_button.pack(side=tk.LEFT, padx=10)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("BlocklistManagerWindow closed."), self.master.destroy()))

    def _clear_frame_widgets(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()

    def _refresh_all_blocklist_displays(self):
        """Clears and rebuilds both IP and DNS blocklist UI sections."""
        logger.debug("Refreshing blocklist displays.")
        self.checkbox_vars.clear() # Clear old vars before repopulating

        self._clear_frame_widgets(self.ip_list_frame_container)
        self._setup_list_ui(self.ip_list_frame_container, config.ip_blocklist_urls, "ip")

        self._clear_frame_widgets(self.dns_list_frame_container)
        self._setup_list_ui(self.dns_list_frame_container, config.dns_blocklist_urls, "dns")

    def _setup_list_ui(self, parent_frame, url_set, list_type):
        """Creates the scrollable checkbox list for a given set of URLs."""
        # Frame for checkboxes with scrollbar
        checkbox_area = tk.Frame(parent_frame) # Use tk.Frame for direct child of LabelFrame
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
        # Use the current config object's sets directly
        current_urls_for_type = config.ip_blocklist_urls if list_type == "ip" else config.dns_blocklist_urls
        sorted_urls = sorted(list(url_set)) # url_set is passed for initial population, but active state from current_urls_for_type

        for url in sorted_urls:
            is_active = url in current_urls_for_type # Check against current config state
            var = tk.BooleanVar(value=is_active)
            self.checkbox_vars[url] = var 

            display_url = url
            max_display_len = 50 # Adjusted for potentially narrower panes
            if len(url) > max_display_len:
                display_url = url[:max_display_len//2 - 2] + "..." + url[-max_display_len//2 + 1:]

            cb = ttk.Checkbutton(scrollable_frame, text=display_url, variable=var)
            cb.pack(anchor="w", padx=2)

    def add_new_blocklist(self):
        """Adds a new blocklist URL to the config object and refreshes the UI."""
        new_url = self.new_url_var.get().strip()
        url_type = self.new_url_type_var.get() # "IP" or "DNS"

        if not new_url:
            messagebox.showwarning("Input Error", "URL cannot be empty.", parent=self.master)
            return
        
        # Basic URL validation (can be improved)
        if not (new_url.startswith("http://") or new_url.startswith("https://")):
            messagebox.showwarning("Input Error", "URL must start with http:// or https://", parent=self.master)
            return

        # Check for duplicates
        if new_url in config.ip_blocklist_urls or new_url in config.dns_blocklist_urls:
            messagebox.showwarning("Duplicate URL", "This URL already exists in the blocklists.", parent=self.master)
            return

        if url_type == "IP":
            config.ip_blocklist_urls.add(new_url)
            logger.info(f"Added new IP blocklist URL (in memory): {new_url}")
        elif url_type == "DNS":
            config.dns_blocklist_urls.add(new_url)
            logger.info(f"Added new DNS blocklist URL (in memory): {new_url}")
        else:
            messagebox.showerror("Internal Error", "Invalid blocklist type selected.", parent=self.master)
            return
        
        self._refresh_all_blocklist_displays() # Refresh UI to show the new URL
        self.new_url_var.set("") # Clear input field
        messagebox.showinfo("URL Added", f"'{new_url}' added as {url_type} blocklist.\nClick 'Save & Apply Changes' to make it permanent.", parent=self.master)


    def save_and_apply_changes(self):
        """Update config object based on checkbox states, save config.ini, re-download, re-load."""
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
