# ui/gui_scan_config.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
# Import the global config instance
from core.config_manager import config

logger = logging.getLogger(__name__)

from ui.gui_tooltip import Tooltip

class ScanConfigWindow:
    def __init__(self, master):
        """Initialize the Scan Detection Configuration window."""
        self.master = master
        self.master.title("Scan Detection Config")
        self.master.geometry("600x400") # Adjusted window size
        logger.info("Initializing ScanConfigWindow.")

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(2, weight=1) # Allow description column to expand

        # --- Helper for description labels ---
        desc_font = ("TkDefaultFont", 8, "italic")

        # --- Time Window ---
        time_window_label = ttk.Label(main_frame, text="Time Window (s):")
        time_window_label.grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        self.time_window_var = tk.StringVar(value=str(config.scan_time_window))
        time_window_entry = ttk.Entry(main_frame, textvariable=self.time_window_var, width=10)
        time_window_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        self.create_tooltip(time_window_label, "The time window in seconds to analyze packets for scan patterns.")
        self.create_tooltip(time_window_entry, "The time window in seconds to analyze packets for scan patterns.")

        # --- Distinct Ports Threshold ---
        ports_thresh_label = ttk.Label(main_frame, text="Ports Threshold:")
        ports_thresh_label.grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        self.ports_thresh_var = tk.StringVar(value=str(config.scan_distinct_ports_threshold))
        ports_thresh_entry = ttk.Entry(main_frame, textvariable=self.ports_thresh_var, width=10)
        ports_thresh_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        self.create_tooltip(ports_thresh_label, "Number of connections to distinct ports on a single host to trigger a port scan alert.")
        self.create_tooltip(ports_thresh_entry, "Number of connections to distinct ports on a single host to trigger a port scan alert.")

        # --- Distinct Hosts Threshold ---
        hosts_thresh_label = ttk.Label(main_frame, text="Hosts Threshold:")
        hosts_thresh_label.grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        self.hosts_thresh_var = tk.StringVar(value=str(config.scan_distinct_hosts_threshold))
        hosts_thresh_entry = ttk.Entry(main_frame, textvariable=self.hosts_thresh_var, width=10)
        hosts_thresh_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        self.create_tooltip(hosts_thresh_label, "Number of connections to distinct hosts to trigger a host scan alert.")
        self.create_tooltip(hosts_thresh_entry, "Number of connections to distinct hosts to trigger a host scan alert.")

        # --- Scan Check Interval ---
        scan_check_interval_label = ttk.Label(main_frame, text="Scan Check Interval (s):")
        scan_check_interval_label.grid(row=3, column=0, sticky=tk.W, pady=5, padx=5)
        self.scan_check_interval_var = tk.StringVar(value=str(config.scan_check_interval))
        scan_check_interval_entry = ttk.Entry(main_frame, textvariable=self.scan_check_interval_var, width=10)
        scan_check_interval_entry.grid(row=3, column=1, sticky=tk.W, pady=5)
        self.create_tooltip(scan_check_interval_label, "The interval in seconds between per-IP scan checks to limit resource usage.")
        self.create_tooltip(scan_check_interval_entry, "The interval in seconds between per-IP scan checks to limit resource usage.")

        # --- Enable/Disable Flags ---
        self.enable_stealth_scan_var = tk.BooleanVar(value=config.enable_stealth_scan_detection)
        stealth_scan_cb = ttk.Checkbutton(main_frame, text="Enable Stealth Scan Detection", variable=self.enable_stealth_scan_var)
        stealth_scan_cb.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5, padx=5)
        self.create_tooltip(stealth_scan_cb, "Enable detection of stealthy scan techniques like FIN, NULL, and XMAS scans.")
        self.flag_internal_scans_var = tk.BooleanVar(value=config.flag_internal_scans)
        internal_scans_cb = ttk.Checkbutton(main_frame, text="Flag Internal Scans", variable=self.flag_internal_scans_var)
        internal_scans_cb.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=5, padx=5)
        self.create_tooltip(internal_scans_cb, "Flag scans originating from and targeting internal networks.")
        self.flag_external_scans_var = tk.BooleanVar(value=config.flag_external_scans)
        external_scans_cb = ttk.Checkbutton(main_frame, text="Flag External Scans", variable=self.flag_external_scans_var)
        external_scans_cb.grid(row=6, column=0, columnspan=2, sticky=tk.W, pady=5, padx=5)
        self.create_tooltip(external_scans_cb, "Flag scans originating from or targeting external networks.")

        # --- Local Networks ---
        local_networks_label = ttk.Label(main_frame, text="Local Networks (CIDR):")
        local_networks_label.grid(row=7, column=0, sticky=tk.W, pady=5, padx=5)
        self.local_networks_var = tk.StringVar(value=', '.join(config.local_networks))
        local_networks_entry = ttk.Entry(main_frame, textvariable=self.local_networks_var, width=40)
        local_networks_entry.grid(row=7, column=1, columnspan=2, sticky=tk.W, pady=5)
        self.create_tooltip(local_networks_label, "A comma-separated list of local network ranges in CIDR notation.")
        self.create_tooltip(local_networks_entry, "A comma-separated list of local network ranges in CIDR notation.")


        # --- Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=8, column=0, columnspan=3, pady=20) # columnspan adjusted
        save_button = ttk.Button(button_frame, text="Save & Apply", command=self.save_and_apply)
        save_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.master.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("ScanConfigWindow closed."), self.master.destroy()))

    def create_tooltip(self, widget, text):
        tooltip = Tooltip(widget, text)
        widget.bind("<Enter>", lambda event: tooltip.showtip())
        widget.bind("<Leave>", lambda event: tooltip.hidetip())

    def save_and_apply(self):
        """Validate inputs, update config object, save config file, and close."""
        try:
            new_time_window = int(self.time_window_var.get())
            new_ports_thresh = int(self.ports_thresh_var.get())
            new_hosts_thresh = int(self.hosts_thresh_var.get())
            new_scan_check_interval = float(self.scan_check_interval_var.get()) # Use float for interval

            if new_time_window <= 0 or new_ports_thresh <= 0 or new_hosts_thresh <= 0 or new_scan_check_interval <=0:
                raise ValueError("Thresholds and interval must be positive numbers.")

            # *** Update config object attributes ***
            config.scan_time_window = new_time_window
            config.scan_distinct_ports_threshold = new_ports_thresh
            config.scan_distinct_hosts_threshold = new_hosts_thresh
            config.scan_check_interval = new_scan_check_interval
            config.enable_stealth_scan_detection = self.enable_stealth_scan_var.get()
            config.flag_internal_scans = self.flag_internal_scans_var.get()
            config.flag_external_scans = self.flag_external_scans_var.get()
            config.local_networks = {net.strip() for net in self.local_networks_var.get().split(',')}


            logger.info(
                f"Applied new scan detection settings: Window={config.scan_time_window}s, "
                f"PortsThresh={config.scan_distinct_ports_threshold}, HostsThresh={config.scan_distinct_hosts_threshold}, "
                f"CheckInterval={config.scan_check_interval}s, "
                f"StealthScan={config.enable_stealth_scan_detection}, "
                f"InternalScan={config.flag_internal_scans}, ExternalScan={config.flag_external_scans}"
            )

            # *** Save changes to config.ini ***
            config.save_config()

            messagebox.showinfo("Settings Applied", "Scan detection settings updated and saved.", parent=self.master)
            self.master.destroy()

        except ValueError as e:
            logger.warning(f"Invalid input for scan config: {e}")
            messagebox.showerror("Invalid Input", f"Please enter valid positive integers.\nError: {e}", parent=self.master)
        except Exception as e:
             logger.error(f"Error applying scan config: {e}", exc_info=True)
             messagebox.showerror("Error", f"Could not apply settings: {e}", parent=self.master)
