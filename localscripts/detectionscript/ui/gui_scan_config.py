# ui/gui_scan_config.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
# Import the global config instance
from core.config_manager import config

logger = logging.getLogger(__name__)

class ScanConfigWindow:
    def __init__(self, master):
        """Initialize the Scan Detection Configuration window."""
        self.master = master
        self.master.title("Scan Detection Config")
        self.master.geometry("600x280") # Adjusted window size
        logger.info("Initializing ScanConfigWindow.")

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(2, weight=1) # Allow description column to expand

        # --- Helper for description labels ---
        desc_font = ("TkDefaultFont", 8, "italic")

        # --- Time Window ---
        ttk.Label(main_frame, text="Time Window (s):").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        self.time_window_var = tk.StringVar(value=str(config.scan_time_window))
        time_window_entry = ttk.Entry(main_frame, textvariable=self.time_window_var, width=10)
        time_window_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        ttk.Label(main_frame, text="Time (s) for analyzing SYN packets for scan patterns.", font=desc_font).grid(row=0, column=2, sticky=tk.W, pady=5, padx=5)

        # --- Distinct Ports Threshold ---
        ttk.Label(main_frame, text="Ports Threshold:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        self.ports_thresh_var = tk.StringVar(value=str(config.scan_distinct_ports_threshold))
        ports_thresh_entry = ttk.Entry(main_frame, textvariable=self.ports_thresh_var, width=10)
        ports_thresh_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        ttk.Label(main_frame, text="SYNs to distinct ports on one host to flag port scan.", font=desc_font).grid(row=1, column=2, sticky=tk.W, pady=5, padx=5)

        # --- Distinct Hosts Threshold ---
        ttk.Label(main_frame, text="Hosts Threshold:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        self.hosts_thresh_var = tk.StringVar(value=str(config.scan_distinct_hosts_threshold))
        hosts_thresh_entry = ttk.Entry(main_frame, textvariable=self.hosts_thresh_var, width=10)
        hosts_thresh_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Label(main_frame, text="SYNs to distinct hosts to flag host scan.", font=desc_font).grid(row=2, column=2, sticky=tk.W, pady=5, padx=5)

        # --- Scan Check Interval ---
        ttk.Label(main_frame, text="Scan Check Interval (s):").grid(row=3, column=0, sticky=tk.W, pady=5, padx=5)
        self.scan_check_interval_var = tk.StringVar(value=str(config.scan_check_interval))
        scan_check_interval_entry = ttk.Entry(main_frame, textvariable=self.scan_check_interval_var, width=10)
        scan_check_interval_entry.grid(row=3, column=1, sticky=tk.W, pady=5)
        ttk.Label(main_frame, text="Interval (s) between per-IP scan checks (rate-limit).", font=desc_font).grid(row=3, column=2, sticky=tk.W, pady=5, padx=5)

        # --- Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=20) # columnspan adjusted
        save_button = ttk.Button(button_frame, text="Save & Apply", command=self.save_and_apply)
        save_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.master.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("ScanConfigWindow closed."), self.master.destroy()))

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

            logger.info(
                f"Applied new scan detection settings: Window={config.scan_time_window}s, "
                f"PortsThresh={config.scan_distinct_ports_threshold}, HostsThresh={config.scan_distinct_hosts_threshold}, "
                f"CheckInterval={config.scan_check_interval}s"
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
