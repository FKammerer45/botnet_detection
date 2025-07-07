# ui/gui_dns_config.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
from core.config_manager import config
from ui.gui_tooltip import Tooltip

logger = logging.getLogger(__name__)

class DnsConfigWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("DNS Analysis Config")
        self.master.geometry("600x400")
        logger.info("Initializing DnsConfigWindow.")

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Enable/Disable ---
        self.enable_dns_analysis_var = tk.BooleanVar(value=config.enable_dns_analysis)
        ttk.Checkbutton(main_frame, text="Enable Enhanced DNS Analysis", variable=self.enable_dns_analysis_var).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5, padx=5)

        # --- DGA Detection ---
        dga_frame = ttk.LabelFrame(main_frame, text="DGA Detection", padding="10")
        dga_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=10, padx=5)
        dga_frame.columnconfigure(1, weight=1)

        ttk.Label(dga_frame, text="Entropy Threshold:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        self.dga_entropy_var = tk.StringVar(value=str(config.dga_entropy_threshold))
        dga_entropy_entry = ttk.Entry(dga_frame, textvariable=self.dga_entropy_var, width=10)
        dga_entropy_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        self.create_tooltip(dga_entropy_entry, "Shannon entropy threshold for detecting DGA domains. Higher values are more strict.")

        ttk.Label(dga_frame, text="Length Threshold:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        self.dga_length_var = tk.StringVar(value=str(config.dga_length_threshold))
        dga_length_entry = ttk.Entry(dga_frame, textvariable=self.dga_length_var, width=10)
        dga_length_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        self.create_tooltip(dga_length_entry, "Domain name length threshold for DGA detection.")

        # --- DNS Tunneling Detection ---
        tunnel_frame = ttk.LabelFrame(main_frame, text="DNS Tunneling Detection", padding="10")
        tunnel_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=10, padx=5)
        tunnel_frame.columnconfigure(1, weight=1)

        ttk.Label(tunnel_frame, text="NXDOMAIN Rate Threshold:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        self.nxdomain_rate_var = tk.StringVar(value=str(config.nxdomain_rate_threshold))
        nxdomain_rate_entry = ttk.Entry(tunnel_frame, textvariable=self.nxdomain_rate_var, width=10)
        nxdomain_rate_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        self.create_tooltip(nxdomain_rate_entry, "Rate of NXDOMAIN responses (0.0-1.0) to trigger a tunneling alert.")

        ttk.Label(tunnel_frame, text="NXDOMAIN Min Count:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        self.nxdomain_min_count_var = tk.StringVar(value=str(config.nxdomain_min_count))
        nxdomain_min_count_entry = ttk.Entry(tunnel_frame, textvariable=self.nxdomain_min_count_var, width=10)
        nxdomain_min_count_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        self.create_tooltip(nxdomain_min_count_entry, "Minimum number of total DNS queries before checking the NXDOMAIN rate.")

        # --- Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=20)
        save_button = ttk.Button(button_frame, text="Save & Apply", command=self.save_and_apply)
        save_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.master.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("DnsConfigWindow closed."), self.master.destroy()))

    def create_tooltip(self, widget, text):
        tooltip = Tooltip(widget, text)
        widget.bind("<Enter>", lambda event: tooltip.showtip())
        widget.bind("<Leave>", lambda event: tooltip.hidetip())

    def save_and_apply(self):
        try:
            config.enable_dns_analysis = self.enable_dns_analysis_var.get()
            config.dga_entropy_threshold = float(self.dga_entropy_var.get())
            config.dga_length_threshold = int(self.dga_length_var.get())
            config.nxdomain_rate_threshold = float(self.nxdomain_rate_var.get())
            config.nxdomain_min_count = int(self.nxdomain_min_count_var.get())

            config.save_config()
            messagebox.showinfo("Settings Applied", "DNS analysis settings updated and saved.", parent=self.master)
            self.master.destroy()

        except ValueError as e:
            logger.warning(f"Invalid input for DNS analysis config: {e}")
            messagebox.showerror("Invalid Input", f"Please enter valid numbers.\nError: {e}", parent=self.master)
        except Exception as e:
            logger.error(f"Error applying DNS analysis config: {e}", exc_info=True)
            messagebox.showerror("Error", f"Could not apply settings: {e}", parent=self.master)
