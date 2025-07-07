# ui/gui_local_network_config.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
from core.config_manager import config
from ui.gui_tooltip import Tooltip

logger = logging.getLogger(__name__)

class LocalNetworkConfigWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Local Network Detection Config")
        self.master.geometry("600x400")
        logger.info("Initializing LocalNetworkConfigWindow.")

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- ARP Spoofing Detection ---
        arp_frame = ttk.LabelFrame(main_frame, text="ARP Spoofing Detection", padding="10")
        arp_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=10, padx=5)
        self.enable_arp_spoof_var = tk.BooleanVar(value=config.enable_arp_spoof_detection)
        ttk.Checkbutton(arp_frame, text="Enable ARP Spoofing Detection", variable=self.enable_arp_spoof_var).pack(anchor=tk.W)

        # --- ICMP Anomaly Detection ---
        icmp_frame = ttk.LabelFrame(main_frame, text="ICMP Anomaly Detection", padding="10")
        icmp_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=10, padx=5)
        icmp_frame.columnconfigure(1, weight=1)

        self.enable_icmp_anomaly_var = tk.BooleanVar(value=config.enable_icmp_anomaly_detection)
        ttk.Checkbutton(icmp_frame, text="Enable ICMP Anomaly Detection", variable=self.enable_icmp_anomaly_var).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5, padx=5)

        ttk.Label(icmp_frame, text="Ping Sweep Threshold:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        self.icmp_ping_sweep_var = tk.StringVar(value=str(config.icmp_ping_sweep_threshold))
        icmp_ping_sweep_entry = ttk.Entry(icmp_frame, textvariable=self.icmp_ping_sweep_var, width=10)
        icmp_ping_sweep_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        self.create_tooltip(icmp_ping_sweep_entry, "Number of ICMP echo requests to distinct hosts to trigger a ping sweep alert.")

        ttk.Label(icmp_frame, text="Large Payload Threshold:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        self.icmp_large_payload_var = tk.StringVar(value=str(config.icmp_large_payload_threshold))
        icmp_large_payload_entry = ttk.Entry(icmp_frame, textvariable=self.icmp_large_payload_var, width=10)
        icmp_large_payload_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        self.create_tooltip(icmp_large_payload_entry, "ICMP payload size in bytes to trigger a large payload (tunneling) alert.")

        # --- Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=20)
        save_button = ttk.Button(button_frame, text="Save & Apply", command=self.save_and_apply)
        save_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.master.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("LocalNetworkConfigWindow closed."), self.master.destroy()))

    def create_tooltip(self, widget, text):
        tooltip = Tooltip(widget, text)
        widget.bind("<Enter>", lambda event: tooltip.showtip())
        widget.bind("<Leave>", lambda event: tooltip.hidetip())

    def save_and_apply(self):
        try:
            config.enable_arp_spoof_detection = self.enable_arp_spoof_var.get()
            config.enable_icmp_anomaly_detection = self.enable_icmp_anomaly_var.get()
            config.icmp_ping_sweep_threshold = int(self.icmp_ping_sweep_var.get())
            config.icmp_large_payload_threshold = int(self.icmp_large_payload_var.get())

            config.save_config()
            messagebox.showinfo("Settings Applied", "Local network detection settings updated and saved.", parent=self.master)
            self.master.destroy()

        except ValueError as e:
            logger.warning(f"Invalid input for local network detection config: {e}")
            messagebox.showerror("Invalid Input", f"Please enter valid numbers.\nError: {e}", parent=self.master)
        except Exception as e:
            logger.error(f"Error applying local network detection config: {e}", exc_info=True)
            messagebox.showerror("Error", f"Could not apply settings: {e}", parent=self.master)
