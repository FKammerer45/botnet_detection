# ui/gui_scoring_config.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
from core.config_manager import config
from ui.gui_tooltip import Tooltip

logger = logging.getLogger(__name__)

class ScoringConfigWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Scoring Config")
        self.master.geometry("600x600")
        logger.info("Initializing ScoringConfigWindow.")

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Add description
        description_text = ("Configure the points assigned for various threat indicators. "
                            "The total score determines the threat level of an IP. "
                            "Set the threshold for when an IP should be flagged as high risk.")
        description_label = ttk.Label(main_frame, text=description_text, wraplength=550, justify=tk.LEFT)
        description_label.pack(pady=(0, 10), fill=tk.X)

        self.scoring_vars = {}
        self.create_widgets(main_frame)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10, fill=tk.X)

        save_button = ttk.Button(button_frame, text="Save & Apply", command=self.save_and_apply)
        save_button.pack(side=tk.LEFT, padx=5)
        
        close_button = ttk.Button(button_frame, text="Close", command=self.master.destroy)
        close_button.pack(side=tk.RIGHT, padx=5)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("ScoringConfigWindow closed."), self.master.destroy()))

    def create_widgets(self, parent_frame):
        # Frame for the grid
        grid_frame = ttk.Frame(parent_frame)
        grid_frame.pack(fill=tk.X)

        # This is a bit repetitive, but it's clear and easy to maintain
        # A more advanced implementation could generate this from a dictionary
        row = 0
        for score_attr, label_text, tooltip_text in self.get_score_attributes():
            ttk.Label(grid_frame, text=label_text).grid(row=row, column=0, sticky=tk.W, pady=2, padx=5)
            # Use hasattr to safely get the attribute, with a default
            current_value = getattr(config, score_attr, 0)
            var = tk.StringVar(value=str(current_value))
            entry = ttk.Entry(grid_frame, textvariable=var, width=10)
            entry.grid(row=row, column=1, sticky=tk.W, pady=2)
            self.create_tooltip(entry, tooltip_text)
            self.scoring_vars[score_attr] = var
            row += 1

    def get_score_attributes(self):
        return [
            ("score_threshold", "Score Threshold:", "If an IP's score exceeds this, it will be flagged."),
            ("score_arp_spoof", "ARP Spoofing:", "Points for detecting ARP spoofing."),
            ("score_icmp_ping_sweep", "ICMP Ping Sweep:", "Points for detecting an ICMP ping sweep."),
            ("score_icmp_tunneling", "ICMP Tunneling:", "Points for detecting ICMP tunneling."),
            ("score_c2_beaconing", "C2 Beaconing:", "Points for detecting C2 beaconing."),
            ("score_ja3_hit", "Malicious JA3/JA3S:", "Points for a JA3/JA3S blocklist hit."),
            ("score_dga", "DGA Detected:", "Points for detecting a DGA domain."),
            ("score_dns_tunneling", "DNS Tunneling:", "Points for detecting DNS tunneling."),
            ("score_ip_blocklist", "IP Blocklist Hit:", "Points for an IP blocklist hit."),
            ("score_dns_blocklist", "DNS Blocklist Hit:", "Points for a DNS blocklist hit."),
            ("score_port_scan", "Port Scan:", "Points for detecting a port scan."),
            ("score_host_scan", "Host Scan:", "Points for detecting a host scan."),
            ("score_rate_anomaly", "Rate Anomaly:", "Points for detecting a rate anomaly."),
            ("score_unsafe_protocol", "Unsafe Protocol:", "Points for using an unsafe protocol."),
        ]

    def create_tooltip(self, widget, text):
        tooltip = Tooltip(widget, text)
        widget.bind("<Enter>", lambda event: tooltip.showtip())
        widget.bind("<Leave>", lambda event: tooltip.hidetip())

    def save_and_apply(self):
        try:
            for score_attr, var in self.scoring_vars.items():
                setattr(config, score_attr, int(var.get()))
            
            config.save_config()
            messagebox.showinfo("Settings Applied", "Scoring settings updated and saved.", parent=self.master)
            self.master.destroy()

        except ValueError as e:
            logger.warning(f"Invalid input for scoring config: {e}")
            messagebox.showerror("Invalid Input", f"Please enter valid integers.\nError: {e}", parent=self.master)
        except Exception as e:
            logger.error(f"Error applying scoring config: {e}", exc_info=True)
            messagebox.showerror("Error", f"Could not apply settings: {e}", parent=self.master)
