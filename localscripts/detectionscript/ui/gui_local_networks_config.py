# ui/gui_local_networks_config.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
from core.config_manager import config
from ui.gui_tooltip import Tooltip

logger = logging.getLogger(__name__)

class LocalNetworksConfigWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Local Networks Config")
        self.master.geometry("600x400")
        logger.info("Initializing LocalNetworksConfigWindow.")

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Local Networks (CIDR):").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        self.local_networks_var = tk.StringVar(value=', '.join(config.local_networks))
        local_networks_entry = ttk.Entry(main_frame, textvariable=self.local_networks_var, width=40)
        local_networks_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W, pady=5)
        self.create_tooltip(local_networks_entry, "A comma-separated list of local network ranges in CIDR notation.")

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=3, pady=20)
        save_button = ttk.Button(button_frame, text="Save & Apply", command=self.save_and_apply)
        save_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.master.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("LocalNetworksConfigWindow closed."), self.master.destroy()))

    def create_tooltip(self, widget, text):
        tooltip = Tooltip(widget, text)
        widget.bind("<Enter>", lambda event: tooltip.showtip())
        widget.bind("<Leave>", lambda event: tooltip.hidetip())

    def save_and_apply(self):
        try:
            config.local_networks = {net.strip() for net in self.local_networks_var.get().split(',')}
            config.save_config()
            messagebox.showinfo("Settings Applied", "Local network settings updated and saved.", parent=self.master)
            self.master.destroy()
        except ValueError as e:
            logger.warning(f"Invalid input for local networks config: {e}")
            messagebox.showerror("Invalid Input", f"Please enter valid CIDR notations, separated by commas.\nError: {e}", parent=self.master)
        except Exception as e:
            logger.error(f"Error applying local networks config: {e}", exc_info=True)
            messagebox.showerror("Error", f"Could not apply settings: {e}", parent=self.master)
