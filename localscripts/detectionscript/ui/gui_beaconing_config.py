# ui/gui_beaconing_config.py
import tkinter as tk
from tkinter import ttk, messagebox
import logging
# Import the global config instance
from core.config_manager import config

logger = logging.getLogger(__name__)

class BeaconingConfigWindow:
    def __init__(self, master):
        """Initialize the Beaconing Detection Configuration window."""
        self.master = master
        self.master.title("Beaconing Detection Config")
        self.master.geometry("600x280") # Adjusted window size
        logger.info("Initializing BeaconingConfigWindow.")

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(2, weight=1) # Allow description column to expand

        # --- Helper for description labels ---
        desc_font = ("TkDefaultFont", 8, "italic")

        # --- Enable/Disable ---
        self.enable_beaconing_var = tk.BooleanVar(value=config.enable_beaconing_detection)
        ttk.Checkbutton(main_frame, text="Enable Beaconing Detection", variable=self.enable_beaconing_var).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5, padx=5)

        # --- Interval ---
        ttk.Label(main_frame, text="Interval (s):").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        self.interval_var = tk.StringVar(value=str(config.beaconing_interval_seconds))
        interval_entry = ttk.Entry(main_frame, textvariable=self.interval_var, width=10)
        interval_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        ttk.Label(main_frame, text="Expected interval between connections.", font=desc_font).grid(row=1, column=2, sticky=tk.W, pady=5, padx=5)

        # --- Tolerance ---
        ttk.Label(main_frame, text="Tolerance (s):").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        self.tolerance_var = tk.StringVar(value=str(config.beaconing_tolerance_seconds))
        tolerance_entry = ttk.Entry(main_frame, textvariable=self.tolerance_var, width=10)
        tolerance_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Label(main_frame, text="Allowed deviation from the interval.", font=desc_font).grid(row=2, column=2, sticky=tk.W, pady=5, padx=5)

        # --- Minimum Occurrences ---
        ttk.Label(main_frame, text="Min Occurrences:").grid(row=3, column=0, sticky=tk.W, pady=5, padx=5)
        self.min_occurrences_var = tk.StringVar(value=str(config.beaconing_min_occurrences))
        min_occurrences_entry = ttk.Entry(main_frame, textvariable=self.min_occurrences_var, width=10)
        min_occurrences_entry.grid(row=3, column=1, sticky=tk.W, pady=5)
        ttk.Label(main_frame, text="Number of regular connections to trigger an alert.", font=desc_font).grid(row=3, column=2, sticky=tk.W, pady=5, padx=5)

        # --- Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=20) # columnspan adjusted
        save_button = ttk.Button(button_frame, text="Save & Apply", command=self.save_and_apply)
        save_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.master.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)

        self.master.protocol("WM_DELETE_WINDOW", lambda: (logger.info("BeaconingConfigWindow closed."), self.master.destroy()))

    def save_and_apply(self):
        """Validate inputs, update config object, save config file, and close."""
        try:
            new_interval = int(self.interval_var.get())
            new_tolerance = int(self.tolerance_var.get())
            new_min_occurrences = int(self.min_occurrences_var.get())

            if new_interval <= 0 or new_tolerance < 0 or new_min_occurrences <= 0:
                raise ValueError("Interval and occurrences must be positive. Tolerance cannot be negative.")

            # *** Update config object attributes ***
            config.enable_beaconing_detection = self.enable_beaconing_var.get()
            config.beaconing_interval_seconds = new_interval
            config.beaconing_tolerance_seconds = new_tolerance
            config.beaconing_min_occurrences = new_min_occurrences

            logger.info(
                f"Applied new beaconing detection settings: Enabled={config.enable_beaconing_detection}, "
                f"Interval={config.beaconing_interval_seconds}s, Tolerance={config.beaconing_tolerance_seconds}s, "
                f"MinOccurrences={config.beaconing_min_occurrences}"
            )

            # *** Save changes to config.ini ***
            config.save_config()

            messagebox.showinfo("Settings Applied", "Beaconing detection settings updated and saved.", parent=self.master)
            self.master.destroy()

        except ValueError as e:
            logger.warning(f"Invalid input for beaconing config: {e}")
            messagebox.showerror("Invalid Input", f"Please enter valid numbers.\nError: {e}", parent=self.master)
        except Exception as e:
             logger.error(f"Error applying beaconing config: {e}", exc_info=True)
             messagebox.showerror("Error", f"Could not apply settings: {e}", parent=self.master)
