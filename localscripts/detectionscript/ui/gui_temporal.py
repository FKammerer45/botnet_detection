# gui_temporal.py
import datetime
import tkinter as tk
from tkinter import ttk, messagebox
import logging # Import logging module
import matplotlib.dates as mdates
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import deque # Import deque explicitly

from core.capture import temporal_data, lock
from config.globals import TRACKED_PROTOCOLS

# Get a logger for this module
logger = logging.getLogger(__name__)

class TemporalAnalysisWindow:
    def __init__(self, master, get_flag_suspicious_func, get_threshold_func):
        """
        Initialize the temporal analysis window.

        Args:
            master: The parent Tkinter window.
            get_flag_suspicious_func: Callback function (unused in current plot logic, but kept for potential future use).
            get_threshold_func: Callback function (unused in current plot logic, but kept for potential future use).
        """
        self.master = master
        self.master.title("Temporal Analysis")
        self.master.geometry("800x600") # Set a default size

        # Store callbacks (currently unused in plotting logic but kept)
        self.get_flag_suspicious_func = get_flag_suspicious_func
        self.get_threshold_func = get_threshold_func
        logger.info("Initializing Temporal Analysis window.")

        # --- Top Control Frame ---
        top_frame = tk.Frame(master)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(top_frame, text="Select Device:").pack(side=tk.LEFT)
        self.device_combo = ttk.Combobox(top_frame, values=[], state='readonly', width=30)
        self.device_combo.pack(side=tk.LEFT, padx=5)
        self.device_combo.bind("<<ComboboxSelected>>", lambda e: self.update_plot())

        self.show_protocols_var = tk.BooleanVar(value=False)
        tk.Checkbutton(top_frame, text="Show Protocol Breakdown", variable=self.show_protocols_var,
                       command=self.update_plot).pack(side=tk.LEFT, padx=5)

        # --- Matplotlib Figure and Canvas ---
        # Explicitly create figure and axes for better control
        self.fig, self.ax = plt.subplots(figsize=(8, 5)) # Adjusted size
        self.canvas = FigureCanvasTkAgg(self.fig, master=master)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Initial Setup ---
        self._update_scheduled = None
        self.refresh_devices() # Populate combobox initially
        self.update_plot() # Draw initial plot
        self.schedule_periodic_refresh() # Start periodic refresh

        # Log window closure
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Handle window closing actions."""
        logger.info("Closing Temporal Analysis window.")
        if self._update_scheduled:
            self.master.after_cancel(self._update_scheduled)
            self._update_scheduled = None
        # Clean up matplotlib resources if necessary
        plt.close(self.fig)
        self.master.destroy()

    def schedule_periodic_refresh(self):
        """Schedules the next refresh of device list and plot."""
        # Check if window exists before scheduling next update
        if self.master.winfo_exists():
            self._update_scheduled = self.master.after(30000, self.periodic_refresh) # Refresh every 30 seconds
        else:
            self._update_scheduled = None

    def refresh_devices(self):
        """Update the list of devices in the combobox."""
        logger.debug("Refreshing device list for temporal analysis.")
        try:
            with lock:
                # Get current device list safely
                devices = sorted(list(temporal_data.keys())) # Sort for consistency
            current_selection = self.device_combo.get()
            self.device_combo['values'] = devices
            # Restore selection if it still exists, otherwise select first if available
            if current_selection in devices:
                self.device_combo.set(current_selection)
            elif devices:
                self.device_combo.current(0)
                logger.info(f"Device list refreshed. Selected first device: {self.device_combo.get()}")
            else:
                self.device_combo.set('') # Clear selection if no devices
                logger.info("Device list refreshed. No devices available.")
        except Exception as e:
            logger.error(f"Error refreshing device list: {e}", exc_info=True)

    def periodic_refresh(self):
        """Periodically refresh device list and update plot."""
        logger.debug("Running periodic refresh for temporal analysis.")
        self.refresh_devices()
        self.update_plot()
        self.schedule_periodic_refresh() # Reschedule next refresh

    def update_plot(self):
        """Update the matplotlib plot based on the selected device and options."""
        device = self.device_combo.get()
        if not device:
            logger.debug("Update plot called but no device selected.")
            self.ax.clear()
            self.ax.set_title("No Device Selected")
            self.ax.set_xlabel("Time")
            self.ax.set_ylabel("Packets per Minute")
            try:
                self.canvas.draw_idle() # Use draw_idle for potentially better performance
            except tk.TclError as e:
                 logger.warning(f"TclError during canvas draw (window likely closing): {e}")
            return

        logger.info(f"Updating temporal plot for device: {device}")

        try:
            with lock:
                # Check if device exists and get a deep copy of its data to avoid race conditions
                if device not in temporal_data:
                    logger.warning(f"Device {device} not found in temporal_data during plot update.")
                    data = None
                else:
                    # Create copies of the deques to work with outside the lock
                    device_data_ref = temporal_data[device]
                    data = {
                        "minutes": list(device_data_ref.get("minutes", deque())),
                        "protocol_minutes": {k: list(v) for k, v in device_data_ref.get("protocol_minutes", {}).items()}
                    }

            self.ax.clear() # Clear previous plot

            if not data or not data["minutes"]:
                logger.info(f"No temporal data available for device: {device}")
                self.ax.set_title(f"No Data for {device}")
            else:
                minutes_data = data["minutes"]
                # 1. Extract timestamps and counts for total packets
                # Ensure data points are valid tuples
                valid_minutes_data = [m for m in minutes_data if isinstance(m, (tuple, list)) and len(m) == 2]
                if not valid_minutes_data:
                     logger.warning(f"Valid minutes_data is empty for {device}")
                     self.ax.set_title(f"No Valid Data Points for {device}")
                else:
                    times = [m[0] for m in valid_minutes_data]  # UNIX timestamps
                    counts = [m[1] for m in valid_minutes_data]
                    # Convert UNIX timestamps to local datetime objects
                    dates = [datetime.datetime.fromtimestamp(t) for t in times]

                    # 2. Plot total packets
                    self.ax.plot(dates, counts, linestyle='-', marker='o', label="Total Packets/Min", zorder=10) # Draw total on top

                    # 3. Plot protocol breakdown if enabled
                    if self.show_protocols_var.get():
                        logger.debug(f"Plotting protocol breakdown for {device}.")
                        protocol_minutes = data.get("protocol_minutes", {})
                        plotted_protocols = 0
                        for (proto, port), pdeque_list in protocol_minutes.items():
                            # Optionally skip if proto not in TRACKED_PROTOCOLS
                            if proto not in TRACKED_PROTOCOLS:
                                continue

                            valid_pdeque_list = [p for p in pdeque_list if isinstance(p, (tuple, list)) and len(p) == 2]
                            if not valid_pdeque_list:
                                continue # Skip empty or invalid protocol data

                            ptimes = [x[0] for x in valid_pdeque_list]
                            pcnts = [x[1] for x in valid_pdeque_list]
                            pdates = [datetime.datetime.fromtimestamp(t) for t in ptimes]

                            line_label = f"{proto.upper()}:{port}" if port else proto.upper()
                            self.ax.plot(pdates, pcnts, '-', label=line_label, alpha=0.7) # Use alpha for less clutter
                            plotted_protocols += 1
                        logger.debug(f"Plotted {plotted_protocols} protocols.")


                    # 4. Formatting
                    self.ax.set_title(f"Traffic for {device} (Packets per Minute)")
                    self.ax.set_xlabel("Time (Local)")
                    self.ax.set_ylabel("Packets per Minute")
                    # Improve date formatting and tick rotation
                    self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
                    self.ax.xaxis.set_major_locator(mdates.AutoDateLocator(minticks=5, maxticks=12)) # Adjust tick density
                    self.fig.autofmt_xdate(rotation=30, ha='right') # Rotate labels

                    # Add grid and legend
                    self.ax.grid(True, linestyle='--', alpha=0.6)
                    self.ax.legend(fontsize='small')

            # Ensure layout is tight
            self.fig.tight_layout()

            # Redraw the canvas
            self.canvas.draw_idle()
            logger.debug(f"Temporal plot for {device} updated successfully.")

        except Exception as e:
            logger.error(f"Error updating temporal plot for {device}: {e}", exc_info=True)
            messagebox.showerror("Plot Error", f"Could not generate plot for {device}:\n{e}")
            # Clear axes on error to avoid showing stale/broken plot
            self.ax.clear()
            self.ax.set_title(f"Error plotting data for {device}")
            try:
                self.canvas.draw_idle()
            except tk.TclError as te:
                 logger.warning(f"TclError during error canvas draw (window likely closing): {te}")

