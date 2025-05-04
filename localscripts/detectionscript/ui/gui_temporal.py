# ui/gui_temporal.py
import datetime
import tkinter as tk
from tkinter import ttk, messagebox
import logging
import matplotlib.dates as mdates
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import deque

# Import config manager and shared data/lock
from core.config_manager import config
from core.capture import temporal_data, lock

logger = logging.getLogger(__name__)

# --- Constants ---
# Define update interval in milliseconds (e.g., 1 second)
UPDATE_INTERVAL_MS = 1000
# Define refresh interval for device list (e.g., 10 seconds)
DEVICE_REFRESH_INTERVAL_MS = 10000
# --- End Constants ---

class TemporalAnalysisWindow:
    def __init__(self, master):
        """Initialize the temporal analysis window."""
        self.master = master
        self.master.title("Temporal Analysis")
        self.master.geometry("800x600")
        logger.info("Initializing Temporal Analysis window.")

        # --- Top Control Frame ---
        top_frame = tk.Frame(master)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(top_frame, text="Select IP:").pack(side=tk.LEFT) # Changed label
        # Use StringVar for easier getting/setting
        self.ip_var = tk.StringVar()
        self.ip_combo = ttk.Combobox(top_frame, textvariable=self.ip_var, values=[], state='readonly', width=30)
        self.ip_combo.pack(side=tk.LEFT, padx=5)
        self.ip_combo.bind("<<ComboboxSelected>>", lambda event: self.update_plot()) # Trigger plot update on selection

        self.show_protocols_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top_frame, text="Show Protocol Breakdown", variable=self.show_protocols_var, command=self.update_plot).pack(side=tk.LEFT, padx=5)

        # --- Matplotlib Figure and Canvas ---
        # Create figure and axes
        try:
            # Use constrained_layout for better spacing
            self.fig, self.ax = plt.subplots(figsize=(8, 5), constrained_layout=True)
        except Exception as e:
             logger.error(f"Error creating Matplotlib figure: {e}", exc_info=True)
             messagebox.showerror("Plot Error", f"Failed to create plot figure:\n{e}")
             self.master.destroy() # Close window if plot fails critically
             return

        # Embed the plot in the Tkinter window
        self.canvas = FigureCanvasTkAgg(self.fig, master=master)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Initial Setup ---
        self._update_scheduled = None # Handle for periodic plot update
        self._device_refresh_scheduled = None # Handle for periodic device list refresh
        self.refresh_ip_list() # Populate the combobox initially
        self.update_plot() # Draw the initial plot (likely empty)
        self.schedule_periodic_refresh() # Start periodic refreshes
        # Set window close handler
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
        logger.info("Temporal Analysis window initialized.")


    def on_close(self):
        """Handle window closing gracefully."""
        logger.info("Closing Temporal Analysis window.")
        # Cancel scheduled updates
        if self._update_scheduled:
            try: self.master.after_cancel(self._update_scheduled)
            except (tk.TclError, ValueError): pass # Ignore errors if already cancelled/invalid
            self._update_scheduled = None
        if self._device_refresh_scheduled:
             try: self.master.after_cancel(self._device_refresh_scheduled)
             except (tk.TclError, ValueError): pass
             self._device_refresh_scheduled = None

        # Close the matplotlib figure
        try:
             plt.close(self.fig)
             logger.debug("Matplotlib figure closed.")
        except Exception as e:
             logger.warning(f"Error closing matplotlib figure: {e}")

        # Explicitly destroy canvas widget first (Might help release some resources earlier)
        if hasattr(self, 'canvas_widget') and self.canvas_widget:
             try:
                 logger.debug("Attempting to destroy canvas_widget.")
                 self.canvas_widget.destroy()
                 logger.debug("Canvas_widget destroyed.")
             except tk.TclError:
                 logger.debug("Canvas_widget already destroyed or TclError.")
                 pass # Ignore if already gone or error during destroy

        # Destroy the Tkinter window (master for this specific window)
        try:
            if self.master.winfo_exists(): # Check if it exists before destroying
                logger.debug("Attempting to destroy TemporalAnalysisWindow master.")
                self.master.destroy()
                logger.debug("TemporalAnalysisWindow master destroyed.")
        except tk.TclError:
            logger.debug("TemporalAnalysisWindow master already destroyed or TclError.")
            pass


    def schedule_periodic_refresh(self):
        """Schedules the periodic refresh of the device list and plot."""
        # Schedule device list refresh
        if self.master.winfo_exists():
             self._device_refresh_scheduled = self.master.after(DEVICE_REFRESH_INTERVAL_MS, self.refresh_ip_list)
        else:
             self._device_refresh_scheduled = None

        # Schedule plot update (more frequent) - Handled within update_plot itself
        # This function only needs to schedule the *next* refresh_ip_list


    def refresh_ip_list(self):
        """Refreshes the list of IPs in the combobox based on available temporal data."""
        logger.debug("Refreshing IP list for temporal analysis.")
        # Keep track of current selection to try and preserve it
        current_selection = self.ip_var.get()
        new_values = []
        try:
            with lock:
                # Get IPs that have temporal data
                devices = sorted(list(temporal_data.keys()))
            # Always include "All Traffic" option? Or only if protocols are tracked?
            # For now, let's just use IPs with data.
            new_values = devices

            # Update combobox values
            self.ip_combo['values'] = new_values

            # Restore selection if possible, otherwise select first or clear
            if current_selection in new_values:
                self.ip_var.set(current_selection)
            elif new_values:
                self.ip_var.set(new_values[0]) # Select the first IP if previous gone
                logger.info(f"IP list refreshed. Auto-selected: {self.ip_var.get()}")
            else:
                self.ip_var.set('') # Clear selection if no IPs have data
                logger.info("IP list refreshed. No IPs with temporal data found.")

        except Exception as e:
            logger.error(f"Error refreshing IP list: {e}", exc_info=True)
        finally:
            # Trigger a plot update after refreshing the list (if selection changed/cleared)
            # The <<ComboboxSelected>> binding handles user changes, this handles programmatic ones
            if self.ip_var.get() != current_selection or not new_values:
                 self.update_plot()
            # Reschedule the next IP list refresh cycle
            if self.master.winfo_exists():
                 self._device_refresh_scheduled = self.master.after(DEVICE_REFRESH_INTERVAL_MS, self.refresh_ip_list)
            else:
                 self._device_refresh_scheduled = None


    def update_plot(self):
        """Update the matplotlib plot based on the selected IP and settings."""
        # --- Cancel previous update if still pending ---
        # (This helps prevent stacking updates if plotting takes longer than interval)
        if self._update_scheduled:
             try: self.master.after_cancel(self._update_scheduled)
             except (tk.TclError, ValueError): pass
             self._update_scheduled = None

        # --- Basic checks before proceeding ---
        try:
            if not self.master.winfo_exists():
                logger.warning("Temporal window closed, aborting plot update.")
                return
            if not hasattr(self, 'canvas') or not self.canvas or not hasattr(self, 'ax') or not self.ax:
                 logger.warning("Canvas or Axes not available, aborting plot update.")
                 return
        except tk.TclError: # Catch if master check fails during shutdown
             logger.warning("Temporal window likely closing, aborting plot update.")
             return


        ip_to_show = self.ip_var.get()
        if not ip_to_show:
            logger.debug("Update plot called, no IP selected.")
            try:
                self.ax.clear()
                self.ax.set_title("No IP Selected")
                self.ax.set_xlabel("Time")
                self.ax.set_ylabel("Packets per Minute")
                self.canvas.draw_idle()
            except Exception as e: # Catch broader errors during clear/draw
                logger.warning(f"Error drawing 'No IP Selected' plot: {e}")
            finally:
                # Still schedule next attempt even if current draw fails
                if self.master.winfo_exists(): self._update_scheduled = self.master.after(UPDATE_INTERVAL_MS, self.update_plot)
            return

        logger.info(f"Updating temporal plot for IP: {ip_to_show}")
        data_copy = None # To store thread-safe copy of data
        try:
            # --- Get data safely ---
            with lock:
                if ip_to_show not in temporal_data:
                    logger.warning(f"IP {ip_to_show} not found in temporal_data.")
                    data_copy = None # No data available
                else:
                    # Create deep copies of the deques (as lists) to work with outside the lock
                    device_data_ref = temporal_data[ip_to_show]
                    data_copy = {
                        "minutes": list(device_data_ref.get("minutes", deque())),
                        "protocol_minutes": {
                            k: list(v) for k, v in device_data_ref.get("protocol_minutes", {}).items()
                        }
                    }
            # --- End lock ---

            # --- Clear and prepare axes ---
            self.ax.clear()

            # --- Plotting logic ---
            if not data_copy or not data_copy.get("minutes"):
                logger.info(f"No temporal data found for IP: {ip_to_show} after copying.")
                self.ax.set_title(f"No Temporal Data for {ip_to_show}")
            else:
                # Plot total packets per minute
                minutes_data = data_copy["minutes"]
                # Ensure data points are valid tuples/lists of length 2
                valid_minutes_data = [m for m in minutes_data if isinstance(m, (tuple, list)) and len(m) == 2]

                if not valid_minutes_data:
                    logger.warning(f"No valid total data points found for {ip_to_show}")
                    self.ax.set_title(f"No Valid Data Points for {ip_to_show}")
                else:
                    try:
                        times = [m[0] for m in valid_minutes_data] # Timestamps
                        counts = [m[1] for m in valid_minutes_data] # Counts
                        dates = [datetime.datetime.fromtimestamp(t) for t in times]

                        # Plot the main "Total Packets" line
                        self.ax.plot(dates, counts, linestyle='-', marker='o', label="Total Packets/Min", zorder=10) # Draw total on top

                        # Plot protocol breakdown if requested
                        if self.show_protocols_var.get():
                            logger.debug(f"Plotting protocol breakdown for {ip_to_show}.")
                            protocol_minutes_data = data_copy.get("protocol_minutes", {})
                            plotted_protocols_count = 0

                            # --- CORRECTED LOOP FOR PROTOCOL BREAKDOWN ---
                            for key, pdeque_list in protocol_minutes_data.items():
                                proto_name, port_num = None, None
                                label_str = "Unknown"

                                # Check if the key is a tuple (proto, port) or just a string (proto)
                                if isinstance(key, tuple) and len(key) == 2:
                                    proto_name, port_num = key
                                    # Format label, ensure proto_name is string
                                    label_str = f"{str(proto_name).upper()}:{port_num}" if port_num is not None else str(proto_name).upper()
                                elif isinstance(key, str): # Handle case where key is just the protocol name string
                                    proto_name = key
                                    port_num = None # Assume no specific port
                                    label_str = str(proto_name).upper()
                                else:
                                    logger.warning(f"Skipping unexpected key format in protocol_minutes: {key}")
                                    continue # Skip this key if format is wrong

                                # Ensure protocol data points are valid
                                valid_pdeque_list = [p for p in pdeque_list if isinstance(p, (tuple, list)) and len(p) == 2]
                                if not valid_pdeque_list:
                                    logger.debug(f"No valid points for protocol '{label_str}' for {ip_to_show}")
                                    continue # Skip if no valid points for this protocol

                                ptimes = [x[0] for x in valid_pdeque_list]
                                pcnts = [x[1] for x in valid_pdeque_list]
                                pdates = [datetime.datetime.fromtimestamp(t) for t in ptimes]

                                # Plot the line for this protocol
                                self.ax.plot(pdates, pcnts, linestyle='-', marker='.', label=label_str, alpha=0.8) # Use different marker/alpha
                                plotted_protocols_count += 1
                            # --- END CORRECTED LOOP ---
                            logger.debug(f"Plotted breakdown for {plotted_protocols_count} protocols.")

                        # --- Configure Axes Appearance ---
                        self.ax.set_title(f"Traffic for {ip_to_show} (Packets per Minute)")
                        self.ax.set_xlabel("Time (Local)")
                        self.ax.set_ylabel("Packets per Minute")
                        # Format x-axis dates
                        self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M')) # Show Hour:Minute
                        interval_minutes = 10 # Example: tick every 10 minutes
                        self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=interval_minutes))
                        self.ax.xaxis.set_minor_locator(mdates.MinuteLocator(interval=5)) # Minor ticks every 5 mins? Adjust as needed
                        # Add grid and legend
                        self.ax.grid(True, linestyle='--', alpha=0.6)
                        self.ax.legend(loc='upper left', fontsize='small')
                        # Rotate date labels slightly
                        self.fig.autofmt_xdate(rotation=30, ha='right')

                    except Exception as plot_ex:
                         logger.error(f"Error during plotting data section for {ip_to_show}: {plot_ex}", exc_info=True)
                         self.ax.clear() # Clear axes on error
                         self.ax.set_title(f"Error Plotting Data for {ip_to_show}")


            # --- Final draw and reschedule (outside main data processing) ---
            # Use tight_layout to prevent labels overlapping
            self.fig.tight_layout()
            # Redraw the canvas
            self.canvas.draw_idle()
            logger.debug(f"Temporal plot for {ip_to_show} update cycle finished.")

        except Exception as e:
            # Catch broad errors during the entire update process
            logger.error(f"General error updating temporal plot for {ip_to_show}: {e}", exc_info=True)
            try:
                 # Try to display an error message on the plot
                 self.ax.clear()
                 self.ax.set_title(f"Error updating plot for {ip_to_show}")
                 self.canvas.draw_idle()
            except Exception as e_draw:
                 logger.error(f"Failed to draw error state on plot: {e_draw}")
                 # Avoid further errors if canvas/ax is broken
        finally:
            # --- Reschedule the next plot update (CRITICAL for loop) ---
            # Add extra safety checks before rescheduling
            try:
                 if self.master.winfo_exists() and hasattr(self, 'canvas') and self.canvas:
                     self._update_scheduled = self.master.after(UPDATE_INTERVAL_MS, self.update_plot)
                 else:
                      logger.info("Temporal window closed or canvas invalid, stopping plot updates.")
                      self._update_scheduled = None # Ensure handle is cleared
            except Exception as e_reschedule:
                 logger.error(f"Error rescheduling temporal plot update: {e_reschedule}")
                 self._update_scheduled = None # Stop trying if rescheduling fails
# --- End of TemporalAnalysisWindow class ---