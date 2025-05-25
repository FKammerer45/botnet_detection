# ui/gui_temporal.py
import datetime
import tkinter as tk
from tkinter import ttk, messagebox
import logging
import matplotlib.dates as mdates
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import matplotlib.pyplot as plt
from collections import deque

# Import config manager and shared data/lock
from core.config_manager import config
# from core.capture import temporal_data, lock # Will be accessed via data_manager
# NetworkDataManager will be passed in via __init__

logger = logging.getLogger(__name__)

# --- Constants ---
# Define update interval in milliseconds (e.g., 1 second)
UPDATE_INTERVAL_MS = 1000
# Define refresh interval for device list (e.g., 10 seconds)
DEVICE_REFRESH_INTERVAL_MS = 10000
# --- End Constants ---

class TemporalAnalysisWindow:
    def __init__(self, master, data_manager): # Added data_manager
        """Initialize the temporal analysis window."""
        self.master = master
        self.data_manager = data_manager # Store data_manager instance
        self.master.title("Temporal Analysis")
        self.master.geometry("800x650") # Slightly increased height for toolbar
        logger.info("Initializing Temporal Analysis window.")
        self._is_closing = False # Flag to indicate if window is being closed

        # --- Top Control Frame ---
        top_frame = ttk.Frame(master, padding=(10, 5, 10, 0)) # Use ttk.Frame for consistency
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
        self.canvas_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=0) # Reduced pady

        # --- Matplotlib Navigation Toolbar ---
        toolbar_frame = ttk.Frame(master)
        toolbar_frame.pack(fill=tk.X, padx=10, pady=(0,5))
        try:
            self.toolbar = NavigationToolbar2Tk(self.canvas, toolbar_frame)
            self.toolbar.update()
        except Exception as e:
            logger.error(f"Failed to create Matplotlib navigation toolbar: {e}", exc_info=True)
            # Continue without toolbar if it fails

        # --- Status Label ---
        self.status_var = tk.StringVar(value="Ready.")
        status_label = ttk.Label(master, textvariable=self.status_var, anchor=tk.W)
        status_label.pack(fill=tk.X, padx=10, pady=(0,5))


        # --- Initial Setup ---
        self.plotter = TemporalPlotter(self.ax) # Create plotter instance
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
        if self._is_closing: # Prevent re-entry
            return
        self._is_closing = True
        logger.info("Closing Temporal Analysis window.")

        # Cancel scheduled updates
        if self._update_scheduled:
            try: 
                self.master.after_cancel(self._update_scheduled)
                logger.debug("Cancelled _update_scheduled.")
            except (tk.TclError, ValueError): 
                logger.debug("Error cancelling _update_scheduled (already cancelled/invalid).")
            self._update_scheduled = None
        if self._device_refresh_scheduled:
             try: 
                self.master.after_cancel(self._device_refresh_scheduled)
                logger.debug("Cancelled _device_refresh_scheduled.")
             except (tk.TclError, ValueError): 
                logger.debug("Error cancelling _device_refresh_scheduled (already cancelled/invalid).")
             self._device_refresh_scheduled = None
        
        # Explicitly None out Tkinter Variables before destroying master
        # This might help with their __del__ method behavior during shutdown.
        if hasattr(self, 'ip_var'):
            self.ip_var = None
            logger.debug("Set self.ip_var to None.")
        if hasattr(self, 'show_protocols_var'):
            self.show_protocols_var = None
            logger.debug("Set self.show_protocols_var to None.")

        # Close the matplotlib figure first
        if hasattr(self, 'fig'):
            try:
                plt.close(self.fig)
                logger.debug("Matplotlib figure closed.")
            except Exception as e:
                logger.warning(f"Error closing matplotlib figure: {e}")
            self.fig = None # Dereference
            self.ax = None  # Dereference axes associated with the figure

        # Destroy Matplotlib toolbar if it exists
        if hasattr(self, 'toolbar') and self.toolbar:
            try:
                self.toolbar.destroy()
                logger.debug("Matplotlib toolbar destroyed.")
            except Exception as e:
                logger.warning(f"Error destroying Matplotlib toolbar: {e}")
            self.toolbar = None

        # Destroy canvas widget
        if hasattr(self, 'canvas_widget') and self.canvas_widget:
             try:
                 self.canvas_widget.destroy()
                 logger.debug("Canvas_widget destroyed.")
             except tk.TclError:
                 logger.debug("Canvas_widget already destroyed or TclError during explicit destroy.")
             self.canvas_widget = None # Dereference
        
        if hasattr(self, 'canvas') and self.canvas: # The FigureCanvasTkAgg instance
            self.canvas = None # Dereference

        # Finally, destroy the Tkinter Toplevel window
        try:
            if self.master.winfo_exists(): 
                logger.debug("Attempting to destroy TemporalAnalysisWindow master (Toplevel).")
                self.master.destroy()
                logger.debug("TemporalAnalysisWindow master (Toplevel) destroyed.")
        except tk.TclError:
            logger.debug("TemporalAnalysisWindow master already destroyed or TclError.")
            pass


    def schedule_periodic_refresh(self):
        """Schedules the periodic refresh of the device list and plot."""
        if self._is_closing:
            return
        # Schedule device list refresh
        if self.master.winfo_exists():
             self._device_refresh_scheduled = self.master.after(DEVICE_REFRESH_INTERVAL_MS, self.refresh_ip_list)
        else:
             self._device_refresh_scheduled = None
             logger.warning("Master window does not exist in schedule_periodic_refresh for device list.")

        # Plot update is scheduled within update_plot itself.
        # This function primarily ensures the IP list refresh cycle continues.


    def refresh_ip_list(self):
        """Refreshes the list of IPs in the combobox based on available temporal data."""
        if self._is_closing or not self.master.winfo_exists():
            logger.debug("refresh_ip_list: Window closing or master destroyed, aborting.")
            if self._device_refresh_scheduled: # Ensure it's not rescheduled if we are aborting
                try: self.master.after_cancel(self._device_refresh_scheduled)
                except: pass
                self._device_refresh_scheduled = None
            return

        logger.debug("Refreshing IP list for temporal analysis.")
        # Keep track of current selection to try and preserve it
        current_selection = self.ip_var.get()
        new_values = []
        try:
            # Get all active IPs from data_manager.ip_data keys
            devices = self.data_manager.get_active_ips_list() # Use new method
            
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
            if self.master.winfo_exists() and not self._is_closing: # Check _is_closing before rescheduling
                 self._device_refresh_scheduled = self.master.after(DEVICE_REFRESH_INTERVAL_MS, self.refresh_ip_list)
            else:
                 logger.debug("Not rescheduling IP list refresh (window closing or master gone).")
                 self._device_refresh_scheduled = None


    def update_plot(self):
        """Update the matplotlib plot based on the selected IP and settings."""
        if self._is_closing or not self.master.winfo_exists(): # Check closing flag and master existence
            logger.debug("update_plot: Window closing or master destroyed, aborting.")
            if self._update_scheduled: # Ensure it's not rescheduled if we are aborting
                try: self.master.after_cancel(self._update_scheduled)
                except: pass
                self._update_scheduled = None
            return

        # --- Cancel previous update if still pending ---
        if self._update_scheduled: # This specific one is for the *plot* update loop
             try: 
                self.master.after_cancel(self._update_scheduled)
                logger.debug("Cancelled previous _update_scheduled for plot.")
             except (tk.TclError, ValueError): 
                logger.debug("Error cancelling previous _update_scheduled for plot (already cancelled/invalid).")
             self._update_scheduled = None # Clear it as we are about to run or reschedule

        # --- Basic checks before proceeding ---
        # Moved winfo_exists check to the top with _is_closing
        if not hasattr(self, 'canvas') or not self.canvas or not hasattr(self, 'ax') or not self.ax:
             logger.warning("Canvas or Axes not available, aborting plot update.")
             # Attempt to reschedule if not closing, so it might recover if canvas becomes available
             if not self._is_closing and self.master.winfo_exists():
                 self._update_scheduled = self.master.after(UPDATE_INTERVAL_MS, self.update_plot)
             return


        self.status_var.set("Updating plot...")
        ip_to_show = self.ip_var.get()

        if not ip_to_show:
            logger.debug("Update plot called, no IP selected.")
            self.plotter.plot_no_data_selected()
            self.canvas.draw_idle()
            self.status_var.set("No IP Selected. Select an IP to view data.")
        else:
            logger.info(f"Updating temporal plot for IP: {ip_to_show}")
            data_copy = None
            try:
                # Get temporal data snapshot from data_manager
                current_temporal_data = self.data_manager.get_temporal_data_snapshot()
                if ip_to_show in current_temporal_data:
                    device_data_ref = current_temporal_data[ip_to_show]
                    # The snapshot already returns deques/lists, so direct use is okay
                    data_copy = {
                        "minutes": device_data_ref.get("minutes", deque()),
                        "protocol_minutes": device_data_ref.get("protocol_minutes", {})
                    }
                else:
                    logger.warning(f"IP {ip_to_show} not found in temporal_data snapshot for plotting.")

                if data_copy and data_copy.get("minutes"): # Check if minutes list is not empty
                    self.plotter.plot_data(ip_to_show, data_copy, self.show_protocols_var.get())
                    self.status_var.set(f"Displaying data for {ip_to_show}")
                else:
                    logger.info(f"No temporal data found for IP: {ip_to_show}.")
                    self.plotter.plot_no_data_for_ip(ip_to_show)
                    self.status_var.set(f"No temporal data available for {ip_to_show}")
                
                self.canvas.draw_idle()
                logger.debug(f"Temporal plot for {ip_to_show} update cycle finished.")

            except Exception as e:
                logger.error(f"General error updating temporal plot for {ip_to_show}: {e}", exc_info=True)
                try:
                    self.plotter.plot_error_state(ip_to_show)
                    self.canvas.draw_idle()
                    self.status_var.set(f"Error updating plot for {ip_to_show}.")
                except Exception as e_draw:
                    logger.error(f"Failed to draw error state on plot: {e_draw}")
        
        # Common finally block for rescheduling
        if not self._is_closing and self.master.winfo_exists():
            self._update_scheduled = self.master.after(UPDATE_INTERVAL_MS, self.update_plot)
        else:
            logger.info("Not rescheduling plot update (window closing or master gone).")
            self._update_scheduled = None


# --- End of TemporalAnalysisWindow class ---
# --- TemporalPlotter Class (Handles actual plotting logic) ---
class TemporalPlotter:
    def __init__(self, ax):
        self.ax = ax

    def _clear_ax(self):
        self.ax.clear()
        # Reset navigation history for zoom/pan if toolbar is used
        if self.ax.get_figure().canvas.toolbar:
            self.ax.get_figure().canvas.toolbar.update()


    def plot_data(self, ip_to_show, data_copy, show_protocols):
        self._clear_ax()
        logger.debug(f"Plotter: Plotting data for {ip_to_show}, show_protocols={show_protocols}")

        minutes_data = data_copy.get("minutes", [])
        valid_minutes_data = [m for m in minutes_data if isinstance(m, (tuple, list)) and len(m) == 2]

        if not valid_minutes_data:
            logger.warning(f"Plotter: No valid total data points found for {ip_to_show}")
            self.ax.set_title(f"No Valid Data Points for {ip_to_show}")
            self.ax.set_xlabel("Time")
            self.ax.set_ylabel("Packets per Minute")
            return

        try:
            times = [m[0] for m in valid_minutes_data]
            counts = [m[1] for m in valid_minutes_data]
            dates = [datetime.datetime.fromtimestamp(t) for t in times]

            self.ax.plot(dates, counts, linestyle='-', marker='o', label="Total Packets/Min", zorder=10, color='blue')

            if show_protocols:
                protocol_minutes_data = data_copy.get("protocol_minutes", {})
                plotted_protocols_count = 0
                # Define some distinct colors for protocols
                protocol_colors = plt.cm.get_cmap('tab10', len(protocol_minutes_data) if protocol_minutes_data else 1)

                for i, (key, pdeque_list) in enumerate(protocol_minutes_data.items()):
                    label_str = "Unknown"
                    if isinstance(key, tuple) and len(key) == 2:
                        proto_name, port_num = key
                        label_str = f"{str(proto_name).upper()}:{port_num}" if port_num is not None else str(proto_name).upper()
                    elif isinstance(key, str):
                        label_str = str(key).upper()
                    else:
                        logger.warning(f"Plotter: Skipping unexpected key format in protocol_minutes: {key}")
                        continue

                    valid_pdeque_list = [p for p in pdeque_list if isinstance(p, (tuple, list)) and len(p) == 2]
                    if not valid_pdeque_list:
                        logger.debug(f"Plotter: No valid points for protocol '{label_str}' for {ip_to_show}")
                        continue

                    ptimes = [x[0] for x in valid_pdeque_list]
                    pcnts = [x[1] for x in valid_pdeque_list]
                    pdates = [datetime.datetime.fromtimestamp(t) for t in ptimes]
                    
                    self.ax.plot(pdates, pcnts, linestyle='--', marker='.', label=label_str, alpha=0.7, color=protocol_colors(i))
                    plotted_protocols_count += 1
                logger.debug(f"Plotter: Plotted breakdown for {plotted_protocols_count} protocols.")

            self.ax.set_title(f"Traffic for {ip_to_show} (Packets per Minute)")
            self.ax.set_xlabel("Time (Local)")
            self.ax.set_ylabel("Packets per Minute")
            self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            
            # Dynamic tick locator based on time range
            if dates:
                time_range_seconds = (max(times) - min(times)) if len(times) > 1 else 60
                if time_range_seconds <= 300: # 5 minutes
                    major_interval = 1
                    minor_interval = 1
                elif time_range_seconds <= 1800: # 30 minutes
                    major_interval = 5
                    minor_interval = 1
                elif time_range_seconds <= 3600 * 2: # 2 hours
                    major_interval = 15
                    minor_interval = 5
                else: # More than 2 hours
                    major_interval = 30
                    minor_interval = 10
                self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=major_interval))
                self.ax.xaxis.set_minor_locator(mdates.MinuteLocator(interval=minor_interval))

            self.ax.grid(True, linestyle=':', alpha=0.7) # Lighter grid
            self.ax.legend(loc='upper left', fontsize='x-small') # Smaller legend
            self.ax.get_figure().autofmt_xdate(rotation=25, ha='right')
            self.ax.get_figure().tight_layout() # Apply tight_layout here

        except Exception as plot_ex:
            logger.error(f"Plotter: Error during plotting data for {ip_to_show}: {plot_ex}", exc_info=True)
            self._clear_ax()
            self.ax.set_title(f"Error Plotting Data for {ip_to_show}")

    def plot_no_data_selected(self):
        self._clear_ax()
        self.ax.set_title("No IP Selected")
        self.ax.set_xlabel("Time")
        self.ax.set_ylabel("Packets per Minute")
        self.ax.get_figure().tight_layout()

    def plot_no_data_for_ip(self, ip_to_show):
        self._clear_ax()
        self.ax.set_title(f"No Temporal Data for {ip_to_show}")
        self.ax.set_xlabel("Time")
        self.ax.set_ylabel("Packets per Minute")
        self.ax.get_figure().tight_layout()

    def plot_error_state(self, ip_to_show="Selected IP"):
        self._clear_ax()
        self.ax.set_title(f"Error Updating Plot for {ip_to_show}")
        self.ax.set_xlabel("Time")
        self.ax.set_ylabel("Packets per Minute")
        self.ax.get_figure().tight_layout()

# --- End of TemporalAnalysisWindow class ---
