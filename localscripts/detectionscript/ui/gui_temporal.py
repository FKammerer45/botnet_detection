# gui_temporal.py
import datetime
import matplotlib.dates as mdates
import tkinter as tk
from tkinter import ttk
from core.capture import temporal_data, lock
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from config.globals import TRACKED_PROTOCOLS

class TemporalAnalysisWindow:
    def __init__(self, master, get_flag_suspicious_func, get_threshold_func):
        self.master = master
        self.master.title("Temporal Analysis")
        self.get_flag_suspicious_func = get_flag_suspicious_func
        self.get_threshold_func = get_threshold_func

        top_frame = tk.Frame(master)
        top_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(top_frame, text="Select Device:").pack(side=tk.LEFT)
        self.device_combo = ttk.Combobox(top_frame, values=[], state='readonly')
        self.device_combo.pack(side=tk.LEFT, padx=5)
        self.device_combo.bind("<<ComboboxSelected>>", lambda e: self.update_plot())

        self.show_protocols_var = tk.BooleanVar(value=False)
        tk.Checkbutton(top_frame, text="Show Protocol Breakdown", variable=self.show_protocols_var,
                       command=self.update_plot).pack(side=tk.LEFT, padx=5)

        self.fig, self.ax = plt.subplots(figsize=(6,3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=master)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.refresh_devices()
        self.update_plot()
        self.master.after(5000, self.periodic_refresh)

    def refresh_devices(self):
        with lock:
            devices = list(temporal_data.keys())
        self.device_combo['values'] = devices
        if devices and not self.device_combo.get():
            self.device_combo.current(0)

    def periodic_refresh(self):
        self.refresh_devices()
        self.update_plot()
        self.master.after(5000, self.periodic_refresh)

    def update_plot(self):
        device = self.device_combo.get()
        if not device:
            return

        with lock:
            if device not in temporal_data:
                self.ax.clear()
                self.ax.set_title("No Data")
                self.canvas.draw()
                return

            data = temporal_data[device]
            minutes_data = list(data["minutes"])
            threshold = self.get_threshold_func()
            flag_susp = self.get_flag_suspicious_func()

            self.ax.clear()

            if not minutes_data:
                self.ax.set_title("No Data")
                self.canvas.draw()
                return

            # 1. Extract timestamps and counts
            times = [m[0] for m in minutes_data]  # UNIX timestamps
            counts = [m[1] for m in minutes_data]

            # 2. Convert UNIX timestamps to local datetime objects
            dates = [datetime.datetime.fromtimestamp(t) for t in times]

            # 3. Plot total packets using dates as x-values
            self.ax.plot(dates, counts, linestyle='-', marker='o', label="Total Packets")

            # 4. If protocol breakdown is enabled:
            if self.show_protocols_var.get():
                for (proto, port), pdeque in data["protocol_minutes"].items():
                    # Optionally skip if proto not in TRACKED_PROTOCOLS
                    if proto not in TRACKED_PROTOCOLS:
                        continue

                    # Plot everything that’s left
                    if not pdeque:
                        continue
                    ptimes = [x[0] for x in pdeque]
                    pcnts = [x[1] for x in pdeque]
                    pdates = [datetime.datetime.fromtimestamp(t) for t in ptimes]

                    line_label = f"{proto.upper()}:{port}" if port else proto.upper()

                    # Use a single line style (or different styles if you want)
                    self.ax.plot(pdates, pcnts, '-', label=line_label)

            # 5. Format x-axis as local time
            self.ax.set_title(f"Traffic for {device} (last 24h)")
            self.ax.set_xlabel("Local Time")
            self.ax.set_ylabel("Packets per Minute")
            self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            self.fig.autofmt_xdate()

            self.ax.legend()
            self.canvas.draw()