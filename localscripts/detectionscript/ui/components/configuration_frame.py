# ui/components/configuration_frame.py
import tkinter as tk
from tkinter import ttk
from core.config_manager import config
from ui.gui_tooltip import Tooltip

class ConfigurationFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        config_frame = self
        config_frame.pack(side=tk.TOP, fill=tk.X, anchor='w')
        row1_frame = tk.Frame(config_frame)
        row1_frame.pack(fill=tk.X, pady=2)
        tk.Label(row1_frame, text="Pkts/Min Threshold:").pack(side=tk.LEFT, padx=(0, 2))
        self.controller.threshold_var = tk.StringVar(value=str(config.max_packets_per_minute))
        self.controller.threshold_entry = tk.Entry(row1_frame, width=8, textvariable=self.controller.threshold_var)
        self.controller.threshold_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.controller.threshold_var.trace_add("write", self.controller.update_threshold_config)
        row2_frame = tk.Frame(config_frame)
        row2_frame.pack(fill=tk.X, pady=2)
        tk.Button(row2_frame, text="Config", command=self.controller.open_config_hub).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Temporal", command=self.controller.open_temporal_analysis).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Help", command=self.controller.open_documentation).pack(side=tk.LEFT, padx=3)
        tk.Button(row2_frame, text="Testing Suite", command=self.controller.open_testing_suite).pack(side=tk.LEFT, padx=3)

    def create_tooltip(self, widget, text):
        tooltip = Tooltip(widget, text)
        widget.bind("<Enter>", lambda event: tooltip.showtip())
        widget.bind("<Leave>", lambda event: tooltip.hidetip())
