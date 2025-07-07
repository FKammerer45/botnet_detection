# ui/tabs/scoring_tab.py
import tkinter as tk
from tkinter import ttk

class ScoringTab:
    def __init__(self, notebook, data_manager, source_ip):
        self.frame = ttk.Frame(notebook)
        self.data_manager = data_manager
        self.source_ip = source_ip

        explanation = "Shows the threat score for this IP and a breakdown of how it was calculated."
        ttk.Label(self.frame, text=explanation, wraplength=500, justify=tk.LEFT).pack(pady=(5, 10), padx=5, anchor=tk.W)
        
        self.score_var = tk.StringVar(value="Score: 0/100")
        ttk.Label(self.frame, textvariable=self.score_var, font=("TkDefaultFont", 14, "bold")).pack(pady=5)

        columns = ("component", "points")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings")
        self.tree.heading("component", text="Detection Component")
        self.tree.heading("points", text="Points")
        self.tree.column("component", anchor=tk.W)
        self.tree.column("points", anchor=tk.CENTER, width=100)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        notebook.add(self.frame, text="Scoring")

    def update_tab(self, ip_snapshot):
        if not ip_snapshot:
            self.score_var.set("Score: N/A")
            self.tree.delete(*self.tree.get_children())
            self.tree.insert("", tk.END, values=("Source IP data unavailable", ""))
            return

        score = ip_snapshot.get("score", 0)
        self.score_var.set(f"Score: {score}/100")

        self.tree.delete(*self.tree.get_children())
        score_components = ip_snapshot.get("score_components", {})
        if not score_components:
            self.tree.insert("", tk.END, values=("No scoring components", ""))
            return
        
        for component, points in sorted(score_components.items()):
            self.tree.insert("", tk.END, values=(component, points))
