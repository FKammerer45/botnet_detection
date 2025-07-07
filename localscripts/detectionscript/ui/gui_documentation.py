# ui/gui_documentation.py
import tkinter as tk
from tkinter import ttk, font
import os
import markdown2
from PIL import Image, ImageTk
from tkhtmlview import HTMLLabel

class DocumentationWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Documentation")
        self.geometry("800x600")

        self.docs_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..","..", "docs"))
        self.assets_path = os.path.join(self.docs_path, "assets")

        self.paned_window = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        self.tree_frame = ttk.Frame(self.paned_window, width=200)
        self.paned_window.add(self.tree_frame, weight=1)

        self.text_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.text_frame, weight=3)

        self.tree = ttk.Treeview(self.tree_frame)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        self.html_label = HTMLLabel(self.text_frame, html="<h1>Welcome to the Documentation</h1>")
        self.html_label.pack(fill=tk.BOTH, expand=True)
        self.html_label.fit_height()

        self.populate_tree()

    def populate_tree(self):
        for section in os.listdir(self.docs_path):
            if os.path.isdir(os.path.join(self.docs_path, section)) and section != "assets":
                section_node = self.tree.insert("", "end", text=section.replace("_", " ").title(), open=True)
                for doc in os.listdir(os.path.join(self.docs_path, section)):
                    if doc.endswith(".md"):
                        self.tree.insert(section_node, "end", text=doc.replace(".md", "").replace("_", " ").title(), values=[os.path.join(self.docs_path, section, doc)])

    def on_tree_select(self, event):
        selected_item = self.tree.selection()[0]
        filepath = self.tree.item(selected_item, "values")
        if filepath:
            self.display_markdown(filepath[0])

    def display_markdown(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                md_content = f.read()
            html_content = markdown2.markdown(md_content, extras=["fenced-code-blocks", "tables", "cuddled-lists", "markdown-in-html", "smarty-pants"])
            self.html_label.set_html(html_content)
        except Exception as e:
            self.html_label.set_html(f"<h1>Error</h1><p>Error loading documentation file: {e}</p>")
