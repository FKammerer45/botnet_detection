#gui_blocklist_manager.py
import tkinter as tk
from tkinter import messagebox
from core.blocklist_integration import blocklists, download_blocklists, load_blocklists

def apply_blocklist_changes(checkbox_vars):
    """
    Update the `blocklists` dictionary and apply changes by downloading and loading blocklists.
    """
    for blocklist, var in checkbox_vars.items():
        blocklists[blocklist] = var.get()  # Update active/inactive status

    # Apply changes
    download_blocklists()
    load_blocklists()

    messagebox.showinfo("Blocklists Updated", "Blocklists have been updated and applied!")


def add_new_blocklist(blocklist_entry, checkbox_vars, frame):
    """
    Add a new blocklist dynamically.
    """
    new_blocklist = blocklist_entry.get().strip()
    if new_blocklist:
        if new_blocklist not in blocklists:
            blocklists[new_blocklist] = True  # Default active
            var = tk.BooleanVar(value=True)
            checkbox_vars[new_blocklist] = var

            # Add a new checkbox to the GUI
            tk.Checkbutton(frame, text=new_blocklist, variable=var).pack(anchor="w")
            blocklist_entry.delete(0, tk.END)
            messagebox.showinfo("Blocklist Added", f"Added blocklist: {new_blocklist}")
        else:
            messagebox.showwarning("Duplicate Blocklist", "This blocklist already exists.")
    else:
        messagebox.showwarning("Invalid Input", "Please enter a valid blocklist URL or filename.")


def open_blocklist_manager():
    """
    Open the blocklist manager GUI.
    """
    def apply_changes():
        apply_blocklist_changes(checkbox_vars)

    # Create the blocklist manager window
    blocklist_window = tk.Toplevel()
    blocklist_window.title("Blocklist Manager")
    blocklist_window.geometry("700x600")

    # Add an explanation at the top
    explanation_label = tk.Label(
        blocklist_window,
        text=(
            "Manage your blocklists below.\n"
            "- `.netset` files can be sourced from: https://raw.githubusercontent.com/firehol/blocklist-ipsets/master\n"
            "- `.txt` or `.csv` links are supported as long as they match the correct format.\n"
            "  Example: https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt\n"
            "  Example: https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv\n"
            "\nSelect blocklists to activate or deactivate them, or add new blocklists via the input field."
        ),
        wraplength=680,
        justify="left",
        fg="blue"
    )
    explanation_label.pack(pady=10, padx=10)

    # Frame for checkboxes
    checkbox_frame = tk.Frame(blocklist_window)
    checkbox_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # Scrollable canvas for many blocklists
    canvas = tk.Canvas(checkbox_frame)
    scrollbar = tk.Scrollbar(checkbox_frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    # Checkboxes for blocklists
    checkbox_vars = {}
    for blocklist, is_active in blocklists.items():
        var = tk.BooleanVar(value=is_active)
        checkbox_vars[blocklist] = var
        tk.Checkbutton(scrollable_frame, text=blocklist, variable=var).pack(anchor="w")

    # Add blocklist entry
    blocklist_entry = tk.Entry(blocklist_window, width=50)
    blocklist_entry.pack(pady=5)
    add_button = tk.Button(
        blocklist_window,
        text="Add Blocklist",
        command=lambda: add_new_blocklist(blocklist_entry, checkbox_vars, scrollable_frame)
    )
    add_button.pack(pady=5)

    # Apply button
    apply_button = tk.Button(blocklist_window, text="Apply Changes", command=apply_changes)
    apply_button.pack(pady=10)
