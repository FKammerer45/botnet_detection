# gui_blocklist_manager.py
import tkinter as tk
from tkinter import messagebox
import logging # Import logging module
from core.blocklist_integration import blocklists, download_blocklists, load_blocklists

# Get a logger for this module
logger = logging.getLogger(__name__)

def apply_blocklist_changes(checkbox_vars):
    """
    Update the `blocklists` dictionary and apply changes by downloading and loading blocklists.
    """
    logger.info("Applying blocklist changes...")
    active_lists = []
    inactive_lists = []
    for blocklist, var in checkbox_vars.items():
        is_active = var.get()
        blocklists[blocklist] = is_active  # Update active/inactive status
        if is_active:
            active_lists.append(blocklist)
        else:
            inactive_lists.append(blocklist)

    logger.debug(f"Active blocklists: {active_lists}")
    logger.debug(f"Inactive blocklists: {inactive_lists}")

    # Apply changes
    try:
        download_blocklists()
        load_blocklists()
        logger.info("Blocklists downloaded and loaded successfully.")
        messagebox.showinfo("Blocklists Updated", "Blocklists have been updated and applied!")
    except Exception as e:
        logger.error(f"Error applying blocklist changes: {e}", exc_info=True)
        messagebox.showerror("Error", f"Failed to apply blocklist changes: {e}")


def add_new_blocklist(blocklist_entry, checkbox_vars, frame):
    """
    Add a new blocklist dynamically.
    """
    new_blocklist = blocklist_entry.get().strip()
    if new_blocklist:
        if new_blocklist not in blocklists:
            logger.info(f"Adding new blocklist: {new_blocklist}")
            blocklists[new_blocklist] = True  # Default active
            var = tk.BooleanVar(value=True)
            checkbox_vars[new_blocklist] = var

            # Add a new checkbox to the GUI
            tk.Checkbutton(frame, text=new_blocklist, variable=var).pack(anchor="w")
            blocklist_entry.delete(0, tk.END)
            messagebox.showinfo("Blocklist Added", f"Added blocklist: {new_blocklist}")
        else:
            logger.warning(f"Attempted to add duplicate blocklist: {new_blocklist}")
            messagebox.showwarning("Duplicate Blocklist", "This blocklist already exists.")
    else:
        logger.warning("Attempted to add an empty blocklist URL/filename.")
        messagebox.showwarning("Invalid Input", "Please enter a valid blocklist URL or filename.")


def open_blocklist_manager():
    """
    Open the blocklist manager GUI.
    """
    logger.info("Opening Blocklist Manager window.")
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
            "- Check or uncheck to activate/deactivate lists.\n"
            "- Add new lists using URLs (e.g., .netset, .txt, .csv formats supported).\n"
            "- Examples:\n"
            "  https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset\n"
            "  https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt\n"
            "  https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv\n"
            "\nClick 'Apply Changes' to download and load active lists."
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
    # Sort blocklist items for consistent display order
    sorted_blocklist_items = sorted(blocklists.items())
    for blocklist, is_active in sorted_blocklist_items:
        var = tk.BooleanVar(value=is_active)
        checkbox_vars[blocklist] = var
        tk.Checkbutton(scrollable_frame, text=blocklist, variable=var).pack(anchor="w")

    # Add blocklist entry
    add_frame = tk.Frame(blocklist_window)
    add_frame.pack(fill=tk.X, padx=10, pady=5)
    tk.Label(add_frame, text="Add URL/Path:").pack(side=tk.LEFT, padx=5)
    blocklist_entry = tk.Entry(add_frame)
    blocklist_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
    add_button = tk.Button(
        add_frame,
        text="Add",
        command=lambda: add_new_blocklist(blocklist_entry, checkbox_vars, scrollable_frame)
    )
    add_button.pack(side=tk.LEFT, padx=5)

    # Apply button
    apply_button = tk.Button(blocklist_window, text="Apply Changes", command=apply_changes)
    apply_button.pack(pady=10)

    # Add basic logging for window closure
    blocklist_window.protocol("WM_DELETE_WINDOW", lambda: (logger.info("Blocklist Manager window closed."), blocklist_window.destroy()))

