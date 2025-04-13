# main.py
import threading
import tkinter as tk
import logging
import sys

# --- Local Imports ---
try:
    from ui.gui_main import PacketStatsGUI
except ImportError as e:
     print(f"ERROR: Failed to import GUI components: {e}", file=sys.stderr)
     sys.exit(1)
except tk.TclError as e:
     print(f"ERROR: Tkinter initialization failed: {e}", file=sys.stderr)
     sys.exit(1)

try:
    from core.capture import capture_packets, select_interfaces
    # Import DNS blocklist loaders to initialize them
    from core.dns_blocklist_integration import download_dns_blocklists, load_dns_blocklists
except ImportError as e:
     print(f"ERROR: Failed to import core components: {e}", file=sys.stderr)
     sys.exit(1)


# --- Logging Configuration ---
def setup_logging():
    """Configures basic logging for the application."""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=log_format, handlers=[logging.StreamHandler()])
    logging.info("Logging configured.")

# --- Main Application Logic ---
def main():
    """Main function to set up logging, select interfaces, start GUI and capture thread."""
    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("Starting Network Monitor application.")

    # --- Initialize DNS Blocklists (Download might be skipped if files exist) ---
    # Note: This happens before GUI starts, could add delay. Consider threading later.
    try:
        logger.info("Downloading initial DNS blocklists (if needed)...")
        download_dns_blocklists()
        logger.info("Loading initial DNS blocklists...")
        load_dns_blocklists()
        logger.info("Initial DNS blocklists processed.")
    except Exception as e:
        logger.error(f"Failed to initialize DNS blocklists: {e}", exc_info=True)
        # Decide if this is fatal or just a warning
        # messagebox.showerror("DNS Blocklist Error", f"Failed to load DNS blocklists: {e}") # Requires Tk root

    # 1. Select Interfaces
    selected_interfaces = select_interfaces()
    if not selected_interfaces:
        logger.warning("No interfaces selected or selection cancelled. Exiting.")
        print("Exiting application.")
        return

    # 2. Initialize GUI (This now also loads IP blocklists)
    try:
        root = tk.Tk()
        app = PacketStatsGUI(root)
    except Exception as e:
        logger.critical(f"Failed to initialize Tkinter GUI: {e}", exc_info=True)
        print(f"ERROR: Could not start the GUI: {e}", file=sys.stderr)
        return

    # 3. Start Packet Capture Thread
    logger.info("Creating packet capture thread...")
    capture_thread = threading.Thread(
        target=capture_packets,
        args=(selected_interfaces,),
        daemon=True
    )
    try:
        capture_thread.start()
        logger.info("Packet capture thread started.")
    except Exception as e:
        logger.critical(f"Failed to start packet capture thread: {e}", exc_info=True)
        # Need root to show messagebox here
        # messagebox.showerror("Thread Error", f"Could not start packet capture: {e}")
        print(f"ERROR: Could not start packet capture thread: {e}", file=sys.stderr)
        try: root.destroy()
        except: pass
        return

    # 4. Start Tkinter Main Loop
    logger.info("Starting Tkinter main loop...")
    try:
        root.mainloop()
    except KeyboardInterrupt:
         logger.info("KeyboardInterrupt received. Shutting down.")
    except Exception as e:
         logger.critical(f"An error occurred in the Tkinter main loop: {e}", exc_info=True)
    finally:
         logger.info("Application shutdown complete.")


if __name__ == "__main__":
    import os
    try: is_admin = os.getuid() == 0
    except AttributeError:
        try:
             import ctypes
             is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception: is_admin = False

    if not is_admin:
         print("WARNING: Packet sniffing usually requires root/administrator privileges.")
         print("The application might not be able to capture packets without them.")

    main()
