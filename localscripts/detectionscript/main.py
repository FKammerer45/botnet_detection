# main.py (Corrected section)
import tkinter as tk
import sys
import threading
import logging # Import standard logging library
import os # Import os for path joining if needed

# --- Setup Logging ---
# Import the config instance first
from core.config_manager import config

# Configure logging using the config object
log_level_str = config.log_level.upper() # Get level string from config
numeric_level = getattr(logging, log_level_str, logging.INFO) # Convert string to logging level

# Define log filename (potentially get from config if you add it there)
# For now, using the default mentioned in config_manager DEFAULTS example
log_filename = "network_monitor.log"
# Optional: Ensure logs go to the script's directory or a specific logs folder
# log_filepath = os.path.join(os.path.dirname(__file__), log_filename) # Example path

logging.basicConfig(
    level=numeric_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    # Use filename=log_filepath if you defined a specific path
    filename=log_filename,
    filemode='a' # Append mode ('w' would overwrite each time)
)
# Optional: Add a handler to also print logs to console (useful for debugging)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(numeric_level) # Use same level or different for console
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logging.getLogger('').addHandler(console_handler) # Add handler to root logger

logger = logging.getLogger(__name__) # Get logger for main module

# --- Now import other components ---
try:
    from core.whitelist_manager import get_whitelist
    # Import the specific functions/event needed from capture
    from core.capture import capture_packets, select_interfaces, stop_capture, capture_stop_event
    from ui.gui_main import PacketStatsGUI
except ImportError as e:
    # Log AFTER basicConfig is set up
    logger.critical(f"Failed to import core components: {e}", exc_info=True)
    print(f"ERROR: Failed to import core components: {e}")
    sys.exit(1)
except Exception as e:
    logger.critical(f"Unexpected error during initial imports: {e}", exc_info=True)
    print(f"ERROR: Unexpected error during imports: {e}")
    sys.exit(1)


def main():
    logger.info("Application starting...")

    # Load whitelist early (optional, depends if needed before GUI)
    try:
        get_whitelist() # Initialize whitelist
        logger.info("Whitelist instance created/retrieved.")
    except Exception as e:
        logger.error(f"Failed to initialize whitelist: {e}", exc_info=True)
        # Decide if this is fatal? Probably not.
        print(f"Warning: Could not initialize whitelist: {e}")

    # --- Select Interfaces ---
    selected_interfaces = select_interfaces()
    if not selected_interfaces:
        logger.warning("No interfaces selected. Exiting.")
        print("No interfaces were selected.")
        return # Exit if no interfaces chosen

    # --- Start Packet Capture Thread ---
    logger.info("Starting packet capture thread...")
    # Make the thread NOT a daemon so we can join it
    capture_thread = threading.Thread(target=capture_packets, args=(selected_interfaces,), daemon=False)
    capture_thread.start()

    # --- Initialize and Run GUI ---
    logger.info("Initializing GUI...")
    root = tk.Tk()
    try:
        app = PacketStatsGUI(root)
        logger.info("Starting Tkinter mainloop...")
        root.mainloop() # Blocks here until the main window is closed
        logger.info("Tkinter mainloop finished.")

    except Exception as e:
        logger.critical(f"Fatal error during GUI execution: {e}", exc_info=True)
        print(f"\nFATAL GUI ERROR: {e}")
    finally:
        # --- Graceful Shutdown Sequence ---
        logger.info("Initiating shutdown sequence...")

        # 1. Signal the capture thread to stop
        stop_capture()

        # 2. Wait for the capture thread to finish
        logger.info("Waiting for capture thread to join...")
        capture_thread.join(timeout=5.0) # Wait up to 5 seconds
        if capture_thread.is_alive():
            logger.warning("Capture thread did not join within timeout!")
        else:
            logger.info("Capture thread joined successfully.")

        # 3. Explicitly shut down logging (optional, do last)
        logger.info("Shutting down logging system.")
        logging.shutdown()
        print("Application finished.")


if __name__ == "__main__":
    # Basic check for admin rights (example for Windows)
    import platform
    import ctypes
    is_admin = False
    try:
        if platform.system() == "Windows":
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        elif platform.system() == "Linux" or platform.system() == "Darwin":
            # Check effective user ID (requires os module)
            import os
            is_admin = os.geteuid() == 0
    except Exception as e:
        logger.warning(f"Could not determine admin rights: {e}")
        print(f"Warning: Could not determine admin/root rights ({e}). Packet capture might fail.")

    if not is_admin:
        logger.warning("Application not running as administrator/root. Packet capture may fail.")
        print("\nWARNING: Not running as administrator/root. Packet capture might require elevated privileges.")
        # Optional: Ask user if they want to continue?
        # cont = input("Continue anyway? (y/n): ").lower()
        # if cont != 'y':
        #     sys.exit("Exiting: Run as administrator/root for packet capture.")

    main()