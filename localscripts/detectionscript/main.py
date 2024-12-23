import threading
import tkinter as tk
from core.capture import capture_packets
from ui.gui_main import PacketStatsGUI

def main():
    root = tk.Tk()
    app = PacketStatsGUI(root)
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    root.mainloop()

if __name__ == "__main__":
    main()