import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, send, Raw
import random
import string
import logging
from queue import Queue, Empty
import socket

# Suppress Scapy's verbose warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --- Configuration ---
# We target a public IP to ensure the traffic leaves the local machine,
# making it more likely to be captured by scapy on Windows.
TARGET_IP = "8.8.8.8"  # A public DNS server

def get_local_ip():
    """Get the local IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

SOURCE_IP = get_local_ip()

class TestingSuiteWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Detection Testing Suite")
        self.geometry("400x500")

        self.log_queue = Queue()
        self._log_update_job = None  # To hold the 'after' job ID

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, side=tk.TOP)

        log_frame = ttk.LabelFrame(main_frame, text="Status Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, side=tk.BOTTOM, pady=(10, 0))

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True)

        tests = {
            "Port Scan": self.trigger_port_scan,
            "Host Scan": self.trigger_host_scan,
            "Unsafe Protocol": self.trigger_unsafe_protocol,
            "Rate Anomaly": self.trigger_rate_anomaly,
            "Beaconing": self.trigger_beaconing,
            "DGA-like DNS": self.trigger_dga,
            "DNS Tunneling": self.trigger_dns_tunneling,
            "ICMP Tunneling": self.trigger_icmp_tunneling,
        }

        for name, command in tests.items():
            button = ttk.Button(button_frame, text=f"Trigger {name}", command=lambda c=command: self.run_in_thread(c))
            button.pack(fill=tk.X, pady=2)

        self._log_update_job = self.after(100, self.process_log_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Gracefully handle window closing."""
        if self._log_update_job:
            self.after_cancel(self._log_update_job)
            self._log_update_job = None
        self.destroy()

    def log(self, message):
        self.log_queue.put(message)

    def process_log_queue(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_text.config(state='normal')
                self.log_text.insert(tk.END, msg + '\n')
                self.log_text.config(state='disabled')
                self.log_text.see(tk.END)
        except Empty:
            pass
        finally:
            if self.winfo_exists():
                self._log_update_job = self.after(100, self.process_log_queue)

    def run_in_thread(self, target_func):
        thread = threading.Thread(target=target_func)
        thread.daemon = True
        thread.start()

    def trigger_port_scan(self):
        self.log("--- Triggering Port Scan ---")
        for port in range(1, 31):
            packet = IP(src=SOURCE_IP, dst=TARGET_IP) / TCP(dport=port, flags="S")
            send(packet, verbose=False)
        self.log("Port scan finished.")

    def trigger_host_scan(self):
        self.log("--- Triggering Host Scan ---")
        for i in range(1, 31):
            ip = f"192.168.0.{i}"
            packet = IP(src=SOURCE_IP, dst=ip) / ICMP()
            send(packet, verbose=False)
        self.log("Host scan finished.")

    def trigger_unsafe_protocol(self):
        self.log("--- Triggering Unsafe Protocol (FTP) ---")
        packet = IP(src=SOURCE_IP, dst=TARGET_IP) / TCP(dport=23, flags="S")
        send(packet, verbose=False)
        self.log("Unsafe protocol finished.")

    def trigger_rate_anomaly(self):
        self.log("--- Triggering Rate Anomaly (ICMP Flood) ---")
        for i in range(2000):
            packet = IP(src=SOURCE_IP, dst=TARGET_IP) / ICMP()
            send(packet, verbose=False)
            if (i + 1) % 200 == 0:
                self.log(f"  ...sent {i+1}/2000 packets")
        self.log("Rate anomaly finished.")

    def trigger_beaconing(self):
        self.log("--- Triggering Beaconing ---")
        for i in range(10):
            packet = IP(src=SOURCE_IP, dst="8.8.8.8") / UDP(dport=53)
            send(packet, verbose=False)
            self.log(f"  ...sent beacon {i+1}/10")
            time.sleep(5)
        self.log("Beaconing finished.")

    def trigger_dga(self):
        self.log("--- Triggering DGA-like DNS Queries ---")
        for _ in range(20):
            domain = ''.join(random.choice(string.ascii_lowercase) for _ in range(25)) + ".com"
            packet = IP(src=SOURCE_IP, dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            send(packet, verbose=False)
        self.log("DGA-like DNS queries finished.")

    def trigger_dns_tunneling(self):
        self.log("--- Triggering DNS Tunneling (High NXDOMAIN Rate) ---")
        for _ in range(20):
            # This domain should not exist and will likely result in an NXDOMAIN response
            domain = "nonexistentdomain" + ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + ".com"
            packet = IP(src=SOURCE_IP, dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            send(packet, verbose=False)
        self.log("DNS tunneling finished.")

    def trigger_icmp_tunneling(self):
        self.log("--- Triggering ICMP Tunneling (Large Payload) ---")
        payload = "This is a large payload to trigger ICMP tunneling detection." * 10
        packet = IP(src=SOURCE_IP, dst=TARGET_IP) / ICMP() / Raw(load=payload)
        send(packet, verbose=False)
        self.log("ICMP tunneling finished.")
