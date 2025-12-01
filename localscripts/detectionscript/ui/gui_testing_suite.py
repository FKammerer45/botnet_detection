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
import ctypes
import platform
from core.config_manager import config

# Suppress Scapy's verbose warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --- Configuration ---
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
        self._shutdown = False

        self.log_queue = Queue()
        self._log_update_job = None  # To hold the 'after' job ID

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, side=tk.TOP)

        # Target configuration
        target_frame = ttk.LabelFrame(main_frame, text="Targets", padding="5")
        target_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(target_frame, text="Public target IP:").grid(row=0, column=0, sticky="w")
        self.target_ip_var = tk.StringVar(value="8.8.8.8")
        ttk.Entry(target_frame, textvariable=self.target_ip_var, width=14).grid(row=0, column=1, padx=5)
        ttk.Label(target_frame, text="LAN prefix (e.g., 192.168.0)").grid(row=1, column=0, sticky="w")
        self.lan_prefix_var = tk.StringVar(value="192.168.0")
        ttk.Entry(target_frame, textvariable=self.lan_prefix_var, width=14).grid(row=1, column=1, padx=5)
        ttk.Label(target_frame, text="Hosts to scan:").grid(row=2, column=0, sticky="w")
        self.lan_hosts_var = tk.IntVar(value=30)
        ttk.Entry(target_frame, textvariable=self.lan_hosts_var, width=8).grid(row=2, column=1, padx=5, sticky="w")
        ttk.Label(target_frame, text="Beacon interval (s):").grid(row=3, column=0, sticky="w")
        self.beacon_interval_var = tk.DoubleVar(value=float(config.beaconing_interval_seconds))
        ttk.Entry(target_frame, textvariable=self.beacon_interval_var, width=10).grid(row=3, column=1, padx=5, sticky="w")

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

        self._check_privileges()
        self._log_update_job = self.after(100, self.process_log_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Gracefully handle window closing."""
        self._shutdown = True
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

    def _log_error(self, message, exc=None):
        if exc:
            logging.exception(message)
        self.log(f"ERROR: {message}")

    def _safe_send(self, pkt, desc="packet"):
        """Send a packet, logging any errors but not raising to the UI thread."""
        try:
            send(pkt, verbose=False)
        except PermissionError as e:
            self._log_error(f"Permission denied while sending {desc} (run as admin/root). {e}")
        except Exception as e:
            self._log_error(f"Failed to send {desc}: {e}")

    def _get_target_ip(self):
        val = self.target_ip_var.get().strip() or "8.8.8.8"
        return val

    def _check_privileges(self):
        try:
            is_admin = False
            if platform.system() == "Windows":
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                is_admin = (hasattr(os, "geteuid") and os.geteuid() == 0)
            if not is_admin:
                self.log("Warning: Not running as administrator/root. Packet send/capture may fail.")
        except Exception:
            self.log("Warning: Could not determine privilege level. Ensure admin/root for reliable sending.")

    def trigger_port_scan(self):
        self.log("--- Triggering Port Scan ---")
        target_ip = self._get_target_ip()
        for port in range(1, 31):
            packet = IP(src=SOURCE_IP, dst=target_ip) / TCP(dport=port, flags="S")
            self._safe_send(packet, f"port-scan packet dport {port}")
        self.log("Port scan finished.")

    def trigger_host_scan(self):
        self.log("--- Triggering Host Scan ---")
        prefix = self.lan_prefix_var.get().strip() or "192.168.0"
        host_count = max(1, min(254, self.lan_hosts_var.get() or 30))
        for i in range(1, host_count + 1):
            ip = f"{prefix}.{i}"
            packet = IP(src=SOURCE_IP, dst=ip) / ICMP()
            self._safe_send(packet, f"host-scan ICMP to {ip}")
        self.log("Host scan finished.")

    def trigger_unsafe_protocol(self):
        self.log("--- Triggering Unsafe Protocol (FTP) ---")
        packet = IP(src=SOURCE_IP, dst=self._get_target_ip()) / TCP(dport=23, flags="S")
        self._safe_send(packet, "unsafe protocol TCP/23")
        self.log("Unsafe protocol finished.")

    def trigger_rate_anomaly(self):
        self.log("--- Triggering Rate Anomaly (ICMP Flood) ---")
        for i in range(2000):
            packet = IP(src=SOURCE_IP, dst=self._get_target_ip()) / ICMP()
            self._safe_send(packet, "ICMP flood packet")
            if (i + 1) % 200 == 0:
                self.log(f"  ...sent {i+1}/2000 packets")
        self.log("Rate anomaly finished.")

    def trigger_beaconing(self):
        self.log("--- Triggering Beaconing ---")
        interval = max(0.5, float(self.beacon_interval_var.get() or 5.0))
        occurrences = max(config.beaconing_min_occurrences, 5)
        for i in range(occurrences):
            if self._shutdown:
                self.log("Beaconing cancelled.")
                break
            packet = IP(src=SOURCE_IP, dst=self._get_target_ip()) / UDP(dport=53)
            self._safe_send(packet, "beacon UDP/53")
            self.log(f"  ...sent beacon {i+1}/{occurrences}")
            time.sleep(interval)
        self.log("Beaconing finished.")

    def trigger_dga(self):
        self.log("--- Triggering DGA-like DNS Queries ---")
        for _ in range(20):
            domain = ''.join(random.choice(string.ascii_lowercase) for _ in range(25)) + ".com"
            packet = IP(src=SOURCE_IP, dst=self._get_target_ip()) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            self._safe_send(packet, f"DGA DNS query {domain}")
        self.log("DGA-like DNS queries finished.")

    def trigger_dns_tunneling(self):
        self.log("--- Triggering DNS Tunneling (High NXDOMAIN Rate) ---")
        for _ in range(20):
            # This domain should not exist and will likely result in an NXDOMAIN response
            domain = "nonexistentdomain" + ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + ".com"
            packet = IP(src=SOURCE_IP, dst=self._get_target_ip()) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            self._safe_send(packet, f"NXDOMAIN DNS query {domain}")
        self.log("DNS tunneling finished.")

    def trigger_icmp_tunneling(self):
        self.log("--- Triggering ICMP Tunneling (Large Payload) ---")
        payload = "This is a large payload to trigger ICMP tunneling detection." * 10
        packet = IP(src=SOURCE_IP, dst=self._get_target_ip()) / ICMP() / Raw(load=payload)
        self._safe_send(packet, "ICMP tunnel payload")
        self.log("ICMP tunneling finished.")
