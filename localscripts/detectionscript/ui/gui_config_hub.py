# ui/gui_config_hub.py
import tkinter as tk
from tkinter import ttk, messagebox
from core.config_manager import config
from core.blocklist_integration import download_blocklists, load_blocklists

def _parse_set(text, cast_type=str):
    raw = text.split(",") if text else []
    result = set()
    for item in raw:
        item = item.strip()
        if not item:
            continue
        try:
            result.add(cast_type(item))
        except Exception:
            continue
    return result

class ConfigHubWindow:
    """Central configuration hub with inline settings and enable checkboxes."""
    def __init__(self, master, controller):
        self.master = master
        self.controller = controller
        self.master.title("Configuration")
        # Provide a generous default size so footer buttons are visible without manual resize.
        self.master.geometry("800x640")
        self.master.minsize(760, 600)

        # Grid layout to keep footer controls visible while notebook content scrolls.
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)  # notebook grows
        self.master.rowconfigure(1, weight=0)  # status bar
        self.master.rowconfigure(2, weight=0)  # buttons

        self.notebook = ttk.Notebook(self.master)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 4))

        self._build_unsafe_tab()
        self._build_scan_tab()
        self._build_beaconing_tab()
        self._build_dns_tab()
        self._build_local_tab()
        self._build_scoring_tab()
        self._build_blocklists_tab()
        self._build_whitelist_tab()

        btn_frame = ttk.Frame(self.master)
        # Keep controls docked at the bottom so they remain visible even when content is tall.
        btn_frame.grid(row=2, column=0, sticky="ew", padx=8, pady=(4, 4))
        ttk.Button(btn_frame, text="Apply & Save", command=self.apply_and_save).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_frame, text="Close", command=self.on_close).pack(side=tk.RIGHT, padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.master, textvariable=self.status_var, anchor="w").grid(row=1, column=0, sticky="ew", padx=8, pady=(0,6))

        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_unsafe_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        self.flag_unsafe_var = self.controller.flag_unsafe_var
        ttk.Checkbutton(frame, text="Flag insecure protocols/ports", variable=self.flag_unsafe_var).pack(anchor="w")
        ttk.Label(frame, text="Unsafe ports (comma separated)").pack(anchor="w", pady=(10,0))
        self.unsafe_ports_var = tk.StringVar(value=", ".join(map(str, sorted(config.unsafe_ports))))
        ttk.Entry(frame, textvariable=self.unsafe_ports_var).pack(fill=tk.X)
        ttk.Label(frame, text="Unsafe protocols (comma separated)").pack(anchor="w", pady=(10,0))
        self.unsafe_protos_var = tk.StringVar(value=", ".join(sorted(config.unsafe_protocols)))
        ttk.Entry(frame, textvariable=self.unsafe_protos_var).pack(fill=tk.X)
        self.notebook.add(frame, text="Unsafe")

    def _build_scan_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        self.flag_scan_var = self.controller.flag_scan_var
        ttk.Checkbutton(frame, text="Flag scans in UI", variable=self.flag_scan_var).pack(anchor="w")
        self.flag_internal_var = self.controller.flag_internal_scans_var
        ttk.Checkbutton(frame, text="Flag internal scans (detection)", variable=self.flag_internal_var).pack(anchor="w")
        self.flag_external_var = self.controller.flag_external_scans_var
        ttk.Checkbutton(frame, text="Flag external scans (detection)", variable=self.flag_external_var).pack(anchor="w")

        ttk.Label(frame, text="Time window (s)").pack(anchor="w", pady=(10,0))
        self.scan_window_var = tk.StringVar(value=str(config.scan_time_window))
        ttk.Entry(frame, textvariable=self.scan_window_var).pack(fill=tk.X)

        ttk.Label(frame, text="Distinct ports threshold").pack(anchor="w", pady=(10,0))
        self.scan_ports_var = tk.StringVar(value=str(config.scan_distinct_ports_threshold))
        ttk.Entry(frame, textvariable=self.scan_ports_var).pack(fill=tk.X)

        ttk.Label(frame, text="Distinct hosts threshold").pack(anchor="w", pady=(10,0))
        self.scan_hosts_var = tk.StringVar(value=str(config.scan_distinct_hosts_threshold))
        ttk.Entry(frame, textvariable=self.scan_hosts_var).pack(fill=tk.X)

        self.flag_stealth_var = self.controller.flag_stealth_scan_var
        ttk.Checkbutton(frame, text="Enable stealth scan detection", variable=self.flag_stealth_var).pack(anchor="w", pady=(8,0))
        self.notebook.add(frame, text="Scan")

    def _build_beaconing_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        self.flag_beacon_var = self.controller.flag_beacon_enable_var
        ttk.Checkbutton(frame, text="Enable beaconing detection", variable=self.flag_beacon_var).pack(anchor="w")
        ttk.Label(frame, text="Beacon interval (s)").pack(anchor="w", pady=(10,0))
        self.beacon_interval_var = tk.StringVar(value=str(config.beaconing_interval_seconds))
        ttk.Entry(frame, textvariable=self.beacon_interval_var).pack(fill=tk.X)
        ttk.Label(frame, text="Tolerance (s)").pack(anchor="w", pady=(10,0))
        self.beacon_tolerance_var = tk.StringVar(value=str(config.beaconing_tolerance_seconds))
        ttk.Entry(frame, textvariable=self.beacon_tolerance_var).pack(fill=tk.X)
        ttk.Label(frame, text="Min occurrences").pack(anchor="w", pady=(10,0))
        self.beacon_min_var = tk.StringVar(value=str(config.beaconing_min_occurrences))
        ttk.Entry(frame, textvariable=self.beacon_min_var).pack(fill=tk.X)
        self.notebook.add(frame, text="Beaconing")

    def _build_dns_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        self.flag_dns_analysis_var = self.controller.flag_dns_analysis_enable_var
        ttk.Checkbutton(frame, text="Enable DNS analysis", variable=self.flag_dns_analysis_var).pack(anchor="w")
        ttk.Label(frame, text="DGA entropy threshold").pack(anchor="w", pady=(10,0))
        self.dga_entropy_var = tk.StringVar(value=str(config.dga_entropy_threshold))
        ttk.Entry(frame, textvariable=self.dga_entropy_var).pack(fill=tk.X)
        ttk.Label(frame, text="DGA length threshold").pack(anchor="w", pady=(10,0))
        self.dga_length_var = tk.StringVar(value=str(config.dga_length_threshold))
        ttk.Entry(frame, textvariable=self.dga_length_var).pack(fill=tk.X)
        ttk.Label(frame, text="NXDOMAIN rate threshold").pack(anchor="w", pady=(10,0))
        self.nx_rate_var = tk.StringVar(value=str(config.nxdomain_rate_threshold))
        ttk.Entry(frame, textvariable=self.nx_rate_var).pack(fill=tk.X)
        ttk.Label(frame, text="NXDOMAIN min count").pack(anchor="w", pady=(10,0))
        self.nx_min_var = tk.StringVar(value=str(config.nxdomain_min_count))
        ttk.Entry(frame, textvariable=self.nx_min_var).pack(fill=tk.X)
        self.notebook.add(frame, text="DNS")

    def _build_local_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        self.flag_arp_var = self.controller.flag_arp_enable_var
        ttk.Checkbutton(frame, text="Enable ARP spoof detection", variable=self.flag_arp_var).pack(anchor="w")
        self.flag_icmp_var = self.controller.flag_icmp_enable_var
        ttk.Checkbutton(frame, text="Enable ICMP anomaly detection", variable=self.flag_icmp_var).pack(anchor="w")
        self.flag_local_threat_var = self.controller.flag_local_threat_var
        ttk.Checkbutton(frame, text="Flag local threats in UI", variable=self.flag_local_threat_var).pack(anchor="w", pady=(6,0))
        ttk.Label(frame, text="ICMP ping sweep threshold").pack(anchor="w", pady=(10,0))
        self.icmp_ping_var = tk.StringVar(value=str(config.icmp_ping_sweep_threshold))
        ttk.Entry(frame, textvariable=self.icmp_ping_var).pack(fill=tk.X)
        ttk.Label(frame, text="ICMP large payload threshold").pack(anchor="w", pady=(10,0))
        self.icmp_large_var = tk.StringVar(value=str(config.icmp_large_payload_threshold))
        ttk.Entry(frame, textvariable=self.icmp_large_var).pack(fill=tk.X)
        ttk.Label(frame, text="Local networks (CIDR, comma separated)").pack(anchor="w", pady=(10,0))
        self.local_networks_var = tk.StringVar(value=", ".join(sorted(config.local_networks)))
        ttk.Entry(frame, textvariable=self.local_networks_var).pack(fill=tk.X)
        self.notebook.add(frame, text="Local Net")

    def _build_scoring_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        ttk.Label(frame, text="Score threshold").pack(anchor="w")
        self.score_threshold_var = tk.StringVar(value=str(config.score_threshold))
        ttk.Entry(frame, textvariable=self.score_threshold_var).pack(fill=tk.X)

        # UI flag toggles
        self.flag_malicious_var = self.controller.flag_malicious_var
        ttk.Checkbutton(frame, text="Flag malicious IPs in UI", variable=self.flag_malicious_var).pack(anchor="w", pady=(8,0))
        self.flag_dns_var = self.controller.flag_dns_var
        ttk.Checkbutton(frame, text="Flag malicious DNS in UI", variable=self.flag_dns_var).pack(anchor="w")
        self.flag_ja3_var = self.controller.flag_ja3_var
        ttk.Checkbutton(frame, text="Flag JA3/JA3S hits in UI", variable=self.flag_ja3_var).pack(anchor="w")
        self.flag_rate_anomaly_var = self.controller.flag_rate_anomaly_var
        ttk.Checkbutton(frame, text="Flag rate anomalies in UI", variable=self.flag_rate_anomaly_var).pack(anchor="w")

        fields = [
            ("ARP spoof", "score_arp_spoof"),
            ("ICMP ping sweep", "score_icmp_ping_sweep"),
            ("ICMP tunneling", "score_icmp_tunneling"),
            ("Beaconing", "score_c2_beaconing"),
            ("JA3 hit", "score_ja3_hit"),
            ("DGA", "score_dga"),
            ("DNS tunneling", "score_dns_tunneling"),
            ("IP blocklist", "score_ip_blocklist"),
            ("DNS blocklist", "score_dns_blocklist"),
            ("Port scan", "score_port_scan"),
            ("Host scan", "score_host_scan"),
            ("Rate anomaly", "score_rate_anomaly"),
            ("Unsafe protocol", "score_unsafe_protocol"),
        ]
        self.score_vars = {}
        for label, attr in fields:
            ttk.Label(frame, text=label).pack(anchor="w", pady=(8,0))
            var = tk.StringVar(value=str(getattr(config, attr)))
            ttk.Entry(frame, textvariable=var).pack(fill=tk.X)
            self.score_vars[attr] = var
        self.notebook.add(frame, text="Scoring")

    def _build_blocklists_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        ttk.Label(frame, text="Manage active blocklists. Check to enable for next run.").pack(anchor="w")
        self.blocklist_vars = {}
        self.blocklist_section_frames = {}

        def build_section(parent, title, data_dict, list_type):
            lf = ttk.LabelFrame(parent, text=title, padding=6)
            lf.pack(fill=tk.BOTH, expand=True, pady=4)
            canvas = tk.Canvas(lf, height=140)
            scrollbar = ttk.Scrollbar(lf, orient="vertical", command=canvas.yview)
            inner = ttk.Frame(canvas)
            inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.create_window((0, 0), window=inner, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            self.blocklist_section_frames[list_type] = inner
            for url, desc in data_dict.items():
                var = tk.BooleanVar(value=True)
                self.blocklist_vars[url] = (var, list_type, desc)
                display = f"{url} ({desc})" if desc else url
                ttk.Checkbutton(inner, text=display, variable=var).pack(anchor="w", pady=1)

        build_section(frame, "IP Blocklists", config.ip_blocklist_urls, "ip")
        build_section(frame, "DNS Blocklists", config.dns_blocklist_urls, "dns")
        build_section(frame, "JA3 Blocklists", config.ja3_blocklist_urls, "ja3")
        build_section(frame, "JA3S Blocklists", config.ja3s_blocklist_urls, "ja3s")

        add_frame = ttk.LabelFrame(frame, text="Add blocklist", padding=6)
        add_frame.pack(fill=tk.X, pady=6)
        ttk.Label(add_frame, text="URL").grid(row=0, column=0, sticky="w")
        self.new_bl_url = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.new_bl_url).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Label(add_frame, text="Description").grid(row=1, column=0, sticky="w")
        self.new_bl_desc = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.new_bl_desc).grid(row=1, column=1, sticky="ew", padx=4)
        ttk.Label(add_frame, text="Type").grid(row=2, column=0, sticky="w")
        self.new_bl_type = tk.StringVar(value="IP")
        ttk.Combobox(add_frame, textvariable=self.new_bl_type, values=["IP", "DNS", "JA3", "JA3S"], state="readonly", width=6).grid(row=2, column=1, sticky="w", padx=4)
        add_frame.columnconfigure(1, weight=1)
        ttk.Button(add_frame, text="Add to list", command=self._add_blocklist_entry).grid(row=3, column=1, sticky="e", pady=4)

        update_frame = ttk.Frame(frame)
        update_frame.pack(fill=tk.X, pady=(4,0))
        ttk.Label(update_frame, text="Update interval (hours, 0=disable):").pack(side=tk.LEFT)
        self.block_update_interval_var = tk.StringVar(value=str(config.blocklist_update_interval_hours))
        ttk.Entry(update_frame, textvariable=self.block_update_interval_var, width=6).pack(side=tk.LEFT, padx=4)
        self.notebook.add(frame, text="Blocklists")

    def _add_blocklist_entry(self):
        url = (self.new_bl_url.get() or "").strip()
        desc = (self.new_bl_desc.get() or "").strip()
        list_type = (self.new_bl_type.get() or "ip").lower()
        if not url:
            messagebox.showwarning("Input Error", "URL cannot be empty.", parent=self.master)
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            messagebox.showwarning("Input Error", "URL must start with http:// or https://", parent=self.master)
            return
        if url in self.blocklist_vars:
            messagebox.showinfo("Duplicate", "This URL already exists in the list.", parent=self.master)
            return
        var = tk.BooleanVar(value=True)
        self.blocklist_vars[url] = (var, list_type, desc)
        inner = self.blocklist_section_frames.get(list_type)
        if inner:
            display = f"{url} ({desc})" if desc else url
            ttk.Checkbutton(inner, text=display, variable=var).pack(anchor="w", pady=1)
        # clear inputs
        self.new_bl_url.set("")
        self.new_bl_desc.set("")

    def _build_whitelist_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        ttk.Label(frame, text="Whitelist is managed via whitelist.txt and the Whitelist Manager.").pack(anchor="w")
        self.notebook.add(frame, text="Whitelist")

    def apply_and_save(self):
        try:
            # Unsafe
            config.unsafe_ports = _parse_set(self.unsafe_ports_var.get(), int)
            config.unsafe_protocols = _parse_set(self.unsafe_protos_var.get(), str)
            # Scan
            config.scan_time_window = int(float(self.scan_window_var.get()))
            config.scan_distinct_ports_threshold = int(self.scan_ports_var.get())
            config.scan_distinct_hosts_threshold = int(self.scan_hosts_var.get())
            config.enable_stealth_scan_detection = self.flag_stealth_var.get()
            config.flag_internal_scans = self.flag_internal_var.get()
            config.flag_external_scans = self.flag_external_var.get()
            # Beaconing
            config.enable_beaconing_detection = self.flag_beacon_var.get()
            # Keep controller vars in sync
            self.controller.flag_beacon_enable_var.set(config.enable_beaconing_detection)
            config.beaconing_interval_seconds = int(float(self.beacon_interval_var.get()))
            config.beaconing_tolerance_seconds = int(float(self.beacon_tolerance_var.get()))
            config.beaconing_min_occurrences = int(self.beacon_min_var.get())
            # DNS
            config.enable_dns_analysis = self.flag_dns_analysis_var.get()
            self.controller.flag_dns_analysis_enable_var.set(config.enable_dns_analysis)
            config.dga_entropy_threshold = float(self.dga_entropy_var.get())
            config.dga_length_threshold = int(self.dga_length_var.get())
            config.nxdomain_rate_threshold = float(self.nx_rate_var.get())
            config.nxdomain_min_count = int(self.nx_min_var.get())
            # Local
            config.enable_arp_spoof_detection = self.flag_arp_var.get()
            self.controller.flag_arp_enable_var.set(config.enable_arp_spoof_detection)
            config.enable_icmp_anomaly_detection = self.flag_icmp_var.get()
            self.controller.flag_icmp_enable_var.set(config.enable_icmp_anomaly_detection)
            config.icmp_ping_sweep_threshold = int(self.icmp_ping_var.get())
            config.icmp_large_payload_threshold = int(self.icmp_large_var.get())
            config.local_networks = _parse_set(self.local_networks_var.get(), str)
            # Scoring
            config.score_threshold = int(self.score_threshold_var.get())
            for attr, var in self.score_vars.items():
                setattr(config, attr, int(var.get()))
            # Scan flags
            config.enable_stealth_scan_detection = self.flag_stealth_var.get()
            config.flag_internal_scans = self.flag_internal_var.get()
            config.flag_external_scans = self.flag_external_var.get()
            self.controller.flag_stealth_scan_var.set(config.enable_stealth_scan_detection)
            self.controller.flag_internal_scans_var.set(config.flag_internal_scans)
            self.controller.flag_external_scans_var.set(config.flag_external_scans)
            # Blocklists
            new_ip = {}
            new_dns = {}
            new_ja3 = {}
            new_ja3s = {}
            for url, (var, list_type, desc) in self.blocklist_vars.items():
                if not var.get():
                    continue
                if list_type == "ip":
                    new_ip[url] = desc
                elif list_type == "dns":
                    new_dns[url] = desc
                elif list_type == "ja3":
                    new_ja3[url] = desc
                elif list_type == "ja3s":
                    new_ja3s[url] = desc
            config.ip_blocklist_urls = new_ip
            config.dns_blocklist_urls = new_dns
            config.ja3_blocklist_urls = new_ja3
            config.ja3s_blocklist_urls = new_ja3s
            config.blocklist_update_interval_hours = int(float(self.block_update_interval_var.get()))
            config.save_config()
            try:
                download_blocklists(force_download=True)
                load_blocklists()
                self.status_var.set("Saved and blocklists reloaded.")
            except Exception:
                self.status_var.set("Saved. Blocklist reload failed; check logs.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply configuration:\n{e}", parent=self.master)
            self.status_var.set("Error applying settings.")

    def on_close(self):
        try:
            if self.master.winfo_exists():
                self.master.destroy()
        except tk.TclError:
            pass

    def _resize_to_tab(self):
        """Resize window to fit current tab content."""
        try:
            self.master.update_idletasks()
            current = self.notebook.select()
            if not current:
                return
            tab_widget = self.notebook.nametowidget(current)
            req_w = tab_widget.winfo_reqwidth()
            req_h = tab_widget.winfo_reqheight()
            # Account for notebook chrome, buttons, status bar, and padding
            total_w = max(req_w + 120, 820)
            total_h = max(req_h + 320, 700)
            self.master.geometry(f"{total_w}x{total_h}")
        except Exception:
            pass
