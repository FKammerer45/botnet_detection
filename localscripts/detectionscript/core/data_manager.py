# core/data_manager.py
import threading
import time
import logging
from collections import deque, defaultdict
import ipaddress # For sorting IP addresses if needed

from scapy.all import DNS # For type hinting or specific field access
import ipaddress

from .config_manager import config
from .whitelist_manager import get_whitelist
from config.globals import MAX_MINUTES_TEMPORAL
from .blocklist_integration import identify_malicious_ip, is_domain_malicious


logger = logging.getLogger(__name__)

class NetworkDataManager:
    def __init__(self):
        logger.info("Initializing NetworkDataManager.")
        self.ip_data = {}
        self.lock = threading.Lock()
        self.temporal_data = {}
        self.current_minute_data = {}
        
        self.whitelist = get_whitelist() 
        
        # Store config values directly as attributes for easier access in methods
        self.ip_data_prune_timeout = config.ip_data_prune_timeout
        self.scan_time_window = config.scan_time_window
        self.scan_distinct_ports_threshold = config.scan_distinct_ports_threshold
        self.scan_distinct_hosts_threshold = config.scan_distinct_hosts_threshold
        self.scan_check_interval = config.scan_check_interval
        self.enable_stealth_scan_detection = config.enable_stealth_scan_detection
        self.flag_internal_scans = config.flag_internal_scans
        self.flag_external_scans = config.flag_external_scans
        self.local_networks = [ipaddress.ip_network(net) for net in config.local_networks]
        self.enable_rate_anomaly_detection = config.enable_rate_anomaly_detection
        self.rate_anomaly_sensitivity = config.rate_anomaly_sensitivity
        self.rate_anomaly_min_packets = config.rate_anomaly_min_packets
        self.rate_anomaly_protocols_to_track = config.rate_anomaly_protocols_to_track
        self.enable_beaconing_detection = config.enable_beaconing_detection
        self.beaconing_interval_seconds = config.beaconing_interval_seconds
        self.beaconing_tolerance_seconds = config.beaconing_tolerance_seconds
        self.beaconing_min_occurrences = config.beaconing_min_occurrences
        self.tracked_protocols_temporal = config.tracked_protocols_temporal
        self.MAX_MINUTES_TEMPORAL = MAX_MINUTES_TEMPORAL

        _DEFAULT_DEQUE_MAXLEN = 1000
        _MAXLEN_MULTIPLIER = 1.5
        try:
            self._packet_deque_maxlen = int(config.max_packets_per_second * 60 * _MAXLEN_MULTIPLIER) if config.max_packets_per_second > 0 else _DEFAULT_DEQUE_MAXLEN
            if self._packet_deque_maxlen < _DEFAULT_DEQUE_MAXLEN:
                self._packet_deque_maxlen = _DEFAULT_DEQUE_MAXLEN
            logger.info(f"DataManager calculated timestamp deque maxlen: {self._packet_deque_maxlen}")
        except AttributeError:
            logger.error(f"DataManager: Config attribute 'max_packets_per_second' not found! Using default: {_DEFAULT_DEQUE_MAXLEN}")
            self._packet_deque_maxlen = _DEFAULT_DEQUE_MAXLEN
        except Exception as e:
            logger.error(f"DataManager: Error calculating deque maxlen: {e}. Using default: {_DEFAULT_DEQUE_MAXLEN}")
            self._packet_deque_maxlen = _DEFAULT_DEQUE_MAXLEN

    def process_packet_data(self, src_ip, dst_ip, proto_name, port_used, pkt_time, tcp_flags, is_dns_traffic, raw_pkt):
        if self.whitelist.is_ip_whitelisted(src_ip) or self.whitelist.is_ip_whitelisted(dst_ip):
            return

        with self.lock:
            if src_ip not in self.ip_data:
                 self.ip_data[src_ip] = {
                     "total": 0, "timestamps": deque(maxlen=self._packet_deque_maxlen),
                     "last_seen": 0.0, "max_per_sec": 0,
                     "destinations": defaultdict(lambda: {"total": 0, "timestamps": deque(maxlen=self._packet_deque_maxlen), "max_per_sec": 0}),
                     "protocols": defaultdict(lambda: {"total": 0, "timestamps": deque(maxlen=self._packet_deque_maxlen), "max_per_sec": 0}),
                     "malicious_hits": {}, "contacted_malicious_ip": False,
                     "suspicious_dns": [],
                     "scan_targets": defaultdict(lambda: {"ports": set(), "first_seen": 0.0, "scan_types": set()}),
                     "last_scan_check_time": 0.0,
                     "detected_scan_ports": False, "detected_scan_hosts": False,
                     "rate_anomaly_detected": False,
                     "protocol_stats": defaultdict(lambda: {"mean": 0, "std": 0, "count": 0}),
                     "beaconing_detected": False,
                     "is_malicious_source": False
                 }
            
            ip_entry = self.ip_data[src_ip]
            ip_entry["total"] += 1
            ip_entry["timestamps"].append(pkt_time)
            ip_entry["last_seen"] = pkt_time

            dest_entry = ip_entry["destinations"][dst_ip]
            dest_entry["total"] += 1
            dest_entry["timestamps"].append(pkt_time)

            proto_key = (proto_name, port_used)
            proto_entry = ip_entry["protocols"][proto_key]
            proto_entry["total"] += 1
            proto_entry["timestamps"].append(pkt_time)

            if proto_name == "tcp" and tcp_flags is not None:
                scan_target_entry = ip_entry["scan_targets"][dst_ip]
                if not scan_target_entry["first_seen"]:
                    scan_target_entry["first_seen"] = pkt_time
                if port_used is not None:
                    scan_target_entry["ports"].add(port_used)
                
                if tcp_flags.S and not tcp_flags.A:
                    scan_target_entry["scan_types"].add("SYN")
                elif self.enable_stealth_scan_detection:
                    if tcp_flags.F:
                        scan_target_entry["scan_types"].add("FIN")
                    if int(tcp_flags) == 0:
                        scan_target_entry["scan_types"].add("NULL")
                    if tcp_flags.F and tcp_flags.P and tcp_flags.U:
                        scan_target_entry["scan_types"].add("XMAS")

            if is_dns_traffic and raw_pkt.haslayer(DNS):
                dns_layer = raw_pkt[DNS]
                if dns_layer.qr == 0 and dns_layer.qdcount > 0:
                    for i in range(dns_layer.qdcount):
                        if dns_layer.qd and i < len(dns_layer.qd) and dns_layer.qd[i] is not None:
                            try:
                                qname_bytes = dns_layer.qd[i].qname
                                qname = qname_bytes.decode('utf-8', errors='ignore').rstrip('.').lower()
                                malicious_domain_info = is_domain_malicious(qname)
                                if malicious_domain_info:
                                    for list_url, description in malicious_domain_info.items():
                                        reason = f"Blocklist Hit: {description}" if description else "Blocklist Hit"
                                        ip_entry["suspicious_dns"].append({"timestamp": pkt_time, "qname": qname, "reason": reason})
                            except Exception as dns_ex:
                                logger.error(f"Error processing DNS query: {dns_ex}", exc_info=False)
            
            minute_start = int(pkt_time // 60) * 60
            if src_ip not in self.current_minute_data:
                 self.current_minute_data[src_ip] = {"start_time": minute_start, "count": 0, "protocol_count": defaultdict(int)}
            
            cdata = self.current_minute_data[src_ip]
            if cdata["start_time"] != minute_start:
                # Previous minute's data for this IP (in cdata) will be aggregated by aggregate_minute_data.
                # Re-initialize for the new current minute.
                self.current_minute_data[src_ip] = {"start_time": minute_start, "count": 0, "protocol_count": defaultdict(int)}
                cdata = self.current_minute_data[src_ip]

            cdata["count"] += 1
            tracked_key = None
            if proto_key in self.tracked_protocols_temporal: tracked_key = proto_key
            elif proto_name in self.tracked_protocols_temporal: tracked_key = proto_name
            
            if tracked_key: 
                cdata["protocol_count"][tracked_key] += 1
            elif "other" in self.tracked_protocols_temporal: 
                cdata["protocol_count"][("other", None)] += 1

    def _is_internal_ip(self, ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net in self.local_networks:
                if ip_obj in net:
                    return True
        except ValueError:
            return False
        return False

    def _check_for_scans(self, ip, ip_entry, now):
        ip_entry["detected_scan_ports"] = False
        ip_entry["detected_scan_hosts"] = False
        if self.whitelist.is_ip_whitelisted(ip):
            ip_entry["scan_targets"].clear()
            return False

        scan_window_start = now - self.scan_time_window
        detected_port_scan_flag = False
        detected_host_scan_flag = False
        unique_targets_in_window_count = 0
        
        is_source_internal = self._is_internal_ip(ip)

        dst_ips_scanned = list(ip_entry.get("scan_targets", {}).keys())
        for dst_ip in dst_ips_scanned:
            if dst_ip not in ip_entry["scan_targets"]: continue
            target_data = ip_entry["scan_targets"][dst_ip]
            first_seen_time = target_data.get("first_seen", 0)

            if first_seen_time >= scan_window_start:
                is_dest_internal = self._is_internal_ip(dst_ip)
                
                if (is_source_internal and not is_dest_internal and self.flag_external_scans) or \
                   (is_source_internal and is_dest_internal and self.flag_internal_scans) or \
                   (not is_source_internal and self.flag_external_scans):
                    unique_targets_in_window_count += 1
                    port_count = len(target_data.get("ports", set()))
                    if not detected_port_scan_flag and port_count > self.scan_distinct_ports_threshold:
                        if not self.whitelist.is_ip_whitelisted(dst_ip):
                            detected_port_scan_flag = True
            else:
                del ip_entry["scan_targets"][dst_ip]
        
        if unique_targets_in_window_count > self.scan_distinct_hosts_threshold:
            detected_host_scan_flag = True
            
        if detected_port_scan_flag: logger.warning(f"Port Scan DETECTED from {ip}")
        if detected_host_scan_flag: logger.warning(f"Host Scan DETECTED from {ip}")

        ip_entry["detected_scan_ports"] = detected_port_scan_flag
        ip_entry["detected_scan_hosts"] = detected_host_scan_flag
        ip_entry["last_scan_check_time"] = now
        return detected_port_scan_flag or detected_host_scan_flag

    def _check_for_beaconing(self, ip, ip_entry, now):
        if not self.enable_beaconing_detection:
            return

        ip_entry["beaconing_detected"] = False
        for dest_ip, dest_data in ip_entry["destinations"].items():
            if self._is_internal_ip(dest_ip) or self.whitelist.is_ip_whitelisted(dest_ip):
                continue

            timestamps = sorted(list(dest_data["timestamps"]))
            if len(timestamps) < self.beaconing_min_occurrences:
                continue

            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            if not intervals:
                continue

            mean_interval = sum(intervals) / len(intervals)
            
            if abs(mean_interval - self.beaconing_interval_seconds) <= self.beaconing_tolerance_seconds:
                # Check for consistency
                consistent_beacons = 0
                for interval in intervals:
                    if abs(interval - self.beaconing_interval_seconds) <= self.beaconing_tolerance_seconds:
                        consistent_beacons += 1
                
                if consistent_beacons + 1 >= self.beaconing_min_occurrences:
                    ip_entry["beaconing_detected"] = True
                    logger.warning(f"Beaconing DETECTED from {ip} to {dest_ip} at interval ~{mean_interval:.2f}s")
                    return # Found beaconing, no need to check other destinations

    def _check_for_rate_anomalies(self, ip, ip_entry, now):
        if not self.enable_rate_anomaly_detection:
            return

        ip_entry["rate_anomaly_detected"] = False
        for proto_key, cdata in ip_entry["protocols"].items():
            proto_name, _ = proto_key
            if proto_name not in self.rate_anomaly_protocols_to_track:
                continue

            stats = ip_entry["protocol_stats"][proto_name]
            
            # Welford's algorithm for running variance
            new_count = stats["count"] + 1
            delta = cdata["total"] - stats["mean"]
            new_mean = stats["mean"] + delta / new_count
            delta2 = cdata["total"] - new_mean
            new_m2 = stats.get("m2", 0) + delta * delta2
            
            stats["count"] = new_count
            stats["mean"] = new_mean
            stats["m2"] = new_m2

            if new_count > 1:
                variance = new_m2 / (new_count -1)
                stats["std"] = variance ** 0.5
            
            if stats["count"] > 1 and cdata["total"] > self.rate_anomaly_min_packets:
                threshold = stats["mean"] + (stats["std"] * self.rate_anomaly_sensitivity)
                if cdata["total"] > threshold:
                    ip_entry["rate_anomaly_detected"] = True
                    logger.warning(f"Rate anomaly DETECTED for {ip} on protocol {proto_name}: {cdata['total']} packets > threshold {threshold:.2f}")

    def aggregate_minute_data(self):
        now = time.time()
        current_minute_start = int(now // 60) * 60
        logger.info(f"DataManager: Running aggregate_minute_data cycle @ {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}")
        
        aggregated_count = 0
        with self.lock:
            for ip, cdata in list(self.current_minute_data.items()):
                if cdata["start_time"] < current_minute_start:
                    if ip not in self.temporal_data:
                        self.temporal_data[ip] = {"minutes": deque(maxlen=self.MAX_MINUTES_TEMPORAL), 
                                                  "protocol_minutes": defaultdict(lambda: deque(maxlen=self.MAX_MINUTES_TEMPORAL))}
                    self.temporal_data[ip]["minutes"].append((cdata["start_time"], cdata["count"]))
                    for proto_key, count_val in cdata["protocol_count"].items():
                        self.temporal_data[ip]["protocol_minutes"][proto_key].append((cdata["start_time"], count_val))
                    del self.current_minute_data[ip]
                    aggregated_count +=1
            if aggregated_count > 0: logger.info(f"DataManager: Aggregated data for {aggregated_count} IP-minute entries.")

            ips_to_prune = []
            prune_threshold_time = now - self.ip_data_prune_timeout
            for ip, ip_entry in list(self.ip_data.items()):
                if ip_entry.get("last_seen", 0) < prune_threshold_time:
                    ips_to_prune.append(ip)
                    continue
                if (now - ip_entry.get("last_scan_check_time", 0)) > self.scan_check_interval:
                     self._check_for_scans(ip, ip_entry, now)
                
                self._check_for_rate_anomalies(ip, ip_entry, now)
                self._check_for_beaconing(ip, ip_entry, now)

                source_ip_malicious_info = identify_malicious_ip(ip)
                if source_ip_malicious_info:
                    ip_entry["is_malicious_source"] = True
                    mal_hits = ip_entry.setdefault("malicious_hits", {})
                    hit_entry = mal_hits.setdefault(ip, {"blocklists": {}, "count": 0, "direction": "source"})
                    hit_entry["blocklists"].update(source_ip_malicious_info)
                    hit_entry["count"] = ip_entry.get("total", 1)
                    ip_entry["contacted_malicious_ip"] = True

                for dst_ip in list(ip_entry.get("destinations", {}).keys()):
                    dest_ip_malicious_info = identify_malicious_ip(dst_ip)
                    if dest_ip_malicious_info:
                        ip_entry["contacted_malicious_ip"] = True
                        mal_hits = ip_entry.setdefault("malicious_hits", {})
                        hit_entry = mal_hits.setdefault(dst_ip, {"blocklists": {}, "count": 0, "direction": "outbound"})
                        hit_entry["blocklists"].update(dest_ip_malicious_info)
                        if dst_ip in ip_entry.get("destinations", {}):
                            hit_entry["count"] = ip_entry["destinations"][dst_ip].get("total", hit_entry["count"])
            
            if ips_to_prune:
                for ip_to_prune in ips_to_prune:
                    if ip_to_prune in self.ip_data: del self.ip_data[ip_to_prune]
                    if ip_to_prune in self.temporal_data: del self.temporal_data[ip_to_prune]
                    if ip_to_prune in self.current_minute_data: del self.current_minute_data[ip_to_prune]
                logger.info(f"DataManager: Pruned {len(ips_to_prune)} inactive IP data entries.")
        logger.debug("DataManager: Aggregation and pruning cycle finished.")

    def get_data_for_main_table_snapshot(self, current_time, prune_seconds):
        data_snapshot = {}
        prune_timestamp = current_time - prune_seconds
        with self.lock:
            for ip, data_entry in self.ip_data.items():
                entry_copy = {
                    "total": data_entry.get("total", 0),
                    "timestamps": deque(data_entry.get("timestamps", deque())), 
                    "max_per_sec": data_entry.get("max_per_sec", 0),
                    "protocols": defaultdict(lambda: {"total": 0, "timestamps": deque(maxlen=self._packet_deque_maxlen), "max_per_sec": 0}, 
                                             {k: v.copy() for k,v in data_entry.get("protocols", {}).items()}),
                    "contacted_malicious_ip": data_entry.get("contacted_malicious_ip", False),
                    "suspicious_dns": list(data_entry.get("suspicious_dns", [])), 
                    "detected_scan_ports": data_entry.get("detected_scan_ports", False),
                    "detected_scan_hosts": data_entry.get("detected_scan_hosts", False),
                    "rate_anomaly_detected": data_entry.get("rate_anomaly_detected", False),
                    "beaconing_detected": data_entry.get("beaconing_detected", False),
                }
                while entry_copy["timestamps"] and entry_copy["timestamps"][0] < prune_timestamp:
                    entry_copy["timestamps"].popleft()
                data_snapshot[ip] = entry_copy
        return data_snapshot

    def get_full_ip_entry_snapshot(self, source_ip):
        with self.lock:
            if source_ip in self.ip_data:
                original_entry = self.ip_data[source_ip]
                entry_copy = {
                    "total": original_entry.get("total", 0),
                    "timestamps": deque(original_entry.get("timestamps", deque())),
                    "last_seen": original_entry.get("last_seen", 0.0),
                    "max_per_sec": original_entry.get("max_per_sec", 0),
                    "destinations": defaultdict(lambda: {"total": 0, "timestamps": deque(maxlen=self._packet_deque_maxlen), "max_per_sec": 0},
                                                {dst_ip: {"total": dst_data.get("total",0), 
                                                          "timestamps": deque(dst_data.get("timestamps", deque())),
                                                          "max_per_sec": dst_data.get("max_per_sec",0)}
                                                 for dst_ip, dst_data in original_entry.get("destinations", {}).items()}),
                    "protocols": defaultdict(lambda: {"total": 0, "timestamps": deque(maxlen=self._packet_deque_maxlen), "max_per_sec": 0},
                                             {proto_key: {"total": proto_data.get("total",0), 
                                                          "timestamps": deque(proto_data.get("timestamps", deque())),
                                                          "max_per_sec": proto_data.get("max_per_sec",0)}
                                              for proto_key, proto_data in original_entry.get("protocols", {}).items()}),
                    "malicious_hits": {k: v.copy() for k, v in original_entry.get("malicious_hits", {}).items()}, 
                    "contacted_malicious_ip": original_entry.get("contacted_malicious_ip", False),
                    "suspicious_dns": list(original_entry.get("suspicious_dns", [])),
                    "scan_targets": defaultdict(lambda: {"ports": set(), "first_seen": 0.0, "scan_types": set()},
                                               {dst_ip: {"ports": set(details.get("ports", set())),
                                                         "first_seen": details.get("first_seen", 0.0),
                                                         "scan_types": set(details.get("scan_types", set()))}
                                                for dst_ip, details in original_entry.get("scan_targets", {}).items()}),
                    "last_scan_check_time": original_entry.get("last_scan_check_time", 0.0),
                    "detected_scan_ports": original_entry.get("detected_scan_ports", False),
                    "rate_anomaly_detected": original_entry.get("rate_anomaly_detected", False),
                    "protocol_stats": defaultdict(lambda: {"mean": 0, "std": 0, "count": 0},
                                             {k: v.copy() for k,v in original_entry.get("protocol_stats", {}).items()}),
                    "beaconing_detected": original_entry.get("beaconing_detected", False),
                    "detected_scan_hosts": original_entry.get("detected_scan_hosts", False),
                    "is_malicious_source": original_entry.get("is_malicious_source", False)
                }
                return entry_copy
            return None

    def get_temporal_data_snapshot(self):
        with self.lock:
            temporal_data_copy = {}
            for ip, data in self.temporal_data.items():
                temporal_data_copy[ip] = {
                    "minutes": deque(data.get("minutes", deque())),
                    "protocol_minutes": defaultdict(lambda: deque(), 
                                                    {k: deque(v) for k, v in data.get("protocol_minutes", {}).items()})
                }
            return temporal_data_copy

    def get_active_ips_list(self):
        with self.lock:
            return sorted(list(self.ip_data.keys()))
