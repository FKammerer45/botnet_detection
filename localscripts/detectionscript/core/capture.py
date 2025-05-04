# core/capture.py
import time
import threading
import logging
from collections import deque, defaultdict
import platform
import ipaddress
import socket
import sys # Added for SystemExit

# Third-party imports

from scapy.all import sniff, IP, TCP, UDP, Ether, IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.config import conf as scapy_conf
from scapy.arch import get_if_list, get_if_hwaddr
if platform.system() == "Windows":
    from scapy.arch.windows import get_windows_if_list # Keep this for potential detailed listing

import psutil



# Local imports
from core.config_manager import config # Use the singleton config instance
from core.whitelist_manager import get_whitelist # Use the singleton whitelist instance
from core.blocklist_integration import identify_malicious_ip, is_domain_malicious
from config.globals import MAX_MINUTES_TEMPORAL # Get maxlen for temporal data

logger = logging.getLogger(__name__)
whitelist = get_whitelist() # Get the singleton instance

# --- Configuration Derived Constants (Example - adjust as needed) ---
# Define defaults in case config access fails or for clarity
_DEFAULT_DEQUE_MAXLEN = 1000
_MAXLEN_MULTIPLIER = 1.5 # Allow deque to hold more than strictly 1 min worth

# Calculate a reasonable max deque length based on config's packets_per_second limit
# This tries to prevent unbounded memory growth for timestamps deques
try:
    # Estimate max packets in 60 seconds, add buffer. Use the CORRECT config attribute.
    _packet_deque_maxlen = int(config.max_packets_per_second * 60 * _MAXLEN_MULTIPLIER) if config.max_packets_per_second > 0 else _DEFAULT_DEQUE_MAXLEN
    # Ensure it's at least the default minimum size
    if _packet_deque_maxlen < _DEFAULT_DEQUE_MAXLEN:
        _packet_deque_maxlen = _DEFAULT_DEQUE_MAXLEN
    logger.info(f"Calculated timestamp deque maxlen: {_packet_deque_maxlen}")
except AttributeError:
     logger.error(f"Config attribute 'max_packets_per_second' not found! Using default deque maxlen: {_DEFAULT_DEQUE_MAXLEN}")
     _packet_deque_maxlen = _DEFAULT_DEQUE_MAXLEN
except Exception as e:
     logger.error(f"Error calculating deque maxlen: {e}. Using default: {_DEFAULT_DEQUE_MAXLEN}")
     _packet_deque_maxlen = _DEFAULT_DEQUE_MAXLEN
# --- End Configuration Derived Constants ---


# --- Global Data Structures (Thread Safety Critical) ---
# Main dictionary holding data per source IP
ip_data = {}
# Lock for thread-safe access to shared data (ip_data, temporal_data, current_minute_data)
lock = threading.Lock()
# Dictionary for aggregated temporal data (per source IP)
temporal_data = {}
# Dictionary for currently accumulating minute data (per source IP)
current_minute_data = {}

capture_stop_event = threading.Event()
# --- End Global Data Structures ---


# --- Packet Processing Callback ---
def packet_callback(pkt):
    """
    Processes individual packets captured by Scapy.
    Extracts relevant information and updates shared data structures.
    Must be thread-safe regarding access to shared data.
    """
    # Log summary of *every* packet received by callback for deep debugging
    # logger.debug(f"Packet received by callback: {pkt.summary()}")

    # --- Basic Packet Validation ---
    # Check for Ethernet layer first
    if not Ether in pkt:
        # logger.debug("Packet ignored (Not Ethernet)") # Too verbose usually
        return
    # Check for IP layer (IPv4 or IPv6)
    is_ipv4 = IP in pkt
    is_ipv6 = IPv6 in pkt # Check for IPv6
    if not is_ipv4 and not is_ipv6:
        logger.debug(f"Packet ignored (No IP layer): {pkt.summary()}")
        return

    try:
        # --- Extract Core IP Information ---
        now = time.time()
        if is_ipv4:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_num = pkt[IP].proto # Protocol number
        else: # IPv6
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto_num = pkt[IPv6].nh # Next Header (equivalent to protocol)

        # --- Whitelist Check (Critical for Performance/Filtering) ---
        # Check both source and destination against IP/Network whitelist
        src_whitelisted = whitelist.is_ip_whitelisted(src_ip)
        dst_whitelisted = whitelist.is_ip_whitelisted(dst_ip)
        if src_whitelisted or dst_whitelisted:
            reason = f"{'src' if src_whitelisted else ''}{' and ' if src_whitelisted and dst_whitelisted else ''}{'dst' if dst_whitelisted else ''}"
            # Log at INFO level for visibility during troubleshooting
        
            return # Stop processing this packet

        # If we reach here, the packet involves non-whitelisted IPs
        logger.debug(f"Processing packet: {src_ip} -> {dst_ip}")

        # --- Protocol and Port Identification ---
        proto_name = "other"
        src_port = None
        dst_port = None
        port_used = None # Destination port is usually most relevant
        is_dns_traffic = False
        tcp_flags = None

        # Map common protocol numbers to names
        protocol_map = {1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'icmpv6'} # Added ICMPv6

        if proto_num in protocol_map:
            proto_name = protocol_map[proto_num]
            # Extract ports for TCP/UDP
            if proto_name == 'tcp' and TCP in pkt:
                tcp_layer = pkt[TCP]
                src_port, dst_port = tcp_layer.sport, tcp_layer.dport
                tcp_flags = tcp_layer.flags
                port_used = dst_port
                is_dns_traffic = (src_port == 53 or dst_port == 53)
            elif proto_name == 'udp' and UDP in pkt:
                udp_layer = pkt[UDP]
                src_port, dst_port = udp_layer.sport, udp_layer.dport
                port_used = dst_port
                is_dns_traffic = (src_port == 53 or dst_port == 53)
            # Note: ICMP/ICMPv6 don't have ports in the same way
        else:
            # Try to get name from Scapy if not in our map
            if is_ipv4:
                proto_name_scapy = pkt[IP].sprintf("%IP.proto%")
            else:
                proto_name_scapy = pkt[IPv6].sprintf("%IPv6.nh%") # Use NextHeader name
            # Use Scapy name if it's not just a number, otherwise format it
            proto_name = proto_name_scapy.lower() if not proto_name_scapy.isdigit() else f"other({proto_num})"

        # --- Update Data Structures (CRITICAL SECTION - REQUIRES LOCK) ---
        with lock:
            # Initialize entry for source IP if it's the first time we see it
            if src_ip not in ip_data:
                 logger.debug(f"Initializing data structures for new source IP: {src_ip}")
                 ip_data[src_ip] = {
                     "total": 0, # Total packets from this source
                     "timestamps": deque(maxlen=_packet_deque_maxlen), # Timestamps for rate calculation
                     "last_seen": 0.0, # Timestamp of the last packet seen
                     "max_per_sec": 0, # Max packets/sec observed
                     # Data per destination contacted by this source
                     "destinations": defaultdict(lambda: {"total": 0, "timestamps": deque(maxlen=_packet_deque_maxlen), "max_per_sec": 0}),
                     # Data per protocol/port used by this source
                     "protocols": defaultdict(lambda: {"total": 0, "timestamps": deque(maxlen=_packet_deque_maxlen), "max_per_sec": 0}),
                     # Details of malicious IPs contacted (key=mal_ip, value=details)
                     "malicious_hits": {},
                     "contacted_malicious_ip": False, # Flag if source contacted any malicious IP
                     # Details of suspicious DNS queries made
                     "suspicious_dns": [],
                     # Data for SYN scan detection (key=dst_ip, value=details)
                     "syn_targets": defaultdict(lambda: {"ports": set(), "first_syn_time": 0.0}),
                     "last_scan_check_time": 0.0, # When scan check was last performed
                     "detected_scan_ports": False, # Flag: Port scan detected from this source
                     "detected_scan_hosts": False, # Flag: Host scan detected from this source
                     "is_malicious_source": False # Flag if the source IP itself is on a blocklist
                 }

            # Get the entry for the current source IP
            ip_entry = ip_data[src_ip]

            # --- Update General IP Stats ---
            ip_entry["total"] += 1
            ip_entry["timestamps"].append(now)
            ip_entry["last_seen"] = now

            # --- Update Destination Stats ---
            # defaultdict handles creation of destination entry if it's new
            dest_entry = ip_entry["destinations"][dst_ip]
            dest_entry["total"] += 1
            dest_entry["timestamps"].append(now)

            # --- Update Protocol/Port Stats ---
            # Use (protocol_name, destination_port) as the key
            proto_key = (proto_name, port_used)
            # defaultdict handles creation of protocol entry if it's new
            proto_entry = ip_entry["protocols"][proto_key]
            proto_entry["total"] += 1
            proto_entry["timestamps"].append(now)

            # --- Specific Logic Updates (Still under lock) ---

            # 1. SYN Scan Detection Input: Log SYN packets
            # Check for TCP SYN flag set, but ACK flag not set
            if proto_name == "tcp" and tcp_flags is not None and tcp_flags.S and not tcp_flags.A:
                # defaultdict handles creation of SYN target entry if it's new
                syn_target_entry = ip_entry["syn_targets"][dst_ip]
                # Record time of first SYN seen for this source->dest pair (within current tracking window)
                if not syn_target_entry["first_syn_time"]:
                    syn_target_entry["first_syn_time"] = now
                # Add the destination port to the set of ports scanned for this target
                if port_used is not None:
                    syn_target_entry["ports"].add(port_used)
                    logger.debug(f"SYN packet logged for scan detection: {src_ip} -> {dst_ip}:{port_used}")

            # 2. DNS Query Processing: Check suspicious domains
            if is_dns_traffic and pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                # qr=0 means it's a query, qdcount > 0 means there's at least one question
                if dns_layer.qr == 0 and dns_layer.qdcount > 0:
                    # Iterate through questions in the query (usually just 1)
                    for i in range(dns_layer.qdcount):
                        # Safely access the question record
                        if dns_layer.qd and i < len(dns_layer.qd) and dns_layer.qd[i] is not None:
                            try:
                                # Decode query name, remove trailing dot, lowercase
                                qname_bytes = dns_layer.qd[i].qname
                                qname = qname_bytes.decode('utf-8', errors='ignore').rstrip('.').lower()
                                logger.debug(f"DNS Query observed: {src_ip} requested '{qname}'")

                                # Check domain against blocklist (this function respects domain whitelist)
                                if is_domain_malicious(qname):
                                    logger.warning(f"Malicious DNS Query DETECTED: {src_ip} -> '{qname}' (BLOCKLIST HIT)")
                                    # Append details to the source IP's record
                                    ip_entry["suspicious_dns"].append({
                                        "timestamp": now,
                                        "qname": qname,
                                        "reason": "Blocklist Hit"
                                    })
                            except IndexError:
                                logger.warning(f"Index error accessing DNS question {i} from {src_ip}")
                            except Exception as dns_ex:
                                # Log errors during DNS parsing, but don't stop processing other packets
                                logger.error(f"Error processing DNS query record for '{qname_bytes}': {dns_ex}", exc_info=False)
                        else:
                             logger.debug(f"Malformed/empty DNS question record index {i} from {src_ip}")


            # 3. Temporal Data Update (Tracking packets per minute)
            minute_start = int(now // 60) * 60 # Integer timestamp for the start of the current minute

            # Initialize per-minute counter for this IP if it's the first packet seen
            if src_ip not in current_minute_data:
                 current_minute_data[src_ip] = {"start_time": minute_start, "count": 0, "protocol_count": defaultdict(int)}

            cdata = current_minute_data[src_ip]

            # Check if the packet belongs to the currently tracked minute for this IP
            if cdata["start_time"] == minute_start:
                cdata["count"] += 1 # Increment total count for the minute
                # Check if the specific protocol/port or generic protocol is tracked
                tracked_key = None
                if proto_key in config.tracked_protocols_temporal:
                    tracked_key = proto_key
                elif proto_name in config.tracked_protocols_temporal:
                     tracked_key = proto_name # Track by protocol name if specific port isn't listed
                # Increment count for the tracked protocol/port
                if tracked_key:
                     cdata["protocol_count"][tracked_key] += 1
                # Increment 'other' count if this packet isn't specifically tracked but 'other' is
                elif "other" in config.tracked_protocols_temporal:
                     cdata["protocol_count"][("other", None)] += 1
            else:
                 # Packet belongs to a *new* minute. The old minute's data will be aggregated
                 # by the separate 'aggregate_minute_data' function soon.
                 # Start counting for the new minute immediately.
                 logger.debug(f"New minute {minute_start} started for {src_ip}. Initializing counters.")
                 # Create new entry for the new minute
                 current_minute_data[src_ip] = {"start_time": minute_start, "count": 1, "protocol_count": defaultdict(int)}
                 # Add the current packet to the new minute's count
                 cdata_new = current_minute_data[src_ip]
                 tracked_key_new = None
                 if proto_key in config.tracked_protocols_temporal: tracked_key_new = proto_key
                 elif proto_name in config.tracked_protocols_temporal: tracked_key_new = proto_name
                 if tracked_key_new: cdata_new["protocol_count"][tracked_key_new] += 1
                 elif "other" in config.tracked_protocols_temporal: cdata_new["protocol_count"][("other", None)] += 1

        # --- End of Critical Section (Lock Released) ---

    except AttributeError as ae:
         # Catch errors if packet structure is unexpected (e.g., missing layers/fields)
         logger.warning(f"Packet attribute error processing packet: {ae} - Summary: {pkt.summary()}", exc_info=False)
    except Exception as e:
        # Catch any other unforeseen errors during packet processing
        logger.error(f"Unhandled error in packet_callback: {e}", exc_info=True)
# --- End Packet Processing Callback ---


# --- Scan Detection Logic ---
def check_for_scans(ip, ip_entry, now):
    """
    Analyzes SYN packet data for a given source IP to detect potential
    port scans or host scans based on configurable thresholds.

    Args:
        ip (str): The source IP address being checked.
        ip_entry (dict): The data dictionary for the source IP from ip_data.
        now (float): The current timestamp.

    Returns:
        bool: True if a scan (port or host) was detected, False otherwise.
              Also updates 'detected_scan_ports' and 'detected_scan_hosts' flags
              within the ip_entry dictionary.
    """
    # Ensure flags are reset at the beginning of the check
    ip_entry["detected_scan_ports"] = False
    ip_entry["detected_scan_hosts"] = False

    # 1. Check if the source IP itself is whitelisted
    if whitelist.is_ip_whitelisted(ip):
        logger.debug(f"Scan check skipped (whitelisted source): {ip}")
        # Clear potentially old scan data if IP just became whitelisted
        ip_entry["syn_targets"].clear()
        return False # No scan detected for whitelisted sources

    # 2. Get configuration thresholds
    scan_window_start = now - config.scan_time_window
    distinct_ports_threshold = config.scan_distinct_ports_threshold
    distinct_hosts_threshold = config.scan_distinct_hosts_threshold

    # 3. Initialize detection flags and counters for this check cycle
    detected_port_scan_flag = False
    detected_host_scan_flag = False
    unique_targets_in_window_count = 0 # Count unique destination IPs with recent SYNs

    # 4. Iterate over SYN targets recorded for this source IP
    # Iterate over a copy of keys as we might delete expired entries
    dst_ips_synced = list(ip_entry.get("syn_targets", {}).keys())

    for dst_ip in dst_ips_synced:
        # Check if entry still exists (might rarely be removed by pruning?)
        if dst_ip not in ip_entry["syn_targets"]:
             continue

        target_data = ip_entry["syn_targets"][dst_ip]
        first_syn_time = target_data.get("first_syn_time", 0)

        # 5. Check if SYN target is within the time window
        if first_syn_time >= scan_window_start:
            # This destination IP was contacted within the scan window
            unique_targets_in_window_count += 1
            port_count = len(target_data.get("ports", set()))

            # 6. Check for Port Scan criteria
            # If we haven't already detected a port scan from this source in this cycle...
            # And the number of distinct ports to this *single* destination exceeds the threshold...
            if not detected_port_scan_flag and port_count > distinct_ports_threshold:
                # And the *destination* IP is NOT whitelisted...
                if not whitelist.is_ip_whitelisted(dst_ip):
                    logger.warning(f"Port Scan DETECTED: {ip} -> {dst_ip} ({port_count} distinct ports > {distinct_ports_threshold} threshold in {config.scan_time_window}s)")
                    detected_port_scan_flag = True # Set flag for this cycle
                else:
                    # Log if high port count seen but destination is whitelisted
                    logger.debug(f"High port count ({port_count}) from {ip} to {dst_ip} ignored (whitelisted destination).")
        else:
            # 7. Prune Expired SYN Target: Entry is older than the scan window
            logger.debug(f"Removing expired SYN target record: {ip} -> {dst_ip} (first SYN @ {first_syn_time} is older than window start {scan_window_start})")
            del ip_entry["syn_targets"][dst_ip]

    # 8. Check for Host Scan criteria
    # If the number of *unique destination IPs* contacted within the window exceeds the threshold
    if unique_targets_in_window_count > distinct_hosts_threshold:
        logger.warning(f"Host Scan DETECTED: {ip} contacted {unique_targets_in_window_count} distinct hosts > {distinct_hosts_threshold} threshold in {config.scan_time_window}s)")
        detected_host_scan_flag = True

    # 9. Update the main flags in the shared ip_data structure
    ip_entry["detected_scan_ports"] = detected_port_scan_flag
    ip_entry["detected_scan_hosts"] = detected_host_scan_flag
    # Record the time this check was performed for rate limiting future checks
    ip_entry["last_scan_check_time"] = now

    # Return overall scan status for this check
    return detected_port_scan_flag or detected_host_scan_flag
# --- End Scan Detection Logic ---


# --- Data Aggregation and Pruning ---
def aggregate_minute_data():
    """
    Periodically called (e.g., every minute) to:
    1. Aggregate counts from `current_minute_data` into `temporal_data`.
    2. Perform checks on `ip_data` (scans, malicious hits).
    3. Prune inactive entries from `ip_data`, `temporal_data`, `current_minute_data`.
    Requires lock for safe access to shared data structures.
    """
    now = time.time()
    current_minute_start = int(now // 60) * 60 # Start timestamp of the current minute
    logger.debug(f"Running data aggregation cycle @ {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}")

    ips_to_prune = [] # List of IPs to remove at the end
    # Calculate cutoff time for pruning based on configured timeout
    prune_threshold_time = now - config.ip_data_prune_timeout

    # --- CRITICAL SECTION - REQUIRES LOCK ---
    with lock:
        # --- 1. Aggregate Completed Minute Counters ---
        # Iterate over a copy of keys in case dict changes (shouldn't with lock, but safer)
        minute_data_keys = list(current_minute_data.keys())
        for ip in minute_data_keys:
            # Check if IP still exists in the dictionary
            if ip not in current_minute_data:
                continue

            # Get the data accumulated for this IP in the 'current' tracker
            cdata = current_minute_data[ip]

            # If the data belongs to a minute *before* the currently starting one, aggregate it
            if cdata["start_time"] < current_minute_start:
                logger.debug(f"Aggregating completed minute {cdata['start_time']} data for IP: {ip}")

                # Ensure the IP has an entry in the main temporal data store
                if ip not in temporal_data:
                    temporal_data[ip] = {
                        "minutes": deque(maxlen=MAX_MINUTES_TEMPORAL),
                        "protocol_minutes": defaultdict(lambda: deque(maxlen=MAX_MINUTES_TEMPORAL))
                    }

                # Append (timestamp, total_count) tuple for the completed minute
                timestamp = cdata["start_time"]
                total_count = cdata["count"]
                temporal_data[ip]["minutes"].append((timestamp, total_count))

                # Append counts for tracked protocols during that minute
                for proto_key, count in cdata["protocol_count"].items():
                    temporal_data[ip]["protocol_minutes"][proto_key].append((timestamp, count))

                # Remove the aggregated minute data from the 'current' tracker
                del current_minute_data[ip]
            # else: Data is for the current minute, leave it to continue accumulating

        # --- 2. Perform Checks and Pruning Preparation on Main ip_data ---
        # Iterate over a copy of keys
        ip_data_keys = list(ip_data.keys())
        for ip in ip_data_keys:
            # Check if IP still exists
            if ip not in ip_data:
                continue

            ip_entry = ip_data[ip]

            # --- 2a. Pruning Check: Mark inactive IPs for removal ---
            if ip_entry.get("last_seen", 0) < prune_threshold_time:
                ips_to_prune.append(ip)
                logger.debug(f"Marking IP {ip} for pruning (last seen: {ip_entry.get('last_seen', 0)} < {prune_threshold_time})")
                continue # Skip other checks if we're going to prune this IP

            # --- 2b. Scan Check (Rate Limited) ---
            # Check if enough time has passed since the last scan check for this IP
            time_since_last_scan = now - ip_entry.get("last_scan_check_time", 0)
            # Use a configurable interval to avoid checking too frequently
            if time_since_last_scan > config.scan_check_interval:
                 logger.debug(f"Performing scan check for {ip} (last check {time_since_last_scan:.1f}s ago)")
                 # This function handles source whitelist check internally and updates ip_entry flags
                 check_for_scans(ip, ip_entry, now)
            # else: logger.debug(f"Skipping scan check for {ip} (checked recently)")


            # --- 2c. Malicious IP Checks (Source and Destinations) ---

            # Check if the source IP itself is on a blocklist (and not whitelisted)
            # The identify_malicious_ip function handles the whitelist check internally
            source_ip_malicious_lists = identify_malicious_ip(ip)
            if source_ip_malicious_lists:
                 if not ip_entry.get("is_malicious_source", False): # Log only first time detected
                     logger.warning(f"Malicious SOURCE IP detected: {ip} is on lists: ({', '.join(source_ip_malicious_lists)})")
                 ip_entry["is_malicious_source"] = True # Set flag
                 # Add/update hit details in the source IP's record for unified view
                 mal_hits = ip_entry.setdefault("malicious_hits", {})
                 hit_entry = mal_hits.setdefault(ip, {"blocklists": set(), "count": 0, "direction": "source"})
                 hit_entry["blocklists"].update(source_ip_malicious_lists)
                 hit_entry["count"] = ip_entry.get("total", 1) # Use total packets from source as count? Or just 1?
                 # Ensure the main flag indicating *any* malicious contact is set
                 ip_entry["contacted_malicious_ip"] = True


            # Check destinations contacted by this (potentially non-malicious) source IP
            destinations_contacted = list(ip_entry.get("destinations", {}).keys())
            for dst_ip in destinations_contacted:
                 # Check if the destination IP is malicious (handles dest whitelist check)
                 dest_ip_malicious_lists = identify_malicious_ip(dst_ip)
                 if dest_ip_malicious_lists:
                     # Log only if this specific src->dst malicious contact hasn't been logged recently?
                     # For now, log each time check runs and finds it.
                     logger.warning(f"Malicious DESTINATION IP detected for flow: {ip} -> {dst_ip} ({', '.join(dest_ip_malicious_lists)})")
                     # Mark the source IP as having contacted *some* malicious IP
                     ip_entry["contacted_malicious_ip"] = True
                     # Add/update hit details in the source IP's record
                     mal_hits = ip_entry.setdefault("malicious_hits", {})
                     # Use setdefault to initialize if this dst_ip hit is new for this source
                     hit_entry = mal_hits.setdefault(dst_ip, {"blocklists": set(), "count": 0, "direction": "outbound"})
                     # Add the lists it was found on (can accumulate if on multiple lists over time)
                     hit_entry["blocklists"].update(dest_ip_malicious_lists)
                     # Update the count based on total packets sent from src to this specific malicious dest
                     # Ensure dest_ip exists in destinations before accessing count
                     if dst_ip in ip_entry.get("destinations", {}):
                         hit_entry["count"] = ip_entry["destinations"][dst_ip].get("total", hit_entry["count"])

        # --- 3. Execute Pruning (Remove marked IPs) ---
        if ips_to_prune:
            logger.info(f"Pruning {len(ips_to_prune)} inactive IP data entries.")
            for ip in ips_to_prune:
                # Remove from all relevant dictionaries
                if ip in ip_data:
                    del ip_data[ip]
                    # logger.debug(f"Pruned ip_data for: {ip}") # Can be verbose
                if ip in temporal_data:
                    del temporal_data[ip]
                    # logger.debug(f"Pruned temporal_data for: {ip}")
                if ip in current_minute_data: # Should have been aggregated, but remove if lingering
                    del current_minute_data[ip]
                    # logger.debug(f"Pruned residual current_minute_data for: {ip}")
            logger.info(f"Pruning complete. Active IPs remaining: {len(ip_data)}")

    # --- End of Critical Section (Lock Released) ---
    logger.debug("Aggregation and pruning cycle finished.")
# --- End Data Aggregation and Pruning ---


# --- Network Interface Handling ---
def get_scapy_iface_dict():
    """Attempts to get Scapy's internal interface dictionary."""
    try:
        # Access Scapy's interface data (structure might vary slightly)
        return scapy_conf.ifaces.data
    except AttributeError:
        logger.warning("Could not access scapy_conf.ifaces.data for detailed interface info.")
        return None

def list_interfaces_cross_platform():
    """
    Lists available network interfaces using Scapy and psutil (if available).
    Tries to provide user-friendly names and associated IP addresses.

    Returns:
        tuple: (dict: {index: scapy_name}, dict: {scapy_name: friendly_name})
               Returns empty dictionaries if no interfaces are found or an error occurs.
    """
    scapy_if_names = []
    try:
        scapy_if_names = get_if_list() # Get basic list of interface names Scapy sees
        logger.debug(f"Scapy get_if_list() found: {scapy_if_names}")
    except Exception as e:
         logger.error(f"Error calling Scapy's get_if_list(): {e}", exc_info=True)
         print(f"\nERROR: Could not retrieve interface list using Scapy: {e}")
         return {}, {} # Return empty dicts on failure

    if not scapy_if_names:
         logger.warning("Scapy's get_if_list() returned empty.")
         # Optionally, try psutil enumeration directly? For now, rely on Scapy finding something.

    scapy_iface_details = get_scapy_iface_dict() # Get Scapy's detailed view if possible
    numbered_interfaces = {} # Map display index to scapy_name
    scapy_to_friendly = {} # Map scapy_name to friendly name for confirmation message
    interface_details_list = [] # List of tuples for sorting and display

    logger.info("Attempting to list and identify network interfaces...")

    # Try using psutil for richer details (IP, UP status, potentially better names)
    if psutil:
        logger.debug("Using psutil for enhanced interface details.")
        try:
            psutil_if_addrs = psutil.net_if_addrs()
            psutil_if_stats = psutil.net_if_stats()

            # Create mappings based on MAC address to link Scapy names to psutil details
            scapy_macs = {} # {scapy_name: mac_address}
            for name in scapy_if_names:
                 try:
                      hwaddr = get_if_hwaddr(name)
                      if hwaddr and hwaddr != "00:00:00:00:00:00": # Ignore zero MACs
                           scapy_macs[name] = hwaddr.lower()
                 except (OSError, ValueError, TypeError, AttributeError) as e: # Catch potential errors in get_if_hwaddr
                     logger.warning(f"Could not get MAC for Scapy interface '{name}': {e}")


            psutil_mac_to_friendly = {} # {mac_address: friendly_name}
            psutil_mac_to_ips = defaultdict(list) # {mac_address: [ip1, ip2]}
            psutil_mac_to_status = {} # {mac_address: is_up (bool)}

            for name, addrs in psutil_if_addrs.items():
                mac = None
                ips = []
                is_up = psutil_if_stats.get(name, None)
                status_str = f"UP" if is_up and is_up.isup else "DOWN" if is_up else "Status N/A"

                for addr in addrs:
                    if addr.family == psutil.AF_LINK and hasattr(addr, 'address'):
                         mac = addr.address.lower().replace('-', ':')
                    elif addr.family == socket.AF_INET and hasattr(addr, 'address'): # IPv4
                         ips.append(addr.address)
                    elif addr.family == socket.AF_INET6 and hasattr(addr, 'address'): # IPv6
                        # Optionally filter link-local (fe80::) or include? For now, include.
                        ips.append(addr.address)

                if mac and mac != "00:00:00:00:00:00":
                    psutil_mac_to_friendly[mac] = name # Use psutil name as friendly name
                    psutil_mac_to_ips[mac].extend(ips)
                    if is_up is not None: psutil_mac_to_status[mac] = status_str

            # Match Scapy interfaces to psutil details via MAC
            found_scapy_names = set()
            for scapy_name, scapy_mac in scapy_macs.items():
                 if scapy_mac in psutil_mac_to_friendly:
                      friendly_name = psutil_mac_to_friendly[scapy_mac]
                      ips_list = psutil_mac_to_ips.get(scapy_mac, ['N/A'])
                      ip_str = ', '.join(ips_list) if ips_list else 'N/A'
                      status = psutil_mac_to_status.get(scapy_mac, 'Status N/A')
                      interface_details_list.append((scapy_name, friendly_name, ip_str, status))
                      found_scapy_names.add(scapy_name)
                 #else: Scapy interface MAC not found in psutil data

            # Add Scapy interfaces not matched via MAC (use Scapy's potentially limited info)
            for scapy_name in scapy_if_names:
                 if scapy_name not in found_scapy_names:
                      friendly_name = str(scapy_name) # Default to scapy name
                      ip_str = 'N/A'
                      status = 'Status N/A'
                      # Try to get slightly better info from Scapy's internal dict if available
                      if scapy_iface_details and scapy_name in scapy_iface_details:
                          scapy_obj = scapy_iface_details[scapy_name]
                          # Use description if available, else name attribute, else original name
                          friendly_name = getattr(scapy_obj, 'description', getattr(scapy_obj, 'name', scapy_name))
                          ip_str = getattr(scapy_obj, 'ip', 'N/A') # Scapy might only store one IP
                          # Scapy often doesn't have reliable 'UP/DOWN' status here
                      interface_details_list.append((scapy_name, friendly_name, ip_str, status))

        except Exception as e:
             logger.error(f"Error using psutil for interface details: {e}", exc_info=True)

             interface_details_list = [] # Clear potentially partial list


    # Fallback or if psutil failed: Use only Scapy information
    if not psutil or not interface_details_list:
        logger.warning("Falling back to Scapy-only interface listing.")
        interface_details_list = [] # Ensure list is clear if psutil failed midway
        for name in scapy_if_names:
             friendly_name = str(name) # Default to string representation of Scapy name
             ip_str = 'N/A'
             status = 'Status N/A'
             # Try to get better name/IP from Scapy's internal dictionary
             if scapy_iface_details and name in scapy_iface_details:
                 scapy_obj = scapy_iface_details[name]
                 friendly_name = getattr(scapy_obj, 'description', getattr(scapy_obj, 'name', name))
                 ip_str = getattr(scapy_obj, 'ip', 'N/A')
             interface_details_list.append((name, friendly_name, ip_str, status))

    # --- Display Interfaces to User ---
    print("\nAvailable Network Interfaces:")
    print("-" * 70)
    # Sort primarily by status (UP preferred), then by friendly name
    interface_details_list.sort(key=lambda x: (x[3] != 'UP', x[1]))

    idx = 1
    for scapy_name, friendly_name_raw, ip_addr, status in interface_details_list:
        # Ensure names are decoded/represented correctly for printing
        try:
            display_friendly_name = repr(friendly_name_raw) if isinstance(friendly_name_raw, bytes) else str(friendly_name_raw)
            # Scapy name might be complex, show its representation
            display_scapy_name = repr(scapy_name) # repr handles bytes/complex objects safely
        except Exception: # Catch potential errors during repr/str conversion
            display_friendly_name = str(friendly_name_raw) # Fallback
            display_scapy_name = str(scapy_name) # Fallback

        print(f"{idx:>2}: {display_friendly_name:<35} Status: {status:<10} IP: {ip_addr:<20}") # Scapy Name: {display_scapy_name}
        numbered_interfaces[idx] = scapy_name # Store the actual name needed by Scapy
        scapy_to_friendly[scapy_name] = display_friendly_name # Store display name for confirmation
        idx += 1

    print("-" * 70)

    if not numbered_interfaces:
        logger.critical("No usable network interfaces were found by Scapy.")
        print("\nERROR: No network interfaces found. Cannot start capture.")
        return {}, {} # Return empty dictionaries

    return numbered_interfaces, scapy_to_friendly
# --- End Network Interface Handling ---


# --- Packet Sniffing Thread Target ---
def capture_packets(selected_interfaces):
    """Target function for the packet sniffing thread. MODIFIED FOR GRACEFUL STOP."""
    global capture_stop_event # Indicate we are using the global event

    if not selected_interfaces:
        logger.error("Packet capture thread started with no interfaces selected. Stopping.")
        return

    interfaces_str = [repr(iface) if isinstance(iface, bytes) else str(iface) for iface in selected_interfaces]
    logger.info(f"Packet capture thread started. Sniffing on interface(s): {', '.join(interfaces_str)}")

    packet_filter = "ip or ip6 or (udp port 53) or (tcp port 53)"
    logger.info(f"Using packet filter: \"{packet_filter}\"")

    # --- Loop with timeout instead of blocking indefinitely ---
    sniff_timeout = 1.0 # Seconds - check the stop event every second
    logger.info(f"Sniffing with {sniff_timeout}s timeout loop for graceful shutdown.")

    while not capture_stop_event.is_set():
        try:
            # Sniff for the timeout period
            sniff(prn=packet_callback, store=False, iface=selected_interfaces,
                  filter=packet_filter, timeout=sniff_timeout)

        except PermissionError as pe:
            logger.critical(f"PERMISSION ERROR: {pe}. Stopping capture thread.", exc_info=False)
            print("\nCRITICAL ERROR: Insufficient permissions. Please run as root/administrator.")
            break # Exit the loop on permission error
        except OSError as ose:
            logger.critical(f"OS ERROR during sniff loop on {interfaces_str}: {ose}", exc_info=True)
            print(f"\nCRITICAL ERROR: Sniffing failed on {', '.join(interfaces_str)}. Check interface/Npcap. ({ose})")
            break # Exit the loop on OS error
        except Exception as e:
            # Catch other unexpected errors during the sniff call
            logger.critical(f"UNEXPECTED SNIFF ERROR: {e}", exc_info=True)
            print(f"\nCRITICAL ERROR: Packet sniffing loop encountered an error: {e}")
            # Decide whether to break or continue after an error? Let's break for safety.
            break

        # Loop continues if timeout expires without error and stop event not set

    # --- End of loop ---
    if capture_stop_event.is_set():
        logger.info("Capture thread received stop signal and is exiting gracefully.")
    else:
         logger.warning("Capture thread loop exited unexpectedly (error?).")
# --- End Packet Sniffing Thread Target ---
def stop_capture():
    """Signals the packet capture thread to stop."""
    global capture_stop_event
    logger.info("Signaling packet capture thread to stop.")
    capture_stop_event.set()


# --- Interface Selection Prompt ---
def select_interfaces():
     """
     Lists available interfaces and prompts the user to select one or more.

     Returns:
         list or None: A list of selected Scapy interface names if confirmed,
                       or None if selection is cancelled or fails.
     """
     numbered_interfaces, scapy_to_friendly = list_interfaces_cross_platform()

     # Check if any interfaces were found
     if not numbered_interfaces:
          print("Exiting: No interfaces available for selection.")
          return None # Indicate failure/nothing to select

     while True:
          selected_input = input("Enter the number(s) of the interface(s) to monitor (e.g., 1 or 1,3): ")
          try:
               # Parse the input string into a list of integers
               selected_indices = [int(i.strip()) for i in selected_input.split(",") if i.strip()]
               if not selected_indices: # Handle empty input after split/strip
                    print("No selection made. Please enter interface number(s).")
                    continue

               selected_scapy_names = [] # Store the actual Scapy names for valid selections
               invalid_indices = []    # Store any invalid numbers entered

               # Validate selected indices against the displayed list
               for idx in selected_indices:
                    if idx in numbered_interfaces:
                         # Add the corresponding Scapy interface name
                         selected_scapy_names.append(numbered_interfaces[idx])
                    else:
                         invalid_indices.append(idx)

               # Report errors if any invalid numbers were entered
               if invalid_indices:
                    print(f"Error: Invalid interface number(s) entered: {invalid_indices}")
                    # Optionally show valid range: print(f"Please choose from 1 to {len(numbered_interfaces)}.")
                    continue # Ask again

               # Check if at least one valid interface was selected
               if not selected_scapy_names:
                    print("No valid interfaces selected from the input.")
                    continue # Ask again

               # --- Confirmation ---
               # Get friendly names for confirmation message
               selected_friendly_names = [scapy_to_friendly.get(name, str(name)) for name in selected_scapy_names]
               print(f"\nYou have selected: {', '.join(selected_friendly_names)}")

               # Ask for confirmation to start sniffing
               confirm = input("Start sniffing on these interfaces? (y/n): ").lower().strip()
               if confirm == 'y':
                    return selected_scapy_names # Return the list of Scapy names
               elif confirm == 'n':
                    print("Selection cancelled by user.")
                    return None # Indicate cancellation
               else:
                    print("Invalid confirmation input. Please enter 'y' or 'n'.")
                    # Loop back to ask for confirmation again (or could go back to index selection)

          except ValueError:
               print("Invalid input. Please enter only numbers, separated by commas if multiple.")
          except Exception as e:
               logger.error(f"Error during interface selection process: {e}", exc_info=True)
               print(f"An unexpected error occurred during selection: {e}")
               return None # Indicate failure
# --- End Interface Selection Prompt ---