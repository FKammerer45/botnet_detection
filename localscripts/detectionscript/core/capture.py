# capture.py
import time
import threading
import logging
from collections import deque, defaultdict # Import deque
import platform
import ipaddress
import socket

# Third-party imports
try:
    from scapy.all import sniff, IP, TCP, UDP, Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.config import conf as scapy_conf
    from scapy.arch import get_if_list, get_if_hwaddr
    if platform.system() == "Windows":
         from scapy.arch.windows import get_windows_if_list
except ImportError:
    logging.critical("Scapy (including layers.dns) is required but not installed. Please install it: pip install scapy")
    raise SystemExit("Scapy not found.")

try:
    import psutil
except ImportError:
     logging.warning("psutil not found (pip install psutil). Falling back to basic interface listing.")
     psutil = None

# Local imports
from core.blocklist_integration import identify_malicious_ip
from core.dns_blocklist_integration import is_domain_malicious
from config.globals import IP_DATA_PRUNE_TIMEOUT, TRACKED_PROTOCOLS

logger = logging.getLogger(__name__)

# --- Global Data Structures ---
ip_data = {}
lock = threading.Lock()
MAX_MINUTES_TEMPORAL = 1440
temporal_data = {}
current_minute_data = {}


# --- Packet Processing ---

def packet_callback(pkt):
    """Callback function executed by Scapy for each captured packet."""
    if not Ether in pkt or not IP in pkt:
         return

    try:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        now = time.time()

        proto = "other"; port = None; is_dns = False

        if TCP in pkt:
            proto, sport, dport = "tcp", pkt[TCP].sport, pkt[TCP].dport
            if sport == 53 or dport == 53: is_dns = True
            port = dport
        elif UDP in pkt:
            proto, sport, dport = "udp", pkt[UDP].sport, pkt[UDP].dport
            if sport == 53 or dport == 53: is_dns = True
            port = dport
        elif pkt.haslayer("ICMP"):
             proto, port = "icmp", None
        else:
            proto_num = pkt[IP].proto
            proto = pkt[IP].sprintf("%IP.proto%")
            if proto.isdigit():
                 proto_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
                 proto = proto_map.get(int(proto), f"other({proto})")
            else: proto = proto.lower()
            port = None

        with lock:
            # --- Initialize ip_data entry if needed ---
            if src_ip not in ip_data:
                ip_data[src_ip] = {
                    "total": 0,
                    # *** FIX: Remove maxlen ***
                    "timestamps": deque(),
                    "last_seen": 0.0, "max_per_sec": 0,
                    # *** FIX: Remove maxlen ***
                    "destinations": defaultdict(lambda: {"total": 0, "timestamps": deque(), "max_per_sec": 0}),
                    # *** FIX: Remove maxlen ***
                    "protocols": defaultdict(lambda: {"total": 0, "timestamps": deque(), "max_per_sec": 0}),
                    "malicious_hits": {}, "contacted_malicious_ip": False,
                    "suspicious_dns": []
                }

            ip_entry = ip_data[src_ip]

            # --- Standard Stats Update ---
            ip_entry["total"] += 1
            ip_entry["timestamps"].append(now) # Add timestamp
            ip_entry["last_seen"] = now

            # Calculate current packets/sec (approximate over last second)
            # Note: Pruning now happens in GUI update before this calc is used there
            one_sec_ago = now - 1.0
            # This calculation is potentially inaccurate now without pruning here,
            # but the GUI update loop will do the accurate calculation after pruning.
            # We still update max_per_sec based on the GUI calculation later.
            # current_pps = sum(1 for t in ip_entry["timestamps"] if t >= one_sec_ago) # Less accurate here now
            # ip_entry["max_per_sec"] = max(ip_entry["max_per_sec"], current_pps) # Max P/S updated in GUI

            # Update destinations
            dest_entry = ip_entry["destinations"][dst_ip]
            dest_entry["total"] += 1
            dest_entry["timestamps"].append(now) # Add timestamp
            # Max P/S for destination updated in gui_detail

            # Update protocols
            proto_key = (proto, port)
            proto_entry = ip_entry["protocols"][proto_key]
            proto_entry["total"] += 1
            proto_entry["timestamps"].append(now) # Add timestamp
            # Max P/S for protocol updated in gui_detail

            # --- DNS Specific Processing ---
            if is_dns and pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                if dns_layer.qr == 0 and dns_layer.qdcount > 0:
                    for i in range(dns_layer.qdcount):
                        if dns_layer.qd[i] is None: continue
                        try:
                            qname = dns_layer.qd[i].qname.decode('utf-8', errors='ignore').rstrip('.').lower()
                            logger.debug(f"DNS Query from {src_ip}: {qname}")
                            if is_domain_malicious(qname):
                                logger.warning(f"Malicious DNS Query: {src_ip} -> {qname} (BLOCKLIST HIT)")
                                dns_event = {"timestamp": now, "qname": qname, "reason": "Blocklist Hit"}
                                ip_entry["suspicious_dns"].append(dns_event)
                        except Exception as dns_ex:
                            logger.error(f"Error processing DNS question {i} from {src_ip}: {dns_ex}", exc_info=False)

            # --- Update current_minute_data ---
            minute_start = int(now // 60) * 60
            if src_ip not in current_minute_data:
                current_minute_data[src_ip] = {
                    "start_time": minute_start, "count": 0, "protocol_count": defaultdict(int)
                }
            if current_minute_data[src_ip]["start_time"] == minute_start:
                cdata = current_minute_data[src_ip]
                cdata["count"] += 1
                if proto in TRACKED_PROTOCOLS or (proto, port) in TRACKED_PROTOCOLS:
                     cdata["protocol_count"][proto_key] += 1
                elif "other" in TRACKED_PROTOCOLS:
                     cdata["protocol_count"][("other", None)] += 1

    except Exception as e:
        logger.error(f"Error processing packet: {e}\nPacket summary: {pkt.summary() if pkt else 'N/A'}", exc_info=True)


# --- Data Aggregation and Pruning ---
def aggregate_minute_data():
    """Aggregates minute data, checks malicious IPs, and prunes old IPs."""
    now = time.time()
    current_minute_start = int(now // 60) * 60
    logger.debug(f"Aggregating data for minute starting at {current_minute_start}")

    ips_to_prune = []
    prune_threshold_time = now - IP_DATA_PRUNE_TIMEOUT

    with lock:
        # Process completed minute data
        minute_keys = list(current_minute_data.keys())
        for ip in minute_keys:
            if ip not in current_minute_data: continue
            cdata = current_minute_data[ip]
            if cdata["start_time"] < current_minute_start:
                logger.debug(f"Aggregating minute data for IP {ip} from timestamp {cdata['start_time']}")
                if ip not in temporal_data:
                    temporal_data[ip] = {
                        "minutes": deque(maxlen=MAX_MINUTES_TEMPORAL),
                        "protocol_minutes": defaultdict(lambda: deque(maxlen=MAX_MINUTES_TEMPORAL))
                    }
                timestamp = cdata["start_time"]
                total_count = cdata["count"]
                temporal_data[ip]["minutes"].append((timestamp, total_count))
                for proto_key, count in cdata["protocol_count"].items():
                    temporal_data[ip]["protocol_minutes"][proto_key].append((timestamp, count))
                del current_minute_data[ip]

        # Malicious IP Check & Pruning
        ip_data_keys = list(ip_data.keys())
        for ip in ip_data_keys:
            if ip not in ip_data: continue
            ip_entry = ip_data[ip]

            # Pruning Check: Check last_seen timestamp
            # Deques are pruned in GUI updates now, just prune the IP entry itself
            if ip_entry.get("last_seen", 0) < prune_threshold_time:
                ips_to_prune.append(ip)
                continue

            # Malicious Hit Check
            destinations_to_check = list(ip_entry.get("destinations", {}).keys())
            for dst_ip in destinations_to_check:
                 matched_lists = identify_malicious_ip(dst_ip)
                 if matched_lists:
                     logger.warning(f"Malicious IP hit: {ip} -> {dst_ip} (Blocklists: {', '.join(matched_lists)})")
                     ip_entry["contacted_malicious_ip"] = True
                     mal_hits = ip_entry.setdefault("malicious_hits", {})
                     hit_entry = mal_hits.setdefault(dst_ip, {"blocklists": set(), "count": 0, "direction": "outbound"})
                     hit_entry["blocklists"].update(matched_lists)
                     hit_entry["count"] = ip_entry.get("destinations", {}).get(dst_ip, {}).get("total", hit_entry["count"])

        # Perform pruning
        if ips_to_prune:
            logger.info(f"Pruning {len(ips_to_prune)} inactive IPs (older than {IP_DATA_PRUNE_TIMEOUT}s).")
            for ip in ips_to_prune:
                if ip in ip_data: del ip_data[ip]; logger.debug(f"Pruned IP: {ip}")
                if ip in temporal_data: del temporal_data[ip]; logger.debug(f"Pruned IP from temporal data: {ip}")
                if ip in current_minute_data: del current_minute_data[ip]

    logger.debug("Aggregation and pruning finished.")


# --- Network Interface Handling ---
# (list_interfaces_cross_platform, capture_packets, select_interfaces remain the same as v4)
def get_scapy_iface_dict():
    """Gets Scapy's internal interface dictionary."""
    try:
        return scapy_conf.ifaces.data
    except AttributeError:
        logger.warning("Could not access scapy_conf.ifaces.data directly.")
        return None

def list_interfaces_cross_platform():
    """Provides a user-friendly list of network interfaces using psutil and Scapy."""
    scapy_if_names = get_if_list()
    scapy_iface_dict = get_scapy_iface_dict()
    numbered_interfaces = {}
    scapy_to_friendly = {}
    interface_details = []

    logger.info("Listing available network interfaces...")

    if psutil:
        logger.debug("Using psutil to get interface details.")
        psutil_if_addrs = psutil.net_if_addrs()
        psutil_if_stats = psutil.net_if_stats()

        scapy_macs = {name: get_if_hwaddr(name).lower() for name in scapy_if_names if get_if_hwaddr(name)}
        logger.debug(f"Scapy MACs: {scapy_macs}")

        psutil_mac_to_friendly = {}
        psutil_mac_to_ips = defaultdict(list)

        for name, addrs in psutil_if_addrs.items():
            friendly_name = name
            mac = None
            ip = 'N/A'
            if name in psutil_if_stats: is_up = psutil_if_stats[name].isup
            else: is_up = False

            for addr in addrs:
                if addr.family == psutil.AF_LINK: mac = addr.address.lower().replace('-', ':')
                elif addr.family == socket.AF_INET: ip = addr.address

            if mac:
                 psutil_mac_to_friendly[mac] = friendly_name
                 if ip != 'N/A': psutil_mac_to_ips[mac].append(ip)
                 logger.debug(f"psutil found: Name='{friendly_name}', MAC={mac}, IP={ip}, Up={is_up}")

        for scapy_name, scapy_mac in scapy_macs.items():
            if scapy_mac in psutil_mac_to_friendly:
                friendly_name = psutil_mac_to_friendly[scapy_mac]
                ips = psutil_mac_to_ips.get(scapy_mac, ['N/A'])
                ip_str = ', '.join(ips)
                interface_details.append((scapy_name, friendly_name, ip_str))
                logger.debug(f"Matched Scapy '{scapy_name}' to Friendly '{friendly_name}' via MAC {scapy_mac}")
            else:
                friendly_name = scapy_name
                ip_str = 'N/A'
                if scapy_iface_dict and scapy_name in scapy_iface_dict:
                     scapy_obj = scapy_iface_dict[scapy_name]
                     friendly_name = getattr(scapy_obj, 'description', getattr(scapy_obj, 'name', scapy_name))
                     ip_str = getattr(scapy_obj, 'ip', 'N/A')
                interface_details.append((scapy_name, friendly_name, ip_str))
                logger.debug(f"Could not match Scapy '{scapy_name}' via MAC {scapy_mac}. Using fallback name '{friendly_name}'.")

    else:
        logger.warning("psutil not available. Interface names might be less friendly.")
        for name in scapy_if_names:
             mac = get_if_hwaddr(name)
             friendly_name = name
             ip_str = 'N/A'
             if scapy_iface_dict and name in scapy_iface_dict:
                  scapy_obj = scapy_iface_dict[name]
                  friendly_name = getattr(scapy_obj, 'description', getattr(scapy_obj, 'name', name))
                  ip_str = getattr(scapy_obj, 'ip', 'N/A')
             interface_details.append((name, friendly_name, ip_str))

    print("\nAvailable Network Interfaces:")
    print("-" * 60)
    idx = 1
    interface_details.sort(key=lambda x: x[1])
    for scapy_name, friendly_name, ip_addr in interface_details:
        display_scapy_name = repr(scapy_name) if isinstance(scapy_name, bytes) else scapy_name
        display_friendly_name = repr(friendly_name) if isinstance(friendly_name, bytes) else friendly_name
        print(f"{idx}: {display_friendly_name} (IP: {ip_addr}, Scapy: {display_scapy_name})")
        numbered_interfaces[idx] = scapy_name
        scapy_to_friendly[scapy_name] = display_friendly_name
        idx += 1
    print("-" * 60)

    if not numbered_interfaces:
         logger.critical("No network interfaces found by Scapy!")

    return numbered_interfaces, scapy_to_friendly


# --- Main Capture Function ---
def capture_packets(selected_interfaces):
    """Starts the packet sniffing process on the specified interfaces."""
    if not selected_interfaces:
        logger.error("No interfaces selected for sniffing.")
        return

    interfaces_str = [repr(iface) if isinstance(iface, bytes) else iface for iface in selected_interfaces]
    logger.info(f"Starting packet sniffing on interfaces: {', '.join(interfaces_str)}")

    try:
        packet_filter = "ip or (udp port 53) or (tcp port 53)"
        logger.info(f"Using packet filter: {packet_filter}")
        sniff(prn=packet_callback, store=False, iface=selected_interfaces, filter=packet_filter)
    except PermissionError:
         logger.critical("Permission denied. Packet sniffing requires root/administrator privileges.")
         print("\nERROR: Permission denied. Please run the script as root or administrator.")
    except OSError as e:
         logger.critical(f"OS Error during sniffing setup on {interfaces_str}: {e}", exc_info=True)
         print(f"\nERROR: Could not start sniffing on {interfaces_str}. Interface might be invalid or unavailable.")
    except Exception as e:
        logger.critical(f"An unexpected error occurred during packet sniffing: {e}", exc_info=True)
        print(f"\nERROR: An unexpected error stopped packet sniffing: {e}")

# --- Helper for getting interface names (used by main) ---
def select_interfaces():
     """Handles the interface selection process."""
     numbered_interfaces, scapy_to_friendly = list_interfaces_cross_platform()
     if not numbered_interfaces:
          print("No interfaces available for selection. Exiting.")
          return None

     while True:
          selected_input = input("Enter the numbers of the interfaces to sniff on, separated by commas (e.g., 1,3): ")
          try:
               selected_indices = [int(i.strip()) for i in selected_input.split(",")]
               selected_scapy_names = []
               invalid_indices = []
               for idx in selected_indices:
                    if idx in numbered_interfaces:
                         selected_scapy_names.append(numbered_interfaces[idx])
                    else:
                         invalid_indices.append(idx)

               if invalid_indices:
                    print(f"Error: Invalid interface numbers entered: {invalid_indices}")
                    continue

               if not selected_scapy_names:
                    print("No valid interfaces selected. Please try again.")
                    continue

               selected_friendly_names = [scapy_to_friendly.get(name, name) for name in selected_scapy_names]
               print(f"\nYou selected: {', '.join(selected_friendly_names)}")
               confirm = input("Start sniffing on these interfaces? (y/n): ").lower()
               if confirm == 'y':
                    return selected_scapy_names
               else:
                    print("Selection cancelled.")
                    return None

          except ValueError:
               print("Invalid input. Please enter numbers separated by commas (e.g., 1,3).")
          except Exception as e:
               logger.error(f"Error during interface selection: {e}", exc_info=True)
               print(f"An unexpected error occurred: {e}")
               return None

