# capture.py
import time
import threading
import subprocess
import re
from collections import deque
from scapy.all import sniff,get_if_list,get_if_hwaddr, IP, TCP, UDP
from core.blocklist_integration import identify_malicious_ip

ip_data = {}
lock = threading.Lock()

# For temporal analysis
MAX_MINUTES = 1440  # store up to 24 hours (one entry per minute)
temporal_data = {}
current_minute_data = {}

def packet_callback(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        now = time.time()

        if TCP in pkt:
            proto = "tcp"
            port = pkt[TCP].dport
        elif UDP in pkt:
            proto = "udp"
            port = pkt[UDP].dport
        else:
            proto = "other"
            port = None

        with lock:
            # Ensure ip_data entry
            if src_ip not in ip_data:
                ip_data[src_ip] = {
                    "total": 0,
                    "timestamps": [],
                    "max_per_sec": 0,
                    "destinations": {},
                    "protocols": {}
                }

            # Update total and timestamps
            ip_data[src_ip]["total"] += 1
            ip_data[src_ip]["timestamps"].append(now)

            # Update destinations
            if dst_ip not in ip_data[src_ip]["destinations"]:
                ip_data[src_ip]["destinations"][dst_ip] = {
                    "total": 0,
                    "timestamps": [],
                    "max_per_sec": 0
                }
            ip_data[src_ip]["destinations"][dst_ip]["total"] += 1
            ip_data[src_ip]["destinations"][dst_ip]["timestamps"].append(now)

            # Update protocol counts
            if (proto, port) not in ip_data[src_ip]["protocols"]:
                ip_data[src_ip]["protocols"][(proto, port)] = {
                    "total": 0,
                    "timestamps": [],
                    "max_per_sec": 0
                }
            p = ip_data[src_ip]["protocols"][(proto, port)]
            p["total"] += 1
            p["timestamps"].append(now)

            # Update current_minute_data aggregator
            minute_start = int(now // 60) * 60
            if src_ip not in current_minute_data:
                current_minute_data[src_ip] = {
                    "start_time": minute_start,
                    "count": 0,
                    "protocol_count": {}
                }
            cdata = current_minute_data[src_ip]
            cdata["count"] += 1
            if (proto, port) not in cdata["protocol_count"]:
                cdata["protocol_count"][(proto, port)] = 0
            cdata["protocol_count"][(proto, port)] += 1

def capture_packets():
    """
    Allow user to select multiple interfaces and sniff packets on them.
    """
    interface_mapping = list_interfaces()

    print("Enter the numbers of the interfaces to sniff on, separated by commas (e.g., 1,3):")
    selected = input("Enter your selection: ")
    try:
        selected_indices = [int(i.strip()) for i in selected.split(",")]
        selected_interfaces = [interface_mapping[idx] for idx in selected_indices if idx in interface_mapping]

        if not selected_interfaces:
            print("No valid interfaces selected. Exiting.")
            return

        print(f"Sniffing on interfaces: {', '.join(selected_interfaces)}")
        sniff(prn=packet_callback, store=False, iface=selected_interfaces)
    except ValueError:
        print("Invalid input. Please enter valid numbers separated by commas.")
        return




def get_friendly_names():
    """
    Map NPF device names to friendly interface names using 'ipconfig' and Scapy.
    """
    # Get NPF device names from Scapy
    npf_devices = get_if_list()

    # Get the MAC addresses for NPF devices
    npf_mac_mapping = {device: get_if_hwaddr(device) for device in npf_devices}

    # Get friendly names and MAC addresses from 'ipconfig /all'
    cmd = "ipconfig /all"
    try:
        output = subprocess.check_output(cmd, shell=True, text=True, encoding="cp1252", errors="replace")
    except subprocess.CalledProcessError as e:
        print("Error running ipconfig:", e)
        return {}

    # Regex to extract friendly names and MAC addresses
    matches = re.finditer(
        r"Beschreibung[. ]+:\s+(.*?)\n.*?Physische Adresse[. ]+:\s+([A-Fa-f0-9-]+)",
        output,
        re.S,
    )

    interface_mapping = {}
    for match in matches:
        friendly_name = match.group(1).strip()
        mac_address = match.group(2).strip().replace("-", ":")

        # Match the MAC address to the NPF device
        for npf_device, npf_mac in npf_mac_mapping.items():
            if npf_mac.lower() == mac_address.lower():
                interface_mapping[npf_device] = friendly_name
                break

    return interface_mapping


def list_interfaces():
    """
    Display a user-friendly list of interfaces.
    """
    mapping = get_friendly_names()

    print("Available Interfaces:")
    numbered_interfaces = {}
    for idx, (npf_name, friendly_name) in enumerate(mapping.items(), start=1):
        print(f"{idx}: {friendly_name} ({npf_name})")
        numbered_interfaces[idx] = npf_name

    return numbered_interfaces

def aggregate_minute_data():
    """
    Called periodically (e.g., every minute) to move data from `current_minute_data`
    into `temporal_data` for plotting, and check malicious IP hits.
    """
    now = time.time()
    with lock:
        for ip, cdata in current_minute_data.items():
            # Create or retrieve the temporal_data entry for this IP
            if ip not in temporal_data:
                temporal_data[ip] = {
                    "minutes": deque(maxlen=MAX_MINUTES),
                    "protocol_minutes": {},
                    "events": []
                }

            # 1) Add the aggregated minute count to 'minutes'
            timestamp = cdata["start_time"]
            total_count = cdata["count"]
            temporal_data[ip]["minutes"].append((timestamp, total_count))

            # 2) For each protocol, store the count in protocol_minutes
            for (proto, port), count in cdata["protocol_count"].items():
                if (proto, port) not in temporal_data[ip]["protocol_minutes"]:
                    temporal_data[ip]["protocol_minutes"][(proto, port)] = deque(maxlen=MAX_MINUTES)
                temporal_data[ip]["protocol_minutes"][(proto, port)].append((timestamp, count))

            # 3) Check malicious IP hits for each destination
            if ip in ip_data:
                for dst_ip, d_info in ip_data[ip]["destinations"].items():
                    blocklists = identify_malicious_ip(dst_ip)
                    if blocklists:
                        # Mark device as malicious
                        ip_data[ip].setdefault("malicious_hits", {})
                        ip_data[ip]["contacted_malicious_ip"] = True

                        if dst_ip not in ip_data[ip]["malicious_hits"]:
                            ip_data[ip]["malicious_hits"][dst_ip] = {
                                "blocklists": set(),
                                "count": 0,
                                "direction": "outbound"
                            }

                        for bl_name in blocklists:
                            ip_data[ip]["malicious_hits"][dst_ip]["blocklists"].add(bl_name)

                        # Add newly-seen packets (since last aggregator run) to malicious_hits count
                        ip_data[ip]["malicious_hits"][dst_ip]["count"] += d_info["total"]

        # Clear current_minute_data for next cycle
        current_minute_data.clear()
