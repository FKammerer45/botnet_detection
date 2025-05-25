# core/capture.py
import time
import threading
import logging
import platform
import socket
import sys 
import functools # For functools.partial

from scapy.all import sniff, IP, TCP, UDP, Ether, IPv6, DNS
from scapy.layers.dns import DNSQR, DNSRR # Not directly used here anymore, but good for context
from scapy.config import conf as scapy_conf
from scapy.arch import get_if_list, get_if_hwaddr
if platform.system() == "Windows":
    from scapy.arch.windows import get_windows_if_list

import psutil
from collections import defaultdict # For list_interfaces_cross_platform

# NetworkDataManager will be passed to packet_callback via functools.partial
# No direct import of data_manager here to avoid circular dependencies if data_manager imports from capture.

logger = logging.getLogger(__name__)

# This event is still used to signal the capture thread to stop.
capture_stop_event = threading.Event()

# --- Packet Processing Callback ---
def packet_callback(data_manager, pkt): # Added data_manager argument
    """
    Extracts relevant information from a packet and passes it to NetworkDataManager.
    """
    try:
        if not Ether in pkt: return
        is_ipv4 = IP in pkt
        is_ipv6 = IPv6 in pkt
        if not is_ipv4 and not is_ipv6: return

        pkt_time = time.time()
        
        src_ip, dst_ip, proto_num = None, None, None
        if is_ipv4:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_num = pkt[IP].proto
        elif is_ipv6: # IPv6
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto_num = pkt[IPv6].nh # Next Header

        # Protocol and Port Identification
        proto_name = "other"
        src_port, dst_port, port_used = None, None, None
        is_dns_traffic = False
        tcp_flags = None # Scapy flags object or None

        protocol_map = {1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'icmpv6'}
        if proto_num in protocol_map:
            proto_name = protocol_map[proto_num]
            if proto_name == 'tcp' and TCP in pkt:
                tcp_layer = pkt[TCP]
                src_port, dst_port = tcp_layer.sport, tcp_layer.dport
                tcp_flags = tcp_layer.flags
                port_used = dst_port
            elif proto_name == 'udp' and UDP in pkt:
                udp_layer = pkt[UDP]
                src_port, dst_port = udp_layer.sport, udp_layer.dport
                port_used = dst_port
            
            # Check for DNS traffic (standard ports)
            if (src_port == 53 or dst_port == 53) and (proto_name == 'tcp' or proto_name == 'udp'):
                is_dns_traffic = True
        else:
            proto_name_scapy = pkt.sprintf(f"%{'IP.proto' if is_ipv4 else 'IPv6.nh'}%")
            proto_name = proto_name_scapy.lower() if not proto_name_scapy.isdigit() else f"other({proto_num})"

        # Pass extracted data to the NetworkDataManager instance
        data_manager.process_packet_data(
            src_ip, dst_ip, proto_name, port_used, pkt_time,
            tcp_flags, is_dns_traffic, pkt # Pass raw packet for DNS layer access in DataManager
        )

    except AttributeError as ae:
         logger.warning(f"Packet attribute error in packet_callback: {ae} - Summary: {pkt.summary()}", exc_info=False)
    except Exception as e:
        logger.error(f"Unhandled error in packet_callback: {e} - Packet: {pkt.summary()}", exc_info=True)

# --- Network Interface Handling (Remains the same as it's UI related utility) ---
def list_interfaces_cross_platform():
    logger.info("Attempting to list and identify network interfaces...")
    detailed_interfaces = []
    try:
        scapy_raw_interfaces = get_if_list()
        scapy_interfaces_map = {str(name): name for name in scapy_raw_interfaces}
    except Exception as e:
        logger.error(f"Scapy get_if_list() failed: {e}. Interface listing might be incomplete.", exc_info=True)
        scapy_interfaces_map = {}

    scapy_mac_to_name_obj = {}
    for name_str, name_obj in scapy_interfaces_map.items():
        try:
            hwaddr = get_if_hwaddr(name_obj)
            if hwaddr and hwaddr != "00:00:00:00:00:00":
                scapy_mac_to_name_obj[hwaddr.lower()] = name_obj
        except Exception as e:
            logger.debug(f"Could not get MAC for Scapy interface '{name_str}': {e}")

    try:
        psutil_if_addrs = psutil.net_if_addrs()
        psutil_if_stats = psutil.net_if_stats()
        processed_scapy_names_objs = set()

        for psutil_name_str, addrs in psutil_if_addrs.items():
            ips = []
            mac_address = None
            for addr in addrs:
                if addr.family == psutil.AF_LINK: mac_address = addr.address.lower().replace('-', ':')
                elif addr.family == socket.AF_INET: ips.append(addr.address)
                elif addr.family == socket.AF_INET6: ips.append(addr.address)

            status_info = psutil_if_stats.get(psutil_name_str)
            status = "UP" if status_info and status_info.isup else "DOWN" if status_info else "N/A"
            scapy_name_obj_to_use = None
            
            if str(psutil_name_str) in scapy_interfaces_map:
                scapy_name_obj_to_use = scapy_interfaces_map[str(psutil_name_str)]
            elif mac_address and mac_address in scapy_mac_to_name_obj:
                scapy_name_obj_to_use = scapy_mac_to_name_obj[mac_address]
            
            if scapy_name_obj_to_use:
                if str(scapy_name_obj_to_use).startswith("\\Device\\NPF_") and not str(psutil_name_str).startswith("\\Device\\NPF_"):
                     # Prefer psutil name if Scapy name is NPF but psutil's is not
                    friendly_name_display = psutil_name_str
                else:
                    friendly_name_display = psutil_name_str # Default to psutil name
                
                # Final filter for display based on friendly name
                if not str(friendly_name_display).startswith("\\Device\\NPF_"):
                    detailed_interfaces.append({
                        "friendly_name": friendly_name_display, 
                        "status": status, "ips": ips if ips else ["N/A"],
                        "scapy_name": scapy_name_obj_to_use, 
                        "mac": mac_address if mac_address else "N/A"
                    })
                    processed_scapy_names_objs.add(scapy_name_obj_to_use)
            # else: logger.debug(f"psutil interface '{psutil_name_str}' not matched.")

        for name_str, name_obj in scapy_interfaces_map.items():
            if name_obj not in processed_scapy_names_objs and not str(name_obj).startswith("\\Device\\NPF_"):
                ips_scapy = ["N/A"] 
                try:
                    ip_s = scapy_conf.ifaces.data.get(name_obj, {}).get('ip', 'N/A')
                    if ip_s and ip_s != '0.0.0.0': ips_scapy = [ip_s]
                except: pass 
                detailed_interfaces.append({
                    "friendly_name": name_str, "status": "N/A", "ips": ips_scapy,
                    "scapy_name": name_obj,
                    "mac": get_if_hwaddr(name_obj) if get_if_hwaddr(name_obj) != "00:00:00:00:00:00" else "N/A"
                })
    except Exception as e:
        logger.error(f"Error gathering interface details: {e}", exc_info=True)
        if not detailed_interfaces: # Fallback
            logger.warning("Falling back to Scapy-only interface listing.")
            for name_str, name_obj in scapy_interfaces_map.items():
                if str(name_obj).startswith("\\Device\\NPF_"): continue
                ips_scapy = ["N/A"]
                try:
                    ip_s = scapy_conf.ifaces.data.get(name_obj, {}).get('ip', 'N/A')
                    if ip_s and ip_s != '0.0.0.0': ips_scapy = [ip_s]
                except: pass
                detailed_interfaces.append({
                    "friendly_name": name_str, "status": "N/A", "ips": ips_scapy,
                    "scapy_name": name_obj,
                    "mac": get_if_hwaddr(name_obj) if get_if_hwaddr(name_obj) != "00:00:00:00:00:00" else "N/A"
                })

    if not detailed_interfaces:
        logger.critical("No usable network interfaces found (after NPF filtering for display).")
        print("\nERROR: No network interfaces found. Cannot start capture.")
        return []

    detailed_interfaces.sort(key=lambda x: (x['status'] != 'UP', str(x['friendly_name'])))
    for i, iface in enumerate(detailed_interfaces): iface['idx'] = i + 1

    print("\nAvailable Network Interfaces:")
    print("-" * 80)
    print(f"{'Idx':<4} {'Name':<30} {'Status':<10} {'IP Addresses':<30}")
    print("-" * 80)
    for iface in detailed_interfaces:
        ips_str = ', '.join(iface['ips'])
        print(f"{iface['idx']:<4} {str(iface['friendly_name']):<30} {iface['status']:<10} {ips_str:<30}")
    print("-" * 80)
    return detailed_interfaces

# --- Packet Sniffing Thread Target ---
def capture_packets(selected_interfaces, data_manager_instance): # Added data_manager_instance
    """Target function for the packet sniffing thread."""
    if not selected_interfaces:
        logger.error("Packet capture thread: No interfaces selected. Stopping.")
        return
    if not data_manager_instance:
        logger.error("Packet capture thread: NetworkDataManager instance not provided. Stopping.")
        return

    interfaces_str = [repr(iface) if isinstance(iface, bytes) else str(iface) for iface in selected_interfaces]
    logger.info(f"Packet capture thread started. Sniffing on: {', '.join(interfaces_str)}")
    
    bound_packet_callback = functools.partial(packet_callback, data_manager_instance)

    packet_filter = "ip or ip6 or (udp port 53) or (tcp port 53)"
    logger.info(f"Using packet filter: \"{packet_filter}\"")
    sniff_timeout = 1.0 
    logger.info(f"Sniffing with {sniff_timeout}s timeout loop for graceful shutdown.")

    while not capture_stop_event.is_set():
        try:
            sniff(prn=bound_packet_callback, store=False, iface=selected_interfaces,
                  filter=packet_filter, timeout=sniff_timeout)
        except PermissionError as pe:
            logger.critical(f"PERMISSION ERROR: {pe}. Stopping capture thread.", exc_info=False)
            print("\nCRITICAL ERROR: Insufficient permissions. Please run as root/administrator.")
            break 
        except OSError as ose:
            logger.critical(f"OS ERROR during sniff loop on {interfaces_str}: {ose}", exc_info=True)
            print(f"\nCRITICAL ERROR: Sniffing failed on {', '.join(interfaces_str)}. Check interface/Npcap. ({ose})")
            break 
        except Exception as e:
            logger.critical(f"UNEXPECTED SNIFF ERROR: {e}", exc_info=True)
            print(f"\nCRITICAL ERROR: Packet sniffing loop encountered an error: {e}")
            break
    
    if capture_stop_event.is_set():
        logger.info("Capture thread received stop signal and is exiting gracefully.")
    else:
         logger.warning("Capture thread loop exited unexpectedly (error?).")

def stop_capture():
    """Signals the packet capture thread to stop."""
    global capture_stop_event
    logger.info("Signaling packet capture thread to stop.")
    capture_stop_event.set()

# --- Interface Selection Prompt ---
def select_interfaces():
    """
    Lists available interfaces and prompts the user to select one or more.
    Uses the new list_interfaces_cross_platform() return format.
    """
    available_interfaces = list_interfaces_cross_platform()
    if not available_interfaces:
        logger.warning("No interfaces returned by list_interfaces_cross_platform.")
        return None 

    idx_to_iface_map = {iface['idx']: iface for iface in available_interfaces}
    while True:
        selected_input = input("Enter the number(s) of the interface(s) to monitor (e.g., 1 or 1,3): ")
        try:
            selected_indices = [int(i.strip()) for i in selected_input.split(",") if i.strip()]
            if not selected_indices:
                print("No selection made. Please enter interface number(s).")
                continue

            selected_scapy_names, selected_friendly_names, invalid_indices = [], [], []
            for idx_val in selected_indices:
                iface_details = idx_to_iface_map.get(idx_val)
                if iface_details:
                    selected_scapy_names.append(iface_details['scapy_name'])
                    selected_friendly_names.append(iface_details['friendly_name'])
                else:
                    invalid_indices.append(idx_val)

            if invalid_indices:
                valid_range_str = f"1 to {len(available_interfaces)}" if available_interfaces else "N/A"
                print(f"Error: Invalid interface number(s) entered: {invalid_indices}. Valid range: {valid_range_str}")
                continue
            if not selected_scapy_names:
                print("No valid interfaces selected from the input.")
                continue

            print(f"\nYou have selected: {', '.join(map(str,selected_friendly_names))}")
            confirm = input("Start sniffing on these interfaces? (y/n): ").lower().strip()
            if confirm == 'y': return selected_scapy_names
            elif confirm == 'n':
                print("Selection cancelled by user.")
                return None 
            else: print("Invalid confirmation input. Please enter 'y' or 'n'.")
        except ValueError:
            print("Invalid input. Please enter only numbers, separated by commas if multiple.")
        except Exception as e:
            logger.error(f"Error during interface selection process: {e}", exc_info=True)
            print(f"An unexpected error occurred during selection: {e}")
            return None
