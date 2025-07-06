# core/blocklist_integration.py
import os
import requests
import csv
import ipaddress
import logging
import re
import time
import threading

# Import config and whitelist function
from core.config_manager import config
from core.whitelist_manager import get_whitelist # Import function
# Import constants from globals
from config.globals import DOWNLOAD_DIR

logger = logging.getLogger(__name__)
whitelist = get_whitelist() # Get the singleton instance

# Data storage (populated by load_blocklists)
blocklist_info = {}
malicious_networks = []
malicious_domains = set()

# --- Utility Functions ---
def get_local_filename(url, list_type="ip"):
    try:
        path_parts = [p for p in url.split('/') if p]
        base_name = path_parts[-1] if path_parts else url
        if not base_name or '.' not in base_name: base_name = url.split('//')[-1].replace('.', '_').replace('/', '_')
        prefix = "dns_" if list_type == "dns" else "ip_"
        filename = f"{prefix}{base_name}"
        filename = "".join(c if c.isalnum() or c in ['.', '-', '_'] else '_' for c in filename)
        max_len = 80
        if len(filename) > max_len:
             keep_end = 20; keep_start = max_len - keep_end - 3
             filename = filename[:keep_start] + "..." + filename[-keep_end:]
        return filename
    except Exception as e: logger.error(f"Filename gen error for {url}: {e}"); return f"{prefix}{hash(url)}.bin"

# --- Downloading ---
def download_blocklists(force_download=False):
    if not os.path.exists(DOWNLOAD_DIR):
        try: os.mkdir(DOWNLOAD_DIR); logger.info(f"Created dir: {DOWNLOAD_DIR}")
        except OSError as e: logger.error(f"Failed create dir {DOWNLOAD_DIR}: {e}", exc_info=True); return
    
    global blocklist_info
    blocklist_info.clear()
    ip_blocklist_dict = config._get_dict_from_config_section('Blocklists_IP')
    dns_blocklist_dict = config._get_dict_from_config_section('Blocklists_DNS')
    
    for url, desc in ip_blocklist_dict.items():
        blocklist_info[url] = {"type": "ip", "description": desc}
    for url, desc in dns_blocklist_dict.items():
        blocklist_info[url] = {"type": "dns", "description": desc}

    all_urls = set(blocklist_info.keys())
    logger.info(f"Checking/Downloading {len(all_urls)} blocklists...")
    for url, info in blocklist_info.items():
        list_type = info["type"]
        local_path = os.path.join(DOWNLOAD_DIR, get_local_filename(url, list_type))
        if os.path.exists(local_path) and not force_download: logger.debug(f"Skip download, exists: {os.path.basename(local_path)}"); continue
        logger.debug(f"Download [{list_type.upper()}]: {url} -> {local_path}")
        try:
            resp = requests.get(url, timeout=60, stream=True, headers={'User-Agent': 'NetworkMonitorBot/1.0'})
            resp.raise_for_status()
            with open(local_path, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192): f.write(chunk)
            logger.debug(f"Downloaded {url}")
        except requests.exceptions.RequestException as e: logger.error(f"Download failed {url}: {e}", exc_info=False)
        except IOError as e: logger.error(f"Write failed {local_path}: {e}", exc_info=True)
        except Exception as e: logger.error(f"Download error {url}: {e}", exc_info=True)
    logger.info("Download check finished.")

# --- Loading ---
def load_blocklists():
    global malicious_networks, malicious_domains
    new_network_list = []; new_domain_set = set()
    loaded_files = 0; total_ip_entries = 0; total_dns_entries = 0
    logger.info("Loading configured blocklists...")
    # Load IP Lists
    logger.info(f"Loading {len(config.ip_blocklist_urls)} IP blocklists...")
    for url in config.ip_blocklist_urls:
        local_path = os.path.join(DOWNLOAD_DIR, get_local_filename(url, "ip"))
        if os.path.exists(local_path):
            logger.debug(f"Parsing [IP]: {os.path.basename(local_path)}")
            try:
                count = 0; filename_lower = local_path.lower()
                if filename_lower.endswith(".csv"): count = _parse_ip_csv_file_to_list(new_network_list, local_path, url)
                else: count = _parse_ip_netset_file_to_list(new_network_list, local_path, url)
                if count > 0: logger.info(f"Loaded {count} IP entries from {os.path.basename(local_path)}"); total_ip_entries += count; loaded_files += 1
                else: logger.warning(f"No IP entries loaded from {os.path.basename(local_path)}.")
            except Exception as e: logger.error(f"Parse IP file error {local_path}: {e}", exc_info=True)
        else: logger.warning(f"IP file not found: {local_path}.")
    # Load DNS Lists
    logger.info(f"Loading {len(config.dns_blocklist_urls)} DNS blocklists...")
    for url in config.dns_blocklist_urls:
         local_path = os.path.join(DOWNLOAD_DIR, get_local_filename(url, "dns"))
         if os.path.exists(local_path):
            logger.debug(f"Parsing [DNS]: {os.path.basename(local_path)}")
            try:
                count = _parse_dns_file_to_set(new_domain_set, local_path, url)
                if count > 0: logger.info(f"Loaded {count} DNS entries from {os.path.basename(local_path)}"); total_dns_entries += count; loaded_files += 1
                else: logger.warning(f"No DNS entries loaded from {os.path.basename(local_path)}.")
            except Exception as e: logger.error(f"Parse DNS file error {local_path}: {e}", exc_info=True)
         else: logger.warning(f"DNS file not found: {local_path}.")
    malicious_networks = new_network_list; malicious_domains = new_domain_set
    logger.info(f"Blocklist loading complete. Files: {loaded_files}, IPs: {total_ip_entries}, DNS: {total_dns_entries}")

# --- IP Parsing Functions ---
def _add_ip_entry_to_list(network_list, network_obj, list_identifier):
    try: network_list.append((network_obj, list_identifier)); return True
    except Exception as e: logger.error(f"Error adding network {network_obj} from '{list_identifier}': {e}", exc_info=True); return False
def _parse_ip_or_cidr(ip_str):
    try: return ipaddress.ip_network(ip_str.strip(), strict=False)
    except ValueError:
        if ip_str and not ip_str.startswith('#'): logger.warning(f"Invalid IP/CIDR: '{ip_str}'. Skipping.")
        return None
def _parse_ip_netset_file_to_list(network_list, filepath, list_identifier, comment_char='#'):
    count = 0
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or (comment_char and line.startswith(comment_char)): continue
                network_obj = _parse_ip_or_cidr(line)
                if network_obj and _add_ip_entry_to_list(network_list, network_obj, list_identifier): count += 1
    except IOError as e: logger.error(f"Read error {filepath}: {e}", exc_info=True)
    except Exception as e: logger.error(f"Parse IP netset error {filepath}: {e}", exc_info=True)
    return count
def _parse_ip_csv_file_to_list(network_list, filepath, list_identifier, ip_column='Dst IP Address', comment_char='#', delimiter=','):
    count = 0; line_num = 0; header_found = False; reader = None
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as csvfile:
            potential_header_line = ""; header_line_num = 0
            for current_line_num, line_h in enumerate(csvfile, 1):
                line_h = line_h.strip()
                if not line_h or line_h.startswith(comment_char): continue
                potential_header_line = line_h; header_line_num = current_line_num; break
            if not potential_header_line: return 0
            fieldnames = []
            try:
                 sniffer = csv.Sniffer(); dialect = sniffer.sniff(potential_header_line)
                 has_header = sniffer.has_header(potential_header_line)
                 if has_header:
                     csvfile.seek(0); reader_check = csv.reader((l for l in csvfile if not l.strip().startswith(comment_char)), dialect=dialect)
                     fieldnames = next(reader_check)
                     if ip_column in fieldnames:
                         header_found = True; logger.debug(f"CSV Header found in {filepath}")
                         csvfile.seek(0); lines_for_dictreader = (l for l_num, l in enumerate(csvfile, 1) if not l.strip().startswith(comment_char) and l_num > header_line_num)
                         reader = csv.DictReader(lines_for_dictreader, fieldnames=fieldnames, dialect=dialect)
                     else: logger.warning(f"CSV Header in {filepath} missing '{ip_column}'. Fields: {fieldnames}. Treating as simple list.")
                 else: logger.warning(f"No header detected in {filepath}. Treating as simple list.")
            except csv.Error: logger.warning(f"CSV dialect/header error in {filepath}. Treating as simple list.")
            if reader:
                 line_num = header_line_num
                 for row_dict in reader:
                     line_num += 1; ip_str = row_dict.get(ip_column, '').strip()
                     if not ip_str: continue
                     network_obj = _parse_ip_or_cidr(ip_str)
                     if network_obj and _add_ip_entry_to_list(network_list, network_obj, list_identifier): count += 1
            else:
                 csvfile.seek(0)
                 for line_num_simple, line_s in enumerate(csvfile, 1):
                     line_s = line_s.strip()
                     if not line_s or line_s.startswith(comment_char): continue
                     ip_str = line_s.split(delimiter)[0].strip()
                     network_obj = _parse_ip_or_cidr(ip_str)
                     if network_obj and _add_ip_entry_to_list(network_list, network_obj, list_identifier): count += 1
    except IOError as e: logger.error(f"Read CSV error {filepath}: {e}", exc_info=True)
    except Exception as e: logger.error(f"Parse IP CSV error {filepath} near line {line_num}: {e}", exc_info=True)
    return count

# --- DNS Parsing Functions ---
def _parse_dns_file_to_set(domain_set, filepath, list_identifier):
    count = 0; line_num = 0
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'): continue
                parts = line.split(); domain = None; potential_domain = None
                try:
                    if len(parts) >= 2 and ipaddress.ip_address(parts[0]): potential_domain = parts[1].lower()
                    elif len(parts) == 1: potential_domain = parts[0].lower()
                except ValueError: # Handle case where first part isn't IP but multiple parts exist
                     if len(parts) == 1: potential_domain = parts[0].lower()

                if potential_domain:
                    potential_domain = potential_domain.rstrip('.')
                    if '.' in potential_domain and not potential_domain.startswith('.') and not potential_domain.endswith('.'):
                        if re.match(r'^[a-z0-9.-]+$', potential_domain): domain = potential_domain
                        else: logger.debug(f"Skip invalid DNS format '{potential_domain}' line {line_num} in {filepath}")
                    else: logger.debug(f"Skip invalid DNS structure '{potential_domain}' line {line_num} in {filepath}")
                if domain: domain_set.add(domain); count += 1
    except IOError as e: logger.error(f"Read DNS file error {filepath}: {e}", exc_info=True)
    except Exception as e: logger.error(f"Parse DNS file error {filepath} near line {line_num}: {e}", exc_info=True)
    return count

# --- Checking Functions ---
def identify_malicious_ip(ip_str: str) -> dict:
    """Checks IP against blocklist, ignoring whitelist."""
    global malicious_networks, blocklist_info
    # *** Use the whitelist instance ***
    if whitelist.is_ip_whitelisted(ip_str): logger.debug(f"IP {ip_str} whitelisted."); return {}
    matched_lists = {}
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for network, list_identifier in malicious_networks:
            if ip_obj in network:
                if list_identifier not in matched_lists:
                    matched_lists[list_identifier] = blocklist_info.get(list_identifier, {}).get('description', 'N/A')
    except ValueError: logger.debug(f"Invalid IP for blocklist lookup: {ip_str}")
    except Exception as e: logger.error(f"IP blocklist lookup error '{ip_str}': {e}", exc_info=True)
    return matched_lists

def is_domain_malicious(domain: str) -> dict:
    """Checks domain against blocklist, ignoring whitelist."""
    global malicious_domains, blocklist_info
    if not domain: return {}
    domain_lower = domain.lower().strip('.')
    # *** Use the whitelist instance ***
    if whitelist.is_domain_whitelisted(domain_lower): logger.debug(f"Domain {domain_lower} whitelisted."); return {}
    
    matched_lists = {}
    
    # Check for exact match
    if domain_lower in malicious_domains:
        for list_identifier in malicious_domains[domain_lower]:
            if list_identifier not in matched_lists:
                matched_lists[list_identifier] = blocklist_info.get(list_identifier, {}).get('description', 'N/A')
        logger.debug(f"Exact domain blocklist match: '{domain_lower}'")
        return matched_lists

    # Check for parent domain match
    parts = domain_lower.split('.')
    for i in range(1, len(parts) - 1):
        parent_domain = '.'.join(parts[i:])
        if parent_domain in malicious_domains:
            for list_identifier in malicious_domains[parent_domain]:
                if list_identifier not in matched_lists:
                    matched_lists[list_identifier] = blocklist_info.get(list_identifier, {}).get('description', 'N/A')
            logger.debug(f"Parent domain blocklist match: '{parent_domain}' for query '{domain_lower}'")
            return matched_lists
            
    return matched_lists

# --- Periodic Update Functionality ---
update_stop_event = threading.Event()

def _periodic_update_task():
    """The actual task run in a thread to update blocklists."""
    interval_hours = config.blocklist_update_interval_hours
    if not isinstance(interval_hours, (int, float)) or interval_hours <= 0:
        logger.info("Blocklist auto-updating is disabled (interval <= 0). Thread exiting.")
        return

    interval_seconds = interval_hours * 3600
    logger.info(f"Blocklist auto-update thread started. Update interval: {interval_hours} hours.")

    while not update_stop_event.wait(interval_seconds):
        logger.info("Periodic blocklist update triggered.")
        try:
            download_blocklists(force_download=True)
            load_blocklists()
            logger.info("Periodic blocklist update finished successfully.")
        except Exception as e:
            logger.error(f"Error during periodic blocklist update: {e}", exc_info=True)

    logger.info("Blocklist auto-update thread received stop signal and is exiting.")

def start_periodic_blocklist_updates():
    """Starts the background thread for periodic blocklist updates if enabled."""
    if config.blocklist_update_interval_hours > 0:
        update_thread = threading.Thread(target=_periodic_update_task, daemon=True)
        update_thread.name = "BlocklistUpdateThread"
        update_thread.start()
        return update_thread
    return None

def stop_periodic_blocklist_updates():
    """Signals the periodic update thread to stop."""
    logger.info("Signaling blocklist auto-update thread to stop.")
    update_stop_event.set()
