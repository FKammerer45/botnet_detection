# core/blocklist_integration.py
import os
import requests
import csv
import ipaddress
import logging

# Get a logger for this module
logger = logging.getLogger(__name__)

# Base URL for FireHOL level 1 lists (example)
FIREHOL_BASE_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"

# Dynamic blocklists storage: URL => Active/Inactive status
blocklists = {
    f"{FIREHOL_BASE_URL}/dshield.netset": True,
    f"{FIREHOL_BASE_URL}/spamhaus_drop.netset": True,
    f"{FIREHOL_BASE_URL}/spamhaus_edrop.netset": True,
    "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt": True,
    "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv": True,
}

DOWNLOAD_DIR = "blocklists"

# Use a simple list to store malicious networks and their source list identifiers (URLs).
# Structure: [(ipaddress.ip_network, list_identifier_str), ...]
malicious_networks = []


def download_blocklists():
    """Downloads all active blocklists from their URLs."""
    if not os.path.exists(DOWNLOAD_DIR):
        try:
            os.mkdir(DOWNLOAD_DIR)
            logger.info(f"Created blocklist download directory: {DOWNLOAD_DIR}")
        except OSError as e:
            logger.error(f"Failed to create blocklist directory {DOWNLOAD_DIR}: {e}", exc_info=True)
            return

    active_lists = {url for url, active in blocklists.items() if active}
    logger.info(f"Starting download for {len(active_lists)} active blocklists...")

    for url in active_lists:
        filename = url.split("/")[-1]
        filename = "".join(c if c.isalnum() or c in ['.', '-', '_'] else '_' for c in filename) # Sanitize
        local_path = os.path.join(DOWNLOAD_DIR, filename)
        logger.debug(f"Attempting to download {url} -> {local_path}")
        try:
            resp = requests.get(url, timeout=60, stream=True)
            resp.raise_for_status()
            with open(local_path, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.debug(f"Successfully downloaded {url}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download {url}: {e}", exc_info=True)
        except IOError as e:
             logger.error(f"Failed to write blocklist file {local_path}: {e}", exc_info=True)
        except Exception as e:
             logger.error(f"An unexpected error occurred downloading {url}: {e}", exc_info=True)

    logger.info("Blocklist download process finished.")


def load_blocklists():
    """Loads all active blocklists from local files into the malicious_networks list."""
    global malicious_networks
    new_network_list = []
    loaded_count = 0
    entry_count = 0

    logger.info("Loading blocklists into memory list...")

    for url, active in blocklists.items():
        if not active:
            logger.debug(f"Skipping inactive blocklist: {url}")
            continue

        filename = url.split("/")[-1]
        filename = "".join(c if c.isalnum() or c in ['.', '-', '_'] else '_' for c in filename)
        local_path = os.path.join(DOWNLOAD_DIR, filename)

        if os.path.exists(local_path):
            # *** Use the URL as the list identifier ***
            list_identifier = url
            logger.debug(f"Parsing blocklist file: {local_path} (Identifier: {list_identifier})")
            try:
                count = 0
                if filename.endswith(".csv"):
                    count = _parse_csv_file_to_list(new_network_list, local_path, list_identifier, ip_column='Dst IP Address', comment_char='#', delimiter=',')
                elif filename.endswith(".txt") or filename.endswith(".netset"):
                     count = _parse_netset_file_to_list(new_network_list, local_path, list_identifier, comment_char='#')
                else:
                     logger.warning(f"Unsupported file extension for blocklist: {filename}. Attempting netset parse.")
                     count = _parse_netset_file_to_list(new_network_list, local_path, list_identifier, comment_char='#')

                if count > 0:
                    logger.info(f"Loaded {count} entries from {filename} (ID: {list_identifier})")
                    entry_count += count
                    loaded_count += 1
                else:
                    logger.warning(f"No entries loaded from {filename}. Check format or content.")

            except Exception as e:
                logger.error(f"Failed to parse blocklist file {local_path}: {e}", exc_info=True)
        else:
            logger.warning(f"Blocklist file not found for active list {url}: {local_path}. Please download first.")

    malicious_networks = new_network_list
    logger.info(f"Blocklist loading complete. Loaded {entry_count} entries from {loaded_count} files into list.")


def _add_entry_to_list(network_list, network_obj, list_identifier):
    """Adds a tuple of (ipaddress.ip_network, list_identifier) to the list."""
    # *** Store list_identifier (URL) instead of filename ***
    try:
        network_list.append((network_obj, list_identifier))
        return True
    except Exception as e:
        logger.error(f"Error adding network {network_obj} from list '{list_identifier}' to list: {e}", exc_info=True)
        return False

def _parse_ip_or_cidr(ip_str):
    """Parses a string as IP or CIDR, returning an ipaddress object or None."""
    try:
        return ipaddress.ip_network(ip_str, strict=False)
    except ValueError:
        logger.warning(f"Invalid IP/CIDR format '{ip_str}'. Skipping.")
        return None

def _parse_netset_file_to_list(network_list, filepath, list_identifier, comment_char='#'):
    """Parses files with one IP or CIDR per line and adds to a list."""
    # *** Uses list_identifier (URL) ***
    count = 0
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or (comment_char and line.startswith(comment_char)):
                    continue
                network_obj = _parse_ip_or_cidr(line)
                if network_obj:
                    if _add_entry_to_list(network_list, network_obj, list_identifier):
                        count += 1
    except IOError as e:
        logger.error(f"Could not read file {filepath}: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Error parsing netset file {filepath}: {e}", exc_info=True)
    return count

def _parse_csv_file_to_list(network_list, filepath, list_identifier, ip_column='IP', comment_char='#', delimiter=','):
    """Parses CSV files, extracting IPs/CIDRs from a specific column and adds to a list."""
     # *** Uses list_identifier (URL) ***
    count = 0
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as csvfile:
            lines = (line for line in csvfile if not line.strip().startswith(comment_char))
            reader = csv.DictReader(lines, delimiter=delimiter)
            if ip_column not in reader.fieldnames:
                 logger.error(f"IP column '{ip_column}' not found in CSV file: {filepath}. Field names: {reader.fieldnames}")
                 return 0

            for row in reader:
                ip_str = row.get(ip_column, '').strip()
                if not ip_str:
                    continue
                network_obj = _parse_ip_or_cidr(ip_str)
                if network_obj:
                    if _add_entry_to_list(network_list, network_obj, list_identifier):
                        count += 1
    except IOError as e:
        logger.error(f"Could not read CSV file {filepath}: {e}", exc_info=True)
    except csv.Error as e:
         logger.error(f"CSV parsing error in file {filepath}, line {reader.line_num}: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Error parsing CSV file {filepath}: {e}", exc_info=True)
    return count


def identify_malicious_ip(ip_str: str) -> set:
    """
    Check if an IP address string falls within any network in the malicious_networks list.

    Args:
        ip_str: The IP address string to check.

    Returns:
        A set containing the original identifiers (URLs) of the blocklists
        the IP was found in, or an empty set if not found or invalid input.
    """
    global malicious_networks
    matched_lists = set()
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        # *** Iterate through (network, list_identifier) tuples ***
        for network, list_identifier in malicious_networks:
            if ip_obj in network:
                matched_lists.add(list_identifier) # Add the URL/identifier
    except ValueError:
        logger.debug(f"Invalid IP string passed to identify_malicious_ip: {ip_str}")
        return set()
    except Exception as e:
        logger.error(f"Error during list lookup for IP '{ip_str}': {e}", exc_info=True)
        return set()

    return matched_lists # Returns a set of URLs

