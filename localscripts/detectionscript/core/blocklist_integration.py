#blocklist_integration.py
import os
import requests
import csv

FIREHOL_BASE_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"

# Dynamic blocklists storage: URL => Active/Inactive
blocklists = {
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/iblocklist_abuse_zeus.netset": True,
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset": True,
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset": True,
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_edrop.netset": True,
    "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt": True,
    "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv": True,
}

DOWNLOAD_DIR = "blocklists"
malicious_networks = []


def download_blocklists():
    if not os.path.exists(DOWNLOAD_DIR):
        os.mkdir(DOWNLOAD_DIR)

    for url, active in blocklists.items():
        if not active:
            continue  # Skip inactive blocklists

        filename = url.split("/")[-1]
        local_path = os.path.join(DOWNLOAD_DIR, filename)
        print(f"Downloading {url} -> {local_path}")
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            with open(local_path, 'wb') as f:
                f.write(resp.content)
        except requests.RequestException as e:
            print(f"Failed to download {url}: {e}")

def load_blocklists():
    global malicious_networks
    malicious_networks.clear()

    for url, active in blocklists.items():
        if not active:
            continue  # Skip inactive blocklists

        filename = url.split("/")[-1]
        local_path = os.path.join(DOWNLOAD_DIR, filename)
        if os.path.exists(local_path):
            if filename.endswith(".csv"):
                _parse_blocklist_file(local_path, url, filetype='csv', ip_column='IP')
            else:
                _parse_blocklist_file(local_path, url, filetype='netset')

    # 2. Parse Feodo text
    feodo_path = os.path.join(DOWNLOAD_DIR, "feodo_aggressive.txt")
    if os.path.exists(feodo_path):
        _parse_blocklist_file(
            filepath=feodo_path, 
            list_name="abusech_feodo", 
            filetype='netset'  # treat lines as netset or single IP
        )

    # 3. Parse SSLBL CSV
    sslbl_path = os.path.join(DOWNLOAD_DIR, "sslipblacklist_aggressive.csv")
    if os.path.exists(sslbl_path):
        _parse_blocklist_file(
            filepath=sslbl_path, 
            list_name="abusech_sslbl", 
            filetype='csv', 
            ip_column='IP'
        )


def _parse_blocklist_file(filepath, list_name, filetype='netset', ip_column='IP'):
    """
    Generic function that:
      - if filetype='netset', reads lines as IP or CIDR
      - if filetype='csv', looks for ip_column, parses IP or CIDR from that column
    """

    if filetype == 'csv':
        _parse_csv_file(filepath, list_name, ip_column)
    else:
        _parse_netset_file(filepath, list_name)


def _parse_netset_file(filepath, list_name):
    """Lines are IP or CIDR. If single IP, convert to /32"""
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Attempt parse as CIDR
            if _add_to_networks(line, list_name):
                continue
            # Maybe it's single IP -> /32
            if _add_single_ip(line, list_name):
                continue


def _parse_csv_file(filepath, list_name, ip_column='IP'):
    """
    e.g. SSLBL has a header line. We find ip_column, parse each row's IP or CIDR.
    """
    with open(filepath, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=';')
        if ip_column not in reader.fieldnames:
            return
        for row in reader:
            ip_str = row[ip_column].strip() if row[ip_column] else ''
            if not ip_str:
                continue
            # Attempt parse as CIDR, else /32
            if _add_to_networks(ip_str, list_name):
                continue
            _add_single_ip(ip_str, list_name)


def _add_to_networks(cidr_or_ip, list_name):
    """Try to parse `cidr_or_ip` as IP network. Return True if success."""
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr_or_ip)
        malicious_networks.append((net, list_name))
        return True
    except ValueError:
        return False

def _add_single_ip(ip_str, list_name):
    """Parse single IP as /32. Return True if success, else False."""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(f"{ip_obj}/32")
        malicious_networks.append((net, list_name))
        return True
    except ValueError:
        return False


def identify_malicious_ip(ip_str: str) -> list:
    """Check if ip_str belongs to any known malicious network(s)."""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return []

    matched_lists = []
    for (net, list_name) in malicious_networks:
        if ip_obj in net:
            matched_lists.append(list_name)
    return matched_lists
