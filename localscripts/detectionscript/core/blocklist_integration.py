import os
import requests
import csv

FIREHOL_BASE_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"
FIREHOL_LISTS = [
    "iblocklist_abuse_zeus.netset",
    "dshield.netset",
    "spamhaus_drop.netset",
    "spamhaus_edrop.netset"
]
ABUSE_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"
ABUSE_SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv"

DOWNLOAD_DIR = "blocklists"

# We'll store (ip_network, list_name) in malicious_networks
malicious_networks = []


def download_blocklists():
    if not os.path.exists(DOWNLOAD_DIR):
        os.mkdir(DOWNLOAD_DIR)

    # 1. FireHol-based
    for netset_file in FIREHOL_LISTS:
        url = f"{FIREHOL_BASE_URL}/{netset_file}"
        local_path = os.path.join(DOWNLOAD_DIR, netset_file)
        print(f"Downloading {url} -> {local_path}")
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        with open(local_path, 'wb') as f:
            f.write(resp.content)

    # 2. Feodo (plain text IPs/CIDRs)
    feodo_path = os.path.join(DOWNLOAD_DIR, "feodo_aggressive.txt")
    print(f"Downloading {ABUSE_FEODO_URL} -> {feodo_path}")
    resp_feodo = requests.get(ABUSE_FEODO_URL, timeout=30)
    resp_feodo.raise_for_status()
    with open(feodo_path, 'wb') as f:
        f.write(resp_feodo.content)

    # 3. SSLBL (CSV)
    sslbl_path = os.path.join(DOWNLOAD_DIR, "sslipblacklist_aggressive.csv")
    print(f"Downloading {ABUSE_SSLBL_URL} -> {sslbl_path}")
    resp_sslbl = requests.get(ABUSE_SSLBL_URL, timeout=30)
    resp_sslbl.raise_for_status()
    with open(sslbl_path, 'wb') as f:
        f.write(resp_sslbl.content)


def load_blocklists():
    global malicious_networks
    malicious_networks.clear()

    # 1. Parse FireHol netset files
    for netset_file in FIREHOL_LISTS:
        local_path = os.path.join(DOWNLOAD_DIR, netset_file)
        if os.path.exists(local_path):
            _parse_blocklist_file(
                filepath=local_path, 
                list_name=netset_file, 
                filetype='netset'
            )

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