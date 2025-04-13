# core/dns_blocklist_integration.py
import os
import requests
import logging
import re

# Get a logger for this module
logger = logging.getLogger(__name__)

# --- Configuration ---
# Dictionary mapping blocklist URL -> active status (similar to IP blocklists)
# Add URLs to reputable domain blocklists here (e.g., StevenBlack hosts list)
# Example using a common format (hosts file):
# Note: Parsing needs to handle different formats correctly.
dns_blocklists = {
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts": True,
    # Add other domain lists as needed
    # "https://some.other.domain.list/domains.txt": True,
}

DOWNLOAD_DIR = "blocklists" # Use the same download directory as IP lists
# Set to store malicious domains (lowercase) for fast lookups
malicious_domains = set()

# --- Functions ---

def download_dns_blocklists():
    """Downloads all active domain blocklists."""
    if not os.path.exists(DOWNLOAD_DIR):
        try:
            os.mkdir(DOWNLOAD_DIR)
            logger.info(f"Created blocklist download directory: {DOWNLOAD_DIR}")
        except OSError as e:
            logger.error(f"Failed to create blocklist directory {DOWNLOAD_DIR}: {e}", exc_info=True)
            return

    active_lists = {url for url, active in dns_blocklists.items() if active}
    logger.info(f"Starting download for {len(active_lists)} active DNS blocklists...")

    for url in active_lists:
        # Generate a filename (consider sanitizing more robustly if needed)
        try:
            base_name = url.split('/')[-1]
            if not base_name: # Handle URLs ending with /
                 base_name = url.split('/')[-2]
            filename = f"dns_{base_name}" # Prefix to distinguish from IP lists
            filename = "".join(c if c.isalnum() or c in ['.', '-', '_'] else '_' for c in filename)
        except IndexError:
             filename = f"dns_{hash(url)}.txt" # Fallback filename

        local_path = os.path.join(DOWNLOAD_DIR, filename)
        logger.debug(f"Attempting to download DNS list {url} -> {local_path}")
        try:
            resp = requests.get(url, timeout=60, stream=True)
            resp.raise_for_status()
            with open(local_path, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.debug(f"Successfully downloaded {url}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download DNS list {url}: {e}", exc_info=True)
        except IOError as e:
             logger.error(f"Failed to write DNS blocklist file {local_path}: {e}", exc_info=True)
        except Exception as e:
             logger.error(f"An unexpected error occurred downloading DNS list {url}: {e}", exc_info=True)

    logger.info("DNS blocklist download process finished.")


def load_dns_blocklists():
    """Loads domains from active blocklist files into the malicious_domains set."""
    global malicious_domains
    new_domain_set = set()
    loaded_files = 0
    loaded_domains = 0

    logger.info("Loading DNS blocklists into memory set...")

    for url, active in dns_blocklists.items():
        if not active:
            continue

        # Generate filename consistently with download function
        try:
            base_name = url.split('/')[-1]
            if not base_name: base_name = url.split('/')[-2]
            filename = f"dns_{base_name}"
            filename = "".join(c if c.isalnum() or c in ['.', '-', '_'] else '_' for c in filename)
        except IndexError:
             filename = f"dns_{hash(url)}.txt"

        local_path = os.path.join(DOWNLOAD_DIR, filename)

        if os.path.exists(local_path):
            logger.debug(f"Parsing DNS blocklist file: {local_path}")
            try:
                count = 0
                # Add parsing logic based on expected format (e.g., hosts file, simple list)
                # Example for hosts file format (lines like '0.0.0.0 domain.com' or '127.0.0.1 domain.com')
                # and simple domain lists
                with open(local_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        # Skip comments and empty lines
                        if not line or line.startswith('#'):
                            continue

                        parts = line.split()
                        domain = None
                        # Check for hosts file format (IP address followed by domain)
                        if len(parts) >= 2 and (parts[0] == '0.0.0.0' or parts[0] == '127.0.0.1'):
                             # Check if the second part looks like a domain
                             potential_domain = parts[1].lower()
                             # Basic domain validation (adjust regex as needed)
                             if re.match(r'^[a-zA-Z0-9.-]+$', potential_domain):
                                 domain = potential_domain
                        # Check for simple domain list format (just the domain on the line)
                        elif len(parts) == 1:
                             potential_domain = parts[0].lower()
                             if re.match(r'^[a-zA-Z0-9.-]+$', potential_domain):
                                 domain = potential_domain

                        # Add valid domain to set
                        if domain:
                            new_domain_set.add(domain)
                            count += 1

                if count > 0:
                    logger.info(f"Loaded {count} domains from {filename}")
                    loaded_domains += count
                    loaded_files += 1
                else:
                    logger.warning(f"No domains loaded from {filename}. Check format/content.")

            except Exception as e:
                 logger.error(f"Failed to parse DNS blocklist file {local_path}: {e}", exc_info=True)
        else:
            logger.warning(f"DNS blocklist file not found for active list {url}: {local_path}. Please download first.")

    # Replace old set with the new one
    malicious_domains = new_domain_set
    logger.info(f"DNS blocklist loading complete. Loaded {loaded_domains} domains from {loaded_files} files.")


def is_domain_malicious(domain: str) -> bool:
    """
    Checks if a domain (or its parent domains) exists in the malicious set.
    Performs exact match and checks parent domains (e.g., checks example.com if sub.example.com is queried).
    """
    global malicious_domains
    if not domain:
        return False

    domain_lower = domain.lower().strip('.') # Normalize: lowercase, remove trailing dot

    # Simple exact match check first
    if domain_lower in malicious_domains:
        logger.debug(f"Exact match found for domain '{domain_lower}' in DNS blocklist.")
        return True

    # Check parent domains (e.g., for sub.example.com, check example.com)
    parts = domain_lower.split('.')
    # Check domains like: sub.example.com -> example.com -> com (stop before TLD usually)
    for i in range(1, len(parts) - 1): # Check parent domains, stopping before TLD
        parent_domain = '.'.join(parts[i:])
        if parent_domain in malicious_domains:
            logger.debug(f"Parent domain '{parent_domain}' for query '{domain_lower}' found in DNS blocklist.")
            return True

    return False

