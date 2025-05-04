# core/whitelist_manager.py
import ipaddress
import logging
import os
# Import constants from globals
from config.globals import WHITELIST_FILENAME

logger = logging.getLogger(__name__)

# --- Whitelist Class Definition ---
class Whitelist:
    """Manages whitelisted IPs, networks, and domains."""

    def __init__(self, filepath=WHITELIST_FILENAME):
        self.filepath = filepath
        self.ip_networks = set() # Store ipaddress.ip_network objects
        self.domains = set()     # Store lowercase domain strings
        self.load_whitelist()

    def load_whitelist(self):
        """Loads whitelist entries from the specified file."""
        new_ip_networks = set()
        new_domains = set()
        loaded_ips = 0
        loaded_domains = 0

        if not os.path.exists(self.filepath):
            logger.warning(f"Whitelist file '{self.filepath}' not found. No entries loaded.")
            # Optionally create an empty file
            try: open(self.filepath, 'a').close()
            except IOError: logger.error(f"Could not create whitelist file {self.filepath}")
            self.ip_networks = new_ip_networks
            self.domains = new_domains
            return

        logger.info(f"Loading whitelist from {self.filepath}")
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Try parsing as IP/CIDR first
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                        new_ip_networks.add(network)
                        loaded_ips += 1
                        logger.debug(f"Whitelisted IP/Network: {network}")
                        continue # Successfully parsed as IP/network
                    except ValueError:
                        # If not IP/CIDR, treat as potential domain
                        pass

                    # Treat as domain (basic validation)
                    domain = line.lower()
                    if '.' in domain and not domain.startswith('.') and not domain.endswith('.'):
                        # Add more robust domain validation if needed
                        new_domains.add(domain)
                        loaded_domains += 1
                        logger.debug(f"Whitelisted Domain: {domain}")
                    else:
                        logger.warning(f"Ignoring invalid whitelist entry on line {line_num}: '{line}'")

            self.ip_networks = new_ip_networks
            self.domains = new_domains
            logger.info(f"Whitelist loading complete. Loaded {loaded_ips} IP/Network entries and {loaded_domains} Domain entries.")

        except IOError as e:
            logger.error(f"Could not read whitelist file {self.filepath}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error loading whitelist: {e}", exc_info=True)

    def is_ip_whitelisted(self, ip_str: str) -> bool:
        """Checks if an IP address is covered by any whitelisted network."""
        if not ip_str: return False
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for network in self.ip_networks:
                if ip_obj in network:
                    logger.debug(f"IP {ip_str} is whitelisted by network {network}.")
                    return True
            return False
        except ValueError:
            logger.debug(f"Invalid IP format for whitelist check: {ip_str}")
            return False
        except Exception as e:
             logger.error(f"Error checking IP whitelist for {ip_str}: {e}", exc_info=True)
             return False

    def is_domain_whitelisted(self, domain: str) -> bool:
        """Checks if a domain is exactly whitelisted (case-insensitive)."""
        if not domain: return False
        domain_lower = domain.lower().strip('.')
        whitelisted = domain_lower in self.domains
        if whitelisted:
             logger.debug(f"Domain {domain_lower} is whitelisted.")
        return whitelisted

# --- Singleton Access Function ---
_whitelist_instance = None

def get_whitelist():
    """Returns the singleton Whitelist instance, creating it if necessary."""
    global _whitelist_instance
    if _whitelist_instance is None:
        logger.debug("Creating singleton Whitelist instance.")
        _whitelist_instance = Whitelist()
    return _whitelist_instance


