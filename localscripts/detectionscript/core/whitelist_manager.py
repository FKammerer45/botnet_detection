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
        self.load_whitelist() # Initial load

    def add_entry(self, entry_str: str) -> tuple[bool, str]:
        """
        Adds a new entry (IP/network or domain) to the whitelist.
        Returns a tuple (success: bool, message_or_type: str).
        message_or_type is "ip", "domain" on success, or error message on failure.
        """
        entry_str = entry_str.strip()
        if not entry_str:
            return False, "Entry cannot be empty."

        # Try parsing as IP/CIDR first
        try:
            network = ipaddress.ip_network(entry_str, strict=False)
            if network not in self.ip_networks:
                self.ip_networks.add(network)
                logger.info(f"Added IP/Network to whitelist (in memory): {network}")
                return True, "ip"
            else:
                return False, "IP/Network already in whitelist."
        except ValueError:
            # If not IP/CIDR, treat as potential domain
            pass

        # Treat as domain
        domain = entry_str.lower()
        if '.' in domain and not domain.startswith('.') and not domain.endswith('.'):
            # Basic validation, can be improved
            if domain not in self.domains:
                self.domains.add(domain)
                logger.info(f"Added domain to whitelist (in memory): {domain}")
                return True, "domain"
            else:
                return False, "Domain already in whitelist."
        else:
            logger.warning(f"Invalid format for whitelist entry: '{entry_str}'")
            return False, f"Invalid IP/Network or Domain format: '{entry_str}'"

    def remove_ip_network(self, ip_network_str: str) -> bool:
        """Removes an IP/network from the whitelist."""
        ip_network_str = ip_network_str.strip()
        try:
            network_to_remove = ipaddress.ip_network(ip_network_str, strict=False)
            if network_to_remove in self.ip_networks:
                self.ip_networks.remove(network_to_remove)
                logger.info(f"Removed IP/Network from whitelist (in memory): {network_to_remove}")
                return True
            return False # Not found
        except ValueError:
            logger.warning(f"Attempted to remove invalid IP/Network format: {ip_network_str}")
            return False
            
    def remove_domain(self, domain_str: str) -> bool:
        """Removes a domain from the whitelist."""
        domain_str = domain_str.strip().lower()
        if domain_str in self.domains:
            self.domains.remove(domain_str)
            logger.info(f"Removed domain from whitelist (in memory): {domain_str}")
            return True
        return False # Not found

    def save_whitelist(self):
        """Saves the current whitelist entries back to the file."""
        logger.info(f"Saving whitelist to {self.filepath}")
        try:
            with open(self.filepath, 'w', encoding='utf-8') as f:
                # Write IPs/Networks, sorted for consistency
                sorted_ips = sorted([str(net) for net in self.ip_networks])
                for ip_entry in sorted_ips:
                    f.write(f"{ip_entry}\n")
                
                # Write Domains, sorted for consistency
                sorted_domains = sorted(list(self.domains))
                for domain_entry in sorted_domains:
                    f.write(f"{domain_entry}\n")
            logger.info(f"Whitelist saved successfully to {self.filepath}.")
            return True
        except IOError as e:
            logger.error(f"Could not write whitelist file {self.filepath}: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Unexpected error saving whitelist: {e}", exc_info=True)
            return False

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
                    original_line = line.strip() # For logging original if needed
                    if not original_line or original_line.startswith('#'):
                        continue
                    
                    # Remove inline comments and strip again
                    entry_to_parse = original_line.split('#')[0].strip()
                    if not entry_to_parse: # Line might have been only a comment after content
                        continue

                    # Try parsing as IP/CIDR first
                    try:
                        network = ipaddress.ip_network(entry_to_parse, strict=False)
                        new_ip_networks.add(network)
                        loaded_ips += 1
                        logger.debug(f"Whitelisted IP/Network: {network} (from line: '{original_line}')")
                        continue # Successfully parsed as IP/network
                    except ValueError:
                        # If not IP/CIDR, treat as potential domain
                        pass

                    # Treat as domain (basic validation)
                    domain = entry_to_parse.lower()
                    if '.' in domain and not domain.startswith('.') and not domain.endswith('.'):
                        # Add more robust domain validation if needed
                        new_domains.add(domain)
                        loaded_domains += 1
                        logger.debug(f"Whitelisted Domain: {domain} (from line: '{original_line}')")
                    else:
                        logger.warning(f"Ignoring invalid whitelist entry on line {line_num}: '{original_line}' (parsed as: '{entry_to_parse}')")

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
