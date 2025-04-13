# config/globals.py
"""
Global configuration settings for the detection script.

This module stores shared configuration data like unsafe port/protocol lists
and protocols tracked for temporal analysis.
"""

# --- Unsafe Ports/Protocols Configuration ---
# These sets define ports and protocol names considered potentially risky or
# indicative of suspicious activity. They are used for highlighting in the GUI
# if the corresponding "Flag Unsafe" option is enabled.

# Set of integer port numbers considered unsafe.
# Examples based on commonly abused services or malware C&C ports.
UNSAFE_PORTS = {
    23,     # Telnet (unencrypted)
    445,    # SMB (often exploited)
     666,    # Commonly associated with trojans (e.g., Doom) 
     8085,   # Example: Koobface variant proxy 
    3389,   # RDP (if exposed, can be vulnerable)
    1080,   # SOCKS Proxy (can be used maliciously)
    3128,   # Common HTTP Proxy port (can be abused)
    6667,   # IRC (often used for botnet C&C)
    # Add more ports as needed based on security policies or observed threats
}

# Set of protocol names (lowercase strings) considered unsafe or suspicious.
# Examples include unencrypted protocols or those commonly used by botnets.
UNSAFE_PROTOCOLS = {
    "telnet",     # Unencrypted remote login
    "ftp",        # Unencrypted file transfer
    "irc",        # Chat protocol often used by botnets
     "rdp",      # RDP uses TCP port 3389, covered by UNSAFE_PORTS
     "smb",      # SMB uses TCP port 445, covered by UNSAFE_PORTS
    "pop3",       # Unencrypted email retrieval
    "imap",       # Unencrypted email retrieval (unless over SSL/TLS)
     "nfs",      # Network File System (can be risky if misconfigured)
     "snmp",     # Can leak info if misconfigured (often UDP 161/162)
    # Add more protocol names (as identified by Scapy, e.g., 'gre', 'igmp') if needed
}


# --- Temporal Analysis Configuration ---

# Set of protocol names (lowercase strings) to track specifically
# in the temporal analysis graphs when the breakdown is enabled.
# Others will still contribute to the "Total Packets" count.
TRACKED_PROTOCOLS = {
    "tcp",
    "udp",
    "icmp", # Example: Add ICMP tracking
    "other" # Catch-all for protocols not TCP/UDP/ICMP
}

# --- Data Pruning Configuration ---
# Time in seconds after which an inactive IP address entry will be
# removed from the main statistics dictionary (`ip_data`) to save memory.
# 3600 seconds = 1 hour
IP_DATA_PRUNE_TIMEOUT = 3600

