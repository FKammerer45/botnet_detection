# globals.py
"""
Globals for storing unsafe ports and protocols.
Import from your other modules to access or modify these sets.
"""

# Known malicious or heavily abused ports:
# - 23 (Telnet)
# - 445 (SMB)
# - 666 (commonly trojan 'doom' or 'rtb666')
# - 8085 (Koobface variant proxy)
# - 3389 (RDP)
# - 1080 (SOCKS proxy)
# - 3128 (Common HTTP proxy)
# etc.
UNSAFE_PORTS = {
    23,
    445,
    666,
    8085,
    3389,
    1080,
    3128,
}

# Potentially suspicious or outdated protocols:
# - "telnet", "ftp", "irc", "rdp", "smb", "pop3", "imap", etc.
# This list is arbitrary; add or remove as suits your environment.
UNSAFE_PROTOCOLS = {
    "telnet",     # unencrypted remote login
    "ftp",        # unencrypted file transfer
    "irc",        # chat protocol widely used by some botnets
    "rdp",        # can be abused if exposed to the internet
    "smb",        # Windows shares
    "pop3",       # unencrypted mail
    "imap",       # unencrypted mail
    "nfs",        # network file system, can be risky if open
    "snmp",       # can leak sensitive info if misconfigured
    # Add more as needed...
}

# If you plan to support port ranges or protocol+port combos,
# you can define more data structures here.
# For example:
# UNSAFE_RULES = []

# Just a set of protocols (or protocol names) we consider relevant for plotting
TRACKED_PROTOCOLS = {
    "tcp",
    "udp",
    "other"  # or "icmp", etc.—whatever your aggregator might store
}