# config/globals.py
"""
Global constants and potentially shared state (though prefer passing config).
Configuration values are now primarily managed by core.config_manager loading config.ini.
"""
import logging

logger = logging.getLogger(__name__)

# --- Constants (Not typically configured via INI) ---

# Max minutes to store in temporal data deque (per IP/protocol)
# 1440 minutes = 24 hours
MAX_MINUTES_TEMPORAL = 1440

# Directory for storing downloaded blocklist files
DOWNLOAD_DIR = "blocklists"

# Filename for the whitelist file
WHITELIST_FILENAME = "whitelist.txt"

# Filename for the configuration file
CONFIG_FILENAME = "config.ini"

logger.debug("Globals module loaded (most config now in core.config_manager).")

