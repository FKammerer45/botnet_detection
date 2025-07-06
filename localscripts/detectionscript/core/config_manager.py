# core/config_manager.py
import configparser
import logging
import os
from ast import literal_eval # For safely evaluating lists/sets from strings

logger = logging.getLogger(__name__)

CONFIG_FILENAME = "config.ini"

class AppConfig:
    """Holds the application configuration loaded from config.ini."""

    def __init__(self, filepath=CONFIG_FILENAME):
        self.filepath = filepath
        # *** FIX: Specify delimiters to only use '=' ***
        self.parser = configparser.ConfigParser(
            inline_comment_prefixes=('#', ';'),
            delimiters=('=',) # Only use '=' as the key-value separator
        )
        self._load_defaults()
        self.load_config() # Load config after defaults are set

    def _load_defaults(self):
        """Set default values before loading from file."""
        # General
        self.log_level = "INFO"
        self.ip_data_prune_timeout = 3600

        # Thresholds
        self.max_packets_per_second = 1000
        self.max_packets_per_minute = 5000
        # Scan Detection
        self.scan_time_window = 60
        self.scan_distinct_ports_threshold = 15
        self.scan_distinct_hosts_threshold = 10
        self.scan_check_interval = 5
        self.enable_stealth_scan_detection = True
        self.flag_internal_scans = True
        self.flag_external_scans = True
        self.local_networks = {"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}
        # Rate Anomaly
        self.enable_rate_anomaly_detection = True
        self.rate_anomaly_sensitivity = 5.0
        self.rate_anomaly_min_packets = 50
        self.rate_anomaly_protocols_to_track = {"tcp", "udp", "icmp"}
        # Unsafe Rules
        self.unsafe_ports = {23, 445, 3389, 1080, 3128, 6667}
        self.unsafe_protocols = {"telnet", "ftp", "irc", "pop3", "imap"}

        # Blocklists (URLs only, description is ignored here but useful in INI)
        self.ip_blocklist_urls = {
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset": "DShield All",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset": "Spamhaus DROP",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_edrop.netset": "Spamhaus eDROP",
            "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt": "Feodo Tracker Aggressive",
        }
        self.dns_blocklist_urls = {
             "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts": "StevenBlack Hosts",
        }
        self.blocklist_update_interval_hours = 24 # New setting for auto-updates

        # Display
        self.tracked_protocols_temporal = {"tcp", "udp", "icmp", "other"}

    def _get_set_from_config(self, section, option, default_set, item_type=str):
        """Helper to safely parse comma-separated values into a set."""
        try:
            value_str = self.parser.get(section, option, fallback=None)
            if value_str is None: return default_set
            items = {item_type(item.strip()) for item in value_str.split(',') if item.strip()}
            return items
        except (configparser.NoSectionError, configparser.NoOptionError): return default_set # Use default if missing
        except ValueError: logger.error(f"Invalid format for {section}/{option}. Using default."); return default_set
        except Exception as e: logger.error(f"Error reading {section}/{option}: {e}. Using default.", exc_info=True); return default_set

    def _get_dict_from_config_section(self, section):
        """Helper to read a section where keys are URLs and values are descriptions."""
        try:
            if self.parser.has_section(section):
                # Read items, strip potential inline comments after '='
                # Ensure using '=' as the delimiter was set during init
                return {url.strip(): desc.split('#')[0].strip() if desc else ""
                        for url, desc in self.parser.items(section)}
            else: logger.warning(f"Section '[{section}]' not found in config file."); return {}
        except Exception as e: logger.error(f"Error reading section [{section}]: {e}. Returning empty dict.", exc_info=True); return {}

    def load_config(self):
        """Loads configuration from the INI file, overriding defaults."""
        if not os.path.exists(self.filepath):
            logger.warning(f"Config file '{self.filepath}' not found. Using default settings."); return

        try:
            read_ok = self.parser.read(self.filepath)
            if not read_ok:
                 logger.error(f"Failed to read config file: {self.filepath}. Check permissions/path.")
                 return # Stop if file couldn't be read

            logger.info(f"Loading configuration from {self.filepath}")

            # General
            self.log_level = self.parser.get('General', 'log_level', fallback=self.log_level).upper()
            self.ip_data_prune_timeout = self.parser.getint('General', 'ip_data_prune_timeout', fallback=self.ip_data_prune_timeout)

            # Thresholds
            self.max_packets_per_second = self.parser.getint('Thresholds', 'max_packets_per_second', fallback=self.max_packets_per_second)
            self.max_packets_per_minute = self.parser.getint('Thresholds', 'max_packets_per_minute', fallback=self.max_packets_per_minute) # Load the new setting

            # Scan Detection
            self.scan_time_window = self.parser.getint('ScanDetection', 'time_window_seconds', fallback=self.scan_time_window)
            self.scan_distinct_ports_threshold = self.parser.getint('ScanDetection', 'distinct_ports_threshold', fallback=self.scan_distinct_ports_threshold)
            self.scan_distinct_hosts_threshold = self.parser.getint('ScanDetection', 'distinct_hosts_threshold', fallback=self.scan_distinct_hosts_threshold)
            self.scan_check_interval = self.parser.getfloat('ScanDetection', 'scan_check_interval', fallback=float(self.scan_check_interval))
            self.enable_stealth_scan_detection = self.parser.getboolean('ScanDetection', 'enable_stealth_scan_detection', fallback=self.enable_stealth_scan_detection)
            self.flag_internal_scans = self.parser.getboolean('ScanDetection', 'flag_internal_scans', fallback=self.flag_internal_scans)
            self.flag_external_scans = self.parser.getboolean('ScanDetection', 'flag_external_scans', fallback=self.flag_external_scans)
            self.local_networks = self._get_set_from_config('ScanDetection', 'local_networks', self.local_networks)

            # Rate Anomaly
            self.enable_rate_anomaly_detection = self.parser.getboolean('RateAnomaly', 'enable_rate_anomaly_detection', fallback=self.enable_rate_anomaly_detection)
            self.rate_anomaly_sensitivity = self.parser.getfloat('RateAnomaly', 'rate_anomaly_sensitivity', fallback=self.rate_anomaly_sensitivity)
            self.rate_anomaly_min_packets = self.parser.getint('RateAnomaly', 'rate_anomaly_min_packets', fallback=self.rate_anomaly_min_packets)
            self.rate_anomaly_protocols_to_track = self._get_set_from_config('RateAnomaly', 'rate_anomaly_protocols_to_track', self.rate_anomaly_protocols_to_track)

            # Unsafe Rules
            self.unsafe_ports = self._get_set_from_config('UnsafeRules', 'ports', self.unsafe_ports, item_type=int)
            self.unsafe_protocols = self._get_set_from_config('UnsafeRules', 'protocols', self.unsafe_protocols, item_type=str)

            # Blocklists
            self.ip_blocklist_urls = self._get_dict_from_config_section('Blocklists_IP')
            self.dns_blocklist_urls = self._get_dict_from_config_section('Blocklists_DNS')
            self.blocklist_update_interval_hours = self.parser.getint('Blocklists', 'update_interval_hours', fallback=self.blocklist_update_interval_hours)

            # Display
            self.tracked_protocols_temporal = self._get_set_from_config('Display', 'tracked_protocols_temporal', self.tracked_protocols_temporal, item_type=str)

        except configparser.Error as e: logger.error(f"Error parsing config file {self.filepath}: {e}", exc_info=True)
        except Exception as e: logger.error(f"Unexpected error loading config: {e}", exc_info=True)

    def save_config(self):
        """Saves the current configuration back to the INI file."""
        logger.info(f"Attempting to save configuration to {self.filepath}")
        try:
            # Ensure sections exist before setting
            sections = ['General', 'Thresholds', 'ScanDetection', 'RateAnomaly', 'UnsafeRules', 'Blocklists_IP', 'Blocklists_DNS', 'Display']
            for section in sections:
                if not self.parser.has_section(section): self.parser.add_section(section)

            # General
            self.parser.set('General', 'log_level', self.log_level)
            self.parser.set('General', 'ip_data_prune_timeout', str(self.ip_data_prune_timeout))
            # Thresholds
            self.parser.set('Thresholds', 'max_packets_per_second', str(self.max_packets_per_second))
            self.parser.set('Thresholds', 'max_packets_per_minute', str(self.max_packets_per_minute)) # Save the new setting
    
            # Scan Detection
            self.parser.set('ScanDetection', 'time_window_seconds', str(self.scan_time_window))
            self.parser.set('ScanDetection', 'distinct_ports_threshold', str(self.scan_distinct_ports_threshold))
            self.parser.set('ScanDetection', 'distinct_hosts_threshold', str(self.scan_distinct_hosts_threshold))
            self.parser.set('ScanDetection', 'scan_check_interval', str(self.scan_check_interval))
            self.parser.set('ScanDetection', 'enable_stealth_scan_detection', str(self.enable_stealth_scan_detection))
            self.parser.set('ScanDetection', 'flag_internal_scans', str(self.flag_internal_scans))
            self.parser.set('ScanDetection', 'flag_external_scans', str(self.flag_external_scans))
            self.parser.set('ScanDetection', 'local_networks', ', '.join(sorted(list(self.local_networks))))

            # Rate Anomaly
            self.parser.set('RateAnomaly', 'enable_rate_anomaly_detection', str(self.enable_rate_anomaly_detection))
            self.parser.set('RateAnomaly', 'rate_anomaly_sensitivity', str(self.rate_anomaly_sensitivity))
            self.parser.set('RateAnomaly', 'rate_anomaly_min_packets', str(self.rate_anomaly_min_packets))
            self.parser.set('RateAnomaly', 'rate_anomaly_protocols_to_track', ', '.join(sorted(list(self.rate_anomaly_protocols_to_track))))
    
            # Unsafe Rules
            self.parser.set('UnsafeRules', 'ports', ', '.join(map(str, sorted(list(self.unsafe_ports)))))
            self.parser.set('UnsafeRules', 'protocols', ', '.join(sorted(list(self.unsafe_protocols))))
            # Display
            self.parser.set('Display', 'tracked_protocols_temporal', ', '.join(sorted(list(self.tracked_protocols_temporal))))

            # Blocklists - Overwrite sections completely
            if not self.parser.has_section('Blocklists'): self.parser.add_section('Blocklists')
            self.parser.set('Blocklists', 'update_interval_hours', str(self.blocklist_update_interval_hours))
            self.parser.remove_section('Blocklists_IP'); self.parser.add_section('Blocklists_IP')
            for url, desc in self.ip_blocklist_urls.items(): self.parser.set('Blocklists_IP', url, desc)
            self.parser.remove_section('Blocklists_DNS'); self.parser.add_section('Blocklists_DNS')
            for url, desc in self.dns_blocklist_urls.items(): self.parser.set('Blocklists_DNS', url, desc)

            with open(self.filepath, 'w') as configfile:
                self.parser.write(configfile)
            logger.info(f"Configuration successfully saved to {self.filepath}")

        except Exception as e: logger.error(f"Error saving configuration to {self.filepath}: {e}", exc_info=True)

# Create a single instance to be imported by other modules
config = AppConfig()
