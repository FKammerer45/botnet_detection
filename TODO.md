unterschiedliche attack strategien hinzufügen
steuerung des ESP mit ? Webinterface,cmd line?

--- NEW SUGGESTIONS (Botnet Detection Tool) ---

**I. Enhancements to Existing Detection Mechanisms:**

*   **Advanced Scan Detection (`data_manager.py`):**
    *   Differentiate TCP Connect scans, UDP scans.
    *   Improve stealth scan detection (e.g., sliding windows).
    *   Configurable internal vs. external scan flagging.
*   **Smarter Threat Intelligence (`blocklist_integration.py`, `main.py`):**
    *   Periodic (automatic) blocklist updates and reloading.
    *   Ensure GUI clearly shows which blocklist source caused a hit.
*   **Refined Anomaly Detection (Packet Rates in `data_manager.py`):**
    *   Implement per-IP dynamic baselining for packet rates.
    *   Detect protocol-specific rate anomalies (e.g., unusual spike in DNS or ICMP traffic from one host).

**II. New Detection Features:**

*   **Periodic Beaconing Detection (`data_manager.py`):**
    *   Identify regular, timed C&C connections by analyzing connection intervals to external hosts.
    *   Configurable: interval parameters, tolerance, min occurrences.
*   **JA3/JA3S TLS Fingerprinting (`capture.py`, `data_manager.py`, `blocklist_integration.py`):**
    *   Compute JA3/JA3S hashes for TLS handshakes.
    *   Check hashes against dedicated JA3 blocklists.
    *   Requires external library (e.g., `ja3-scapy`).
*   **Enhanced DNS Analysis (`data_manager.py`, `capture.py`):**
    *   Heuristics for DGA detection (entropy, char sequences, length).
    *   DNS Tunneling Indicators:
        *   High NXDOMAIN rate per IP.
        *   Anomalous DNS query types (TXT, NULL) or large query/response payloads.
    *   Configurable: thresholds for NXDOMAIN rate, query length.
*   **Local Network Threat Detection (`capture.py`, `data_manager.py`):**
    *   ARP Spoofing: Monitor ARP traffic for IP-MAC mapping anomalies.
    *   ICMP Anomalies:
        *   Ping sweeps (internal).
        *   Basic ICMP tunneling detection (large payloads).

**III. General & Architectural Suggestions:**

*   **Alert Correlation/Scoring:** Develop a system to combine weak signals into higher-priority alerts.
*   **Configuration for All New Features:** Ensure all new detection logic is configurable (on/off, thresholds) via `config.ini`.
*   **Data Enrichment (Future):**
    *   GeoIP lookup for external IPs.
    *   Async WHOIS lookups.
*   **Plugin System for Detection Modules (Future Refactor):** For easier addition of new detection techniques.
