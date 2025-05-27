**I. Enhancements to Existing Detection Mechanisms:**

*   **Advanced Port Scan Detection (`data_manager.py`):**
    *   Improve stealth scan detection (e.g., sliding windows).
    *   Configurable internal vs. external scan flagging.
*   **Smarter Threat Intelligence (`blocklist_integration.py`, `main.py`):**
    *   Periodic (automatic) blocklist updates and reloading.
    *   Add more infos to the specific Hit from the blocklist
*   **Refined Anomaly Detection (Packet Rates in `data_manager.py`):**
    *   Detect protocol-specific rate anomalies (e.g., unusual spike in DNS or ICMP traffic from one host).

**II. New Detection Features:**

*   **Periodic Beaconing Detection (`data_manager.py`):**
    *   Identify regular, timed C&C connections by analyzing connection intervals to external hosts.
    *   Configurable: interval parameters, tolerance, min occurrences.
*   **JA3/JA3S TLS Fingerprinting (`capture.py`, `data_manager.py`, `blocklist_integration.py`):**
    *   Compute JA3/JA3S hashes for TLS handshakes.
        *   **What:** JA3 fingerprints how a client initiates a TLS (HTTPS) session by hashing fields from the Client Hello. JA3S fingerprints the server's response (Server Hello).
        *   **Why:** Malware often has unique TLS negotiation characteristics. These fingerprints can identify known malicious clients/servers even if traffic is encrypted, without decryption. Helps detect C&C or connections to malicious sites.
    *   Check hashes against dedicated JA3 blocklists.
    *   Requires external library (e.g., `ja3-scapy`).
*   **Enhanced DNS Analysis (`data_manager.py`, `capture.py`):**
    *   Heuristics for DGA detection (entropy, char sequences, length).
    *   DNS Tunneling Indicators:
        *   **Why use DNS Tunneling:** Technique to exfiltrate data or establish C&C by encoding data in DNS queries/responses, often bypassing firewalls as DNS traffic is usually allowed.
        *   **How (Indicators):**
            *   High NXDOMAIN rate per IP (attacker tries many non-existent domains to send data).
            *   Anomalous DNS query types (e.g., TXT, NULL, which can carry more data) or unusually large query/response payloads.
    *   Configurable: thresholds for NXDOMAIN rate, query length.
*   **Local Network Threat Detection (`capture.py`, `data_manager.py`):**
    *   ARP Spoofing: Monitor ARP traffic for IP-MAC mapping anomalies.
        *   **What:** ARP Spoofing (or ARP Poisoning) is an attack where a malicious actor sends forged ARP messages on a local network. This allows the attacker to associate their MAC address with another host's IP (e.g., the gateway), redirecting traffic through the attacker for man-in-the-middle attacks.
    *   ICMP Anomalies:
        *   Ping sweeps (internal).
        *   Basic ICMP tunneling detection (large payloads).

**III. General & Architectural Suggestions:**

*   **Alert Correlation/Scoring:** Develop a system to combine weak signals into higher-priority alerts.
*   **Data Enrichment (Future):**
    *   GeoIP lookup for external IPs.
    *   Async WHOIS lookups.
