# Configuration

The application provides several configuration windows to customize the detection mechanisms.

## Unsafe Protocols

-   **Ports:** A comma-separated list of ports to be considered unsafe.
-   **Protocols:** A comma-separated list of protocols to be considered unsafe.

## Scan Detection

-   **Time Window (s):** The time window in seconds to analyze packets for scan patterns.
-   **Ports Threshold:** Number of connections to distinct ports on a single host to trigger a port scan alert.
-   **Hosts Threshold:** Number of connections to distinct hosts to trigger a host scan alert.
-   **Scan Check Interval (s):** The interval in seconds between per-IP scan checks to limit resource usage.
-   **Enable Stealth Scan Detection:** Enable detection of stealthy scan techniques like FIN, NULL, and XMAS scans.
-   **Flag Internal Scans:** Flag scans originating from and targeting internal networks.
-   **Flag External Scans:** Flag scans originating from or targeting external networks.

## Beaconing Detection

-   **Interval (s):** Expected interval between connections.
-   **Tolerance (s):** Allowed deviation from the interval.
-   **Min Occurrences:** Number of regular connections to trigger an alert.

## DNS Analysis

-   **Entropy Threshold:** Shannon entropy threshold for detecting DGA domains. Higher values are more strict.
-   **Length Threshold:** Domain name length threshold for DGA detection.
-   **NXDOMAIN Rate Threshold:** Rate of NXDOMAIN responses (0.0-1.0) to trigger a tunneling alert.
-   **NXDOMAIN Min Count:** Minimum number of total DNS queries before checking the NXDOMAIN rate.

## Local Network Detection

-   **Enable ARP Spoofing Detection:** Enable detection of ARP spoofing.
-   **Enable ICMP Anomaly Detection:** Enable detection of ICMP anomalies.
-   **Ping Sweep Threshold:** Number of ICMP echo requests to distinct hosts to trigger a ping sweep alert.
-   **Large Payload Threshold:** ICMP payload size in bytes to trigger a large payload (tunneling) alert.

## Scoring

-   This window allows you to configure the points assigned to each detection mechanism.
