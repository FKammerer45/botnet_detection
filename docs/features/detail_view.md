# Detail View

The detail view provides a more in-depth look at the activity of a specific IP address. It is accessed by double-clicking on an IP address in the main window.

## Tabs

The detail view is organized into several tabs, each providing a different perspective on the IP's activity:

-   **Destinations:** Shows all destination IPs this host has communicated with, along with packet counts.
-   **Protocols:** Shows all protocols and ports used by this host, along with packet counts.
-   **Threat Info:** Shows all malicious IPs, domains, and JA3/S fingerprints this host has communicated with, based on loaded blocklists.
-   **DNS Queries:** Shows all suspicious DNS queries made by this host that were found in the blocklists.
-   **Scan Activity:** Shows detected port and host scan activity originating from this host.
-   **Rate Anomaly:** Shows detected traffic rate anomalies for specific protocols used by this host.
-   **Beaconing:** Shows detected Command & Control (C2) beaconing activity from this host to external destinations.
-   **DNS Analysis:** Shows advanced DNS analysis, including DGA and DNS tunneling detection.
-   **Local Network:** Shows detected local network threats like ARP spoofing and ICMP anomalies.
-   **Scoring:** Shows the threat score for this IP and a breakdown of how it was calculated.
