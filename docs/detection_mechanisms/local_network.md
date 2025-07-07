# Local Network Threat Detection

The local network threat detection module provides several mechanisms for detecting threats that originate from within the local network.

## ARP Spoofing Detection

-   **What it is:** ARP Spoofing (or ARP Poisoning) is an attack where a malicious actor sends forged ARP messages on a local network. This allows the attacker to associate their MAC address with another host's IP (e.g., the gateway), redirecting traffic through the attacker for man-in-the-middle attacks.
-   **How it's triggered:** The ARP spoofing detection mechanism is triggered when the MAC address associated with an IP address changes.
-   **How to interpret it:** An ARP spoofing detection indicates that a host on the local network is attempting to impersonate another host.

## ICMP Anomaly Detection

-   **Ping Sweeps:** A ping sweep is a technique used to discover active hosts on a network by sending ICMP echo requests to a range of IP addresses.
-   **ICMP Tunneling:** ICMP tunneling is a technique used to exfiltrate data or establish C2 communication by encoding data in ICMP packets.
-   **How it's triggered:**
    -   A ping sweep is detected when a host sends a large number of ICMP echo requests to distinct hosts.
    -   ICMP tunneling is detected when an ICMP packet with an unusually large payload is detected.
-   **How to interpret it:**
    -   A ping sweep detection indicates that a host is attempting to map out the local network.
    -   An ICMP tunneling detection indicates that a host may be exfiltrating data or communicating with a C2 server.
