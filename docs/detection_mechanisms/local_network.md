# Local Network Threat Detection

The local network threat detection module provides several mechanisms for detecting threats that originate from within the local network.

## ARP Spoofing Detection

### What it is

ARP Spoofing (or ARP Poisoning) is an attack where a malicious actor sends forged ARP messages on a local network. This allows the attacker to associate their MAC address with another host's IP (e.g., the gateway), redirecting traffic through the attacker for man-in-the-middle attacks.

### How it's Detected

This tool detects ARP spoofing by maintaining a table of IP-MAC address mappings. If a new ARP response is received that changes the MAC address associated with an IP address, it is flagged as a potential ARP spoofing attack.

### Why it's Malicious

ARP spoofing can be used to launch man-in-the-middle attacks, allowing an attacker to intercept, modify, or block traffic between two hosts. This can be used to steal sensitive information, such as login credentials and credit card numbers.

## ICMP Anomaly Detection

### Ping Sweeps

A ping sweep is a technique used to discover active hosts on a network by sending ICMP echo requests to a range of IP addresses.

### ICMP Tunneling

ICMP tunneling is a technique used to exfiltrate data or establish C2 communication by encoding data in ICMP packets.

### How it's Detected

-   **Ping Sweep:** A ping sweep is detected when a host sends a large number of ICMP echo requests to distinct hosts.
-   **ICMP Tunneling:** ICMP tunneling is detected when an ICMP packet with an unusually large payload is detected.

### Why it's Malicious

-   **Ping Sweep:** A ping sweep is often a precursor to an attack, as it allows an attacker to identify potential targets.
-   **ICMP Tunneling:** ICMP tunneling is a common technique used by botnets to exfiltrate data and receive commands from a C2 server.

### Further Reading

-   [ARP Spoofing](https://www.veracode.com/security/arp-spoofing)
-   [How Hackers Use ICMP Tunneling to Own Your Network](https://www.cynet.com/attack-techniques-hands-on/how-hackers-use-icmp-tunneling-to-own-your-network/)
