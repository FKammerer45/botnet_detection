# DNS Analysis

The DNS analysis module provides several mechanisms for detecting suspicious DNS activity.

## DGA Detection

### What it is

Domain Generation Algorithms (DGAs) are used by malware to generate a large number of domain names for C2 communication. This makes it difficult to block the C2 servers by blacklisting individual domains.

### How it's Detected

This tool detects DGA domains by analyzing the entropy and length of the domain name. A high entropy score indicates a high degree of randomness, which is a common characteristic of DGA-generated domains. The entropy and length thresholds can be configured in the "Conf DNS" window.

### Why it's Malicious

DGA is a common technique used by botnets to evade detection. By detecting DGA domains, you can identify infected hosts on your network and take steps to remove the malware and prevent further damage.

## DNS Tunneling Detection

### What it is

DNS tunneling is a technique used to exfiltrate data or establish C2 communication by encoding data in DNS queries and responses. This technique is often used to bypass firewalls, as DNS traffic is usually allowed.

### How it's Detected

This tool detects DNS tunneling by monitoring the rate of NXDOMAIN (non-existent domain) responses for a given host. A high rate of NXDOMAIN responses can indicate that a host is attempting to communicate with a C2 server by sending a large number of DNS queries to non-existent domains. The NXDOMAIN rate threshold and minimum query count can be configured in the "Conf DNS" window.

### Why it's Malicious

DNS tunneling is a common technique used by botnets to exfiltrate data and receive commands from a C2 server. By detecting DNS tunneling, you can identify infected hosts on your network and take steps to remove the malware and prevent further damage.

### Further Reading

-   [Detection for domain generation algorithm (DGA)](https://link.springer.com/article/10.1007/s13198-022-01713-2)
-   [DNS Tunneling: How it Works and How to Detect it](https://www.varonis.com/blog/dns-tunneling)
