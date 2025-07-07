# DNS Analysis

The DNS analysis module provides several mechanisms for detecting suspicious DNS activity.

## DGA Detection

-   **What it is:** Domain Generation Algorithms (DGAs) are used by malware to generate a large number of domain names for C2 communication. This makes it difficult to block the C2 servers by blacklisting individual domains.
-   **How it's triggered:** The DGA detection mechanism is triggered when a domain name has a high entropy and a long length.
-   **How to interpret it:** A DGA detection indicates that the host may be infected with malware.

## DNS Tunneling Detection

-   **What it is:** DNS tunneling is a technique used to exfiltrate data or establish C2 communication by encoding data in DNS queries and responses. This technique is often used to bypass firewalls, as DNS traffic is usually allowed.
-   **How it's triggered:** The DNS tunneling detection mechanism is triggered when a host has a high rate of NXDOMAIN (non-existent domain) responses.
-   **How to interpret it:** A DNS tunneling detection indicates that the host may be exfiltrating data or communicating with a C2 server.
