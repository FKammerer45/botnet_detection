# Port and Host Scans

## What it is

Port and host scanning are techniques used to discover open ports and active hosts on a network. This is often a precursor to an attack, as it allows an attacker to identify potential targets.

-   **Port Scan:** An attacker sends packets to a range of ports on a single host to see which ones are open.
-   **Host Scan:** An attacker sends packets to a range of hosts on a network to see which ones are active.

## How it's triggered

-   **Port Scan:** A port scan is detected when a host connects to a large number of distinct ports on a single host within a short period of time.
-   **Host Scan:** A host scan is detected when a host connects to a large number of distinct hosts within a short period of time.

## How to interpret it

A port or host scan detection indicates that a host on your network may be compromised and is being used to scan for other vulnerable hosts.

## Further Reading

-   [Nmap: The Network Mapper](https://nmap.org/)
