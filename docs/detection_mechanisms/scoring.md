# Scoring System

The scoring system provides a quantitative measure of the threat level associated with each IP address. The score is calculated based on a variety of detection mechanisms, each with its own weight.

## How it Works

Each detection mechanism contributes a certain number of points to the total score. The total score is capped at 100. The higher the score, the more likely it is that the IP address is malicious.

### Score Breakdown

| Detection Category | Event | Points per Event |
| :--- | :--- | :--- |
| **Local Network Threats** | ARP Spoofing Detected | 50 |
| | ICMP Ping Sweep | 5 |
| | ICMP Tunneling (Large Payload) | 20 |
| **C2 & Malware Indicators** | C2 Beaconing Detected | 40 |
| | JA3/JA3S Blocklist Hit | 20 |
| | DGA Detected (per domain) | 10 |
| | DNS Tunneling (NXDOMAIN rate) | 25 |
| **Blocklist Hits** | IP Blocklist Hit (per list) | 15 |
| | DNS Blocklist Hit (per list) | 10 |
| **Scanning & Anomalies** | Port Scan Detected | 5 (per target) |
| | Host Scan Detected | 10 |
| | Rate Anomaly Detected | 15 |
| **Low-Severity Indicators** | Use of Unsafe Protocol/Port | 2 |


