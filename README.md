# Botnet Detection Project

Welcome to the **Botnet Detection Project** repository! This project provides a Python-based tool to help identify malicious network activity and detect anomalies that could indicate botnet-related behavior within your local network.

## About the Project

This tool analyzes network traffic on the machine it runs on. Typical deployments:

1. **PC as Access Point (AP)**: Use Windows Mobile Hotspot or similar; connect target devices so their traffic passes through your PC.
2. **Port Mirroring/TAP**: Mirror switch/router traffic to the PC running this tool.
3. **Local Inspection**: Run on a workstation/server to monitor local traffic (requires admin/root and Npcap on Windows).

The app captures traffic (Scapy), applies multiple detections, scores each IP, and provides a Tkinter GUI to review and drill into threats.

## Prerequisites

Before running the detection tool, ensure you have the following:

*   **Python**: Python 3.8 or newer is recommended.
*   **Npcap (for Windows users)**: Npcap is required by Scapy for packet capture on Windows.
    *   Download and install Npcap from [https://npcap.com/#download](https://npcap.com/#download).
    *   During installation, it's recommended to select the "Install Npcap in WinPcap API-compatible Mode" option for broader compatibility with tools like Scapy. Also, consider installing the "Support Npcap loopback adapter" if you intend to capture loopback traffic (though not the primary use case here).
*   **Pip**: Python package installer, usually included with Python.
*   **Git**: For cloning the repository.

## Code Structure

The Python-based detection tool is primarily located within the `localscripts/detectionscript/` directory:
```
botnet_detection/
├─ localscripts/
│  ├─ detectionscript/
│  │  ├─ main.py                 # App entrypoint (GUI + capture thread + blocklist updater)
│  │  ├─ config.ini              # User-configurable thresholds/flags/blocklists
│  │  ├─ whitelist.txt           # User-managed whitelist
│  │  ├─ blocklists/             # Downloaded blocklist files
│  │  ├─ config/
│  │  │  ├─ globals.py           # Constants (paths, defaults)
│  │  ├─ core/
│  │  │  ├─ capture.py           # Packet capture and callback plumbing
│  │  │  ├─ data_manager.py      # In-memory state, detections, scoring
│  │  │  ├─ config_manager.py    # Load/save config.ini
│  │  │  ├─ blocklist_integration.py # Download/parse/query IP/DNS/JA3/JA3S blocklists
│  │  │  ├─ whitelist_manager.py # Whitelist handling
│  │  │  ├─ ja3.py               # JA3 fingerprint helper
│  │  ├─ ui/
│  │  │  ├─ gui_main.py          # Main window, tables, event loop
│  │  │  ├─ gui_detail.py        # IP detail window (tabs)
│  │  │  ├─ gui_temporal.py      # Temporal view
│  │  │  ├─ gui_testing_suite.py # Test traffic generator
│  │  │  ├─ gui_config_hub.py    # Unified configuration window (tabs)
│  │  │  ├─ tabs/                # Detail tabs (beaconing, DNS, scans, etc.)
│  │  │  ├─ components/          # Shared UI components (configuration frame)
│  ├─ detectionscript/config.ini # (same as above, accessible path)
├─ docs/                         # In-app documentation content
├─ requirements.txt              # Python dependencies
├─ README.md
├─ .gitignore
└─ src/                          # Optional ESP32 test script (for traffic generation)
```

## Features (GUI-driven)

- **Real-time capture**: Scapy-based sniffing on selected interfaces (admin/root; Npcap on Windows).
- **Threat scoring (0–100)**: Aggregates detections with per-component breakdown.
- **Threat intel**: IP/DNS/JA3/JA3S blocklists with auto-download/update.
- **Whitelist**: IP/CIDR/domain whitelist to suppress known-good traffic.
- **Scan detection**: Port/host scans, stealth variants.
- **Unsafe protocol/port flagging**: Legacy/unencrypted protocols and ports.
- **DNS analysis**: DGA heuristic, DNS tunneling (NXDOMAIN rate), blocklist hits.
- **Beaconing**: Periodic C2 beaconing detection (configurable interval/tolerance).
- **Local network**: ARP spoofing, ICMP anomalies (ping sweep, large payload).
- **JA3/JA3S**: Fingerprint lookups against blocklists.
- **GUI drill-down**: Main table + detail tabs (destinations, protocols, threat info, DNS, scans, rate anomaly, beaconing, DNS analysis, local network, scoring).
- **Temporal view**: Packets/min over time with protocol breakdown.
- **Testing Suite**: Generate test traffic (port/host scan, unsafe protocol, rate anomaly, beaconing, DGA, DNS tunneling, ICMP tunneling).
- **In-app docs**: Rich Help window covering all features; auto-resizing for readability.
- **Logging**: Events to `network_monitor.log`.

## Setup & Run

1) **Clone**  
```bash
git clone https://github.com/FKammerer45/botnet_detection.git
cd botnet_detection
```

2) **Create & activate venv (recommended)**  
```bash
python -m venv venv
# Windows PowerShell: .\venv\Scripts\Activate.ps1   (may require: Set-ExecutionPolicy Unrestricted -Scope Process)
# Windows CMD:       .\venv\Scripts\activate
# Linux/macOS:       source venv/bin/activate
```

3) **Install deps**  
```bash
pip install -r requirements.txt
```

4) **Run app**  
```bash
python localscripts/detectionscript/main.py
```
> Run as **Administrator/Root** for packet capture (Npcap required on Windows).

## How to Use (GUI flow)

1. Launch the app (admin/root).  
2. Select network interfaces when prompted.  
3. Click **Config** to enable/disable detections and set thresholds (unsafe, scans, beaconing, DNS analysis, local net, scoring, blocklists, whitelist).  
4. Main table: monitor Internal/External IPs, score, totals, pkts/min/sec, max pkts/min.  
5. Double-click an IP for detail tabs (threat info, DNS, scans, rate anomaly, beaconing, DNS analysis, local network, scoring).  
6. Use **Temporal** for packets/min over time; **Testing Suite** to generate sample attack traffic; **Help** for full in-app docs.

## Tips
- Install Npcap (WinPcap-compatible) on Windows.
- Whitelist known-good IPs/domains to reduce noise.
- Tune DGA entropy/length and NXDOMAIN thresholds for your environment.
- Set beacon interval/tolerance to match expected beacons; multicast/unspecified destinations are ignored.

---
*The following section relates to the optional ESP32 component of the project.*

## ESP32 Test Script (Optional)

This project includes an optional ESP32 script located in the `src/` directory. This script is intended for testing purposes only and is not required to run the main detection tool. It can be used to generate various types of network traffic to test the detection capabilities of the Python application.

### ESP32 Script Credentials

For the ESP32 script to work, you need to create a `credentials.h` file to store your Wi-Fi credentials. This ensures that sensitive information like your SSID and password is not exposed in the repository.

### Example `credentials.h` File

```cpp
const char* ssid     = "sampleSSID"; 
const char* password = "samplePSW";
```

Include this file in your ESP32 project, and ensure it is added to `.gitignore` to prevent accidental commits.

---

## License

This project is licensed under the MIT License.
