# Botnet Detection Project

Welcome to the **Botnet Detection Project** repository! This project provides a Python-based tool to help identify malicious network activity and detect anomalies that could indicate botnet-related behavior within your local network.

## About the Project

This tool is designed to analyze network traffic passing through the machine it runs on. To effectively monitor network devices (e.g., IoT devices, other computers), you can:

1.  **Set up an Access Point (AP) on your PC**: Use your operating system's built-in features (e.g., Windows Mobile Hotspot) to create an AP. Connect your target devices to this AP. All traffic from these devices will then route through your PC.
2.  **Use a Network Tap or Port Mirroring**: For more comprehensive network visibility, configure a managed switch or router to mirror traffic from specific ports (or the entire network) to the network interface of the PC running this tool.

This setup allows the tool to capture and analyze traffic, helping to identify suspicious patterns and potential threats.

## Prerequisites

Before running the detection tool, ensure you have the following:

*   **Python**: Python 3.8 or newer is recommended.
*   **Npcap (for Windows users)**: Npcap is required by Scapy for packet capture on Windows.
    *   Download and install Npcap from [https://npcap.com/#download](https://npcap.com/#download).
    *   During installation, it's recommended to select the "Install Npcap in WinPcap API-compatible Mode" option for broader compatibility with tools like Scapy. Also, consider installing the "Support Npcap loopback adapter" if you intend to capture loopback traffic (though not the primary use case here).
*   **Pip**: Python package installer, usually included with Python.
*   **Git**: For cloning the repository.

## Code Structure (Detection Tool)

The Python-based detection tool is primarily located within the `localscripts/detectionscript/` directory:

```
botnet_detection/
|-- localscripts/
|   |-- detectionscript/
|       |-- main.py              # Main entry point for the application
|       |-- config.ini           # Configuration file for thresholds, blocklists, etc.
|       |-- whitelist.txt        # User-managed whitelist for IPs and domains
|       |-- network_monitor.log  # Log file for application events
|       |-- blocklists/          # Directory where downloaded blocklist files are stored
|       |-- config/
|       |   |-- globals.py       # Defines global constants like filenames
|       |-- core/                # Core backend logic
|       |   |-- capture.py       # Packet capture, processing, and data aggregation
|       |   |-- config_manager.py # Handles loading and saving config.ini
|       |   |-- whitelist_manager.py # Manages whitelist operations
|       |   |-- blocklist_integration.py # Handles downloading and querying IP/DNS blocklists
|       |-- ui/                  # Tkinter-based Graphical User Interface components
|           |-- gui_main.py      # Main application window
|           |-- gui_temporal.py  # Temporal analysis window
|           |-- gui_detail.py    # IP detail view window
|           |-- gui_dns.py       # DNS query monitor window (if implemented)
|           |-- gui_scan_config.py # Scan detection settings window
|           |-- gui_blocklist_manager.py # Blocklist management window
|           |-- gui_whitelist_manager.py # Whitelist management window
|           |-- gui_unsafe.py    # Unsafe port/protocol configuration window
|-- requirements.txt             # Python package dependencies
|-- README.md                    # This file
|-- .gitignore
|-- (Other project files like ESP32 related code, platformio.ini etc. if present)
```

## Features

*   **Real-time Packet Monitoring**: Captures and analyzes network packets on selected interfaces.
*   **Configurable Thresholds**: Set thresholds for packets/minute to flag potentially anomalous traffic.
*   **Threat Intelligence Integration**:
    *   Utilizes IP blocklists to identify connections to known malicious IP addresses.
    *   Utilizes DNS blocklists to identify queries for known malicious domains.
*   **Whitelist Management**: Maintain a list of trusted IPs, networks (CIDR), and domains that should not be flagged, manageable via the UI.
*   **Scan Detection**: Identifies potential port scans and host scans originating from local devices.
*   **Unsafe Protocol/Port Flagging**: Highlights traffic using commonly exploited or unencrypted protocols/ports (e.g., Telnet, FTP).
*   **Temporal Traffic Analysis**: Provides a graphical view of traffic volume over time for selected IPs, with protocol breakdown.
*   **Detailed IP View**: Double-click an IP in the main list to see detailed connection information, malicious hits, and DNS queries associated with it.
*   **User-Friendly GUI**: Tkinter-based interface for easy interaction and configuration.
*   **Logging**: Records application events and errors to `network_monitor.log`.

## Setting Up and Running the Detection Tool

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/FKammerer45/botnet_detection.git
    cd botnet_detection
    ```

1.5. **Create and Activate Virtual Environment (Recommended)**:
    It's highly recommended to use a virtual environment to manage project dependencies.

    *   **Create the virtual environment** (e.g., named `venv`):
        ```bash
        python -m venv venv 
        ```
        (On some systems, you might need `python3` instead of `python`)

    *   **Activate the virtual environment**:
        *   Windows (Command Prompt):
            ```bash
            .\venv\Scripts\activate
            ```
        *   Windows (PowerShell):
            ```bash
            .\venv\Scripts\Activate.ps1
            ```
            (If you get an error about script execution policy, you may need to run: `Set-ExecutionPolicy Unrestricted -Scope Process` first, then try activating again.)
        *   Linux / macOS (bash/zsh):
            ```bash
            source venv/bin/activate
            ```
    You should see the virtual environment's name (e.g., `(venv)`) in your terminal prompt once activated. All subsequent `pip install` commands will install packages into this environment.

2.  **Install Dependencies**:
    Ensure your virtual environment is activated. Navigate to the directory containing `requirements.txt` (likely the project root, where you cloned the repository) and run:
    ```bash
    pip install -r requirements.txt
    ```
    (If `requirements.txt` is in the root, run from there. If it's specific to `detectionscript`, `cd` there first or adjust path, but typically it's in the root).

3.  **Navigate to the Script Directory**:
    ```bash
    cd localscripts/detectionscript
    ```

4.  **Run the Application**:
    ```bash
    python main.py
    ```
    *   **Administrator/Root Privileges**: On most systems (especially Windows and Linux), packet capture requires elevated privileges. Run the script as an administrator (Windows) or with `sudo` (Linux/macOS):
        *   Windows: Right-click your terminal (CMD, PowerShell) and "Run as administrator", then navigate and run the script.
        *   Linux/macOS: `sudo python main.py`

## How to Use the Tool

### Main Interface
*   **Packet Statistics Table**: Displays a list of source IPs observed on the network, along with:
    *   `Total Pkts`: Total packets seen from this IP.
    *   `Pkts/Min`: Packets seen from this IP in the last minute.
    *   `Pkts/Sec`: Current packets per second from this IP.
    *   `Max P/S`: Highest packets per second rate observed for this IP.
*   **Threshold Configuration**: You can set a "Pkts/Min Threshold" directly on the main UI. IPs exceeding this will be flagged.
*   **Flags**: Checkboxes allow you to enable/disable flagging conditions:
    *   `Flag Unsafe`: Highlights IPs using ports/protocols defined as unsafe.
    *   `Flag Malicious IP`: Highlights IPs found on configured IP blocklists or communicating with blocklisted IPs.
    *   `Flag Bad DNS`: Highlights IPs making DNS queries for domains found on DNS blocklists.
    *   `Flag Scan`: Highlights IPs detected performing port or host scans.
*   **Row Highlighting**: Rows in the table are highlighted in red if they meet any of the enabled flagging criteria or exceed the packet threshold.
*   **Detailed View**: Double-click any IP address in the table to open a "Detail Window" showing its connections, protocols used, malicious hits, and DNS queries.

### Configuration Dialogs
Accessible via buttons on the main UI:
*   **Conf Unsafe**: Configure which ports and protocols are considered "unsafe". Changes are saved to `config.ini`.
*   **Conf Scan**: Adjust parameters for scan detection (time window, distinct port/host thresholds, check interval). Changes are saved to `config.ini`.
*   **Blocklists**: Manage IP and DNS blocklist URLs. Activate/deactivate existing lists or add new ones. Changes update `config.ini` and trigger a re-download/reload of blocklists.
*   **Whitelist**: Add or remove IPs, CIDR networks, or domains that should be ignored by detection logic. Changes are saved to `whitelist.txt`.
*   **Temporal**: Opens the "Temporal Analysis" window. Select an IP to see a graph of its traffic volume (packets per minute) over time, with an option for protocol breakdown.
*   **DNS Mon**: Opens the "DNS Query Monitor" window, showing recent DNS queries observed (if this feature is fully implemented and populated).

### Interpreting Alerts
*   **High Packet Counts (Pkts/Min)**: Could indicate large data transfers, streaming, or potentially anomalous activity like DoS participation or data exfiltration.
*   **Unsafe Flags**: Alerts to the use of protocols/ports that may be insecure or associated with malware (e.g., Telnet for C2, FTP for data theft).
*   **Malicious IP Flags**: Indicates communication with IPs known to be malicious (e.g., C2 servers, malware distribution points). Investigate the specific blocklist hit in the Detail View.
*   **Bad DNS Flags**: Shows attempts to resolve domains known for malware, phishing, etc.
*   **Scan Flags**: Suggests a host on your network might be compromised and scanning other internal or external hosts, or is being scanned.

### Configuration Files
*   **`config.ini`**: Stores most of the application's settings, including thresholds, scan detection parameters, blocklist URLs, and unsafe port/protocol definitions. Many of these are configurable via the UI.
*   **`whitelist.txt`**: Contains a list of IPs, CIDR networks, and domains that are considered safe and will be ignored by the flagging logic. This file is managed through the "Whitelist" UI.

---
*The following sections relate to the ESP32 part of the project, if applicable.*

## ESP32 Script Credentials

For the ESP32 script to work, you need to create a `credentials.h` file to store your Wi-Fi credentials. This ensures that sensitive information like your SSID and password is not exposed in the repository.

### Example `credentials.h` File

```cpp
const char* ssid     = "sampleSSID"; 
const char* password = "samplePSW";
```

Include this file in your ESP32 project, and ensure it is added to `.gitignore` to prevent accidental commits.

---

## License

This project is licensed under the MIT License. (Assuming MIT, please add a `LICENSE` file if one doesn't exist).
