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
|           |-- gui_detail.py    # IP detail view window
|           |-- (other gui files)
|-- docs/
|   |-- (documentation files)
|-- requirements.txt             # Python package dependencies
|-- README.md                    # This file
|-- .gitignore
```

## Features

*   **Real-time Packet Monitoring**: Captures and analyzes network packets on selected interfaces.
*   **Threat Scoring:** Each IP address is assigned a threat score from 0 to 100, with higher scores indicating a greater potential threat.
*   **Threat Intelligence Integration**:
    *   Utilizes IP blocklists to identify connections to known malicious IP addresses.
    *   Utilizes DNS blocklists to identify queries for known malicious domains.
    *   Utilizes JA3/JA3S blocklists to identify connections from known malicious clients/servers.
*   **Whitelist Management**: Maintain a list of trusted IPs, networks (CIDR), and domains that should not be flagged, manageable via the UI.
*   **Scan Detection**: Identifies potential port scans and host scans originating from local devices.
*   **Unsafe Protocol/Port Flagging**: Highlights traffic using commonly exploited or unencrypted protocols/ports (e.g., Telnet, FTP).
*   **Temporal Traffic Analysis**: Provides a graphical view of traffic volume over time for selected IPs, with protocol breakdown.
*   **Detailed IP View**: Double-click an IP in the main list to see detailed connection information, malicious hits, and DNS queries associated with it.
*   **DNS Analysis**:
    *   **DGA Detection:** Detects randomly generated domain names often used by malware.
    *   **DNS Tunneling Detection:** Identifies patterns of DNS queries that suggest data exfiltration.
*   **Local Network Threat Detection**:
    *   **ARP Spoofing Detection:** Monitors for changes in IP-MAC address mappings.
    *   **ICMP Anomaly Detection:** Detects ping sweeps and large ICMP payloads.
*   **User-Friendly GUI**: Tkinter-based interface for easy interaction and configuration.
*   **In-App Documentation**: A built-in documentation viewer to explain features and detection mechanisms.
*   **Logging**: Records application events and errors to `network_monitor.log`.
*   **Testing Suite**: A built-in tool to simulate various network attacks and anomalies to verify that the detection mechanisms are working correctly.

## Setting Up and Running the Detection Tool

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/FKammerer45/botnet_detection.git
    cd botnet_detection
    ```

2.  **Create and Activate Virtual Environment (Recommended)**:
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

3.  **Install Dependencies**:
    Ensure your virtual environment is activated. Navigate to the directory containing `requirements.txt` (likely the project root, where you cloned the repository) and run:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the Application**:
    ```bash
    python localscripts/detectionscript/main.py
    ```
    *   **Administrator/Root Privileges**: On most systems (especially Windows and Linux), packet capture requires elevated privileges. Run the script as an administrator (Windows) or with `sudo` (Linux/macOS):
        *   Windows: Right-click your terminal (CMD, PowerShell) and "Run as administrator", then navigate and run the script.
        *   Linux/macOS: `sudo python main.py`

## How to Use the Tool

For detailed instructions on how to use the tool, please refer to the in-app documentation by clicking the "Help" button on the main window.

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
