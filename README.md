# Botnet Detection Project

Welcome to the **Botnet Detection Project** repository! This repository contains the tools, scripts, and logic necessary to identify malicious network activity and perform analysis to detect botnet-related anomalies. This project is organized to ensure simplicity and efficiency while leveraging Python for real-time packet capture and analysis.

---

## Project Background 🛠️

This is a collaborative project by two students of **OTH Regensburg**, designed to build a tool that helps detect malicious clients within your own network that could potentially be part of a botnet. 

### Key Features:
1. **Real-Time Packet Analysis:** Capture and analyze network packets flowing through your own machine.
2. **Protocol and Port Monitoring:** Flag unsafe or suspicious protocols and ports based on custom configurations.
3. **Malicious IP Detection:** Identify connections to IPs flagged in known blocklists.
4. **Temporal Analysis:** Visualize network traffic trends over time to spot anomalies.

---

## Important Note ⚠️

This tool only analyzes the traffic running **through your own machine**. To monitor all devices in your network, you would need to:
- Create an **Access Point (AP)** where your network devices connect.
- Alternatively, mirror the entire network traffic through a **switch or router** to your PC.

---

## Repository Structure 📁

Here is an overview of the folder structure:

```
├── localscripts/
│   ├── detectionscript/
│   │   ├── blocklists/               # Contains IP blocklists downloaded from external sources.
│   │   ├── config/                   # Configuration files (e.g., unsafe protocols, ports).
│   │   ├── core/                     # Core logic for packet capture and blocklist integration.
│   │   ├── ui/                       # GUI components (e.g., main window, temporal analysis).
│   │   └── main.py                   # Entry point for the botnet detection tool.
├── src/                              # PlatformIO scripts (separate for ESP32 testing purposes).
├── lib/                              # Libraries for PlatformIO.
├── .gitignore                        # Ignore unnecessary files like Python cache and blocklists.
├── platformio.ini                    # PlatformIO configuration.
├── README.md                         # Documentation for the repository.
├── requirements.txt                  # Python dependencies.
```

---

## Installation and Setup 🚀

### Prerequisites:
Ensure you have the following installed on your system:
- **Python 3.8+**
- **pip** (Python package installer)
- **Git**

### Steps:

1. Clone this repository:

```bash
git clone https://github.com/FKammerer45/botnet_detection.git
cd botnet_detection
```

2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Run the main script:

```bash
python localscripts/detectionscript/main.py
```

---

## How It Works 🧪

1. **Packet Capture:**
   - The tool captures packets using Scapy and analyzes their source, destination, protocol, and port.
   - Temporal data is logged for trend analysis.

2. **Blocklist Integration:**
   - Known malicious IPs are downloaded from external blocklists and flagged if encountered.

3. **GUI:**
   - The GUI provides visualization tools to track suspicious traffic and configure unsafe ports/protocols.

---

## Contributing 👥

Contributions to the project are welcome! Feel free to fork the repository, make improvements, and create pull requests.

---

## License 📜

This project is for educational and research purposes only and should not be used for malicious activities. Please refer to the LICENSE file for more details.
