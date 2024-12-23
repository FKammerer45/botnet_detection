# Botnet Detection Project

Welcome to the **Botnet Detection Project** repository! This repository contains the tools, scripts, and logic necessary to identify malicious network activity and perform analysis to detect botnet-related anomalies. This project is organized to ensure simplicity and efficiency while leveraging Python for real-time packet capture and analysis.

## About the Project

We are two students from **OTH-Regensburg** giving this project a try to build a tool that helps detect malicious clients in your own network that could be part of a botnet. The tool analyzes traffic running *through* your own machine. To achieve this, you can:

- **Set up an Access Point (AP)**: Use Windows settings to create an AP where your network devices connect.
- **Mirror network traffic**: Mirror the entire network traffic through a switch or router to your PC.

This setup ensures all network traffic is visible to the tool, allowing it to analyze and detect anomalies effectively.

## ESP32 Script Credentials

For the ESP32 script to work, you need to create a `credentials.h` file to store your Wi-Fi credentials. This ensures that sensitive information like your SSID and password is not exposed in the repository.

### Example `credentials.h` File

```cpp
const char* ssid     = "sampleSSID"; 
const char* password = "samplePSW";
```

Include this file in your ESP32 project, and ensure it is added to `.gitignore` to prevent accidental commits.

---

## Directory Structure

The project is structured as follows:

```
ESP 32 DDOS test/
|-- localscripts/
|   |-- detectionscript/
|       |-- blocklists/          # Blocklist files for malicious IP detection
|       |-- config/              # Configuration files (e.g., globals.py)
|       |-- core/                # Core logic for packet capturing and analysis
|       |-- ui/                  # GUI components
|-- src/                         # ESP32-related source files
|-- lib/                         # Libraries for PlatformIO
|-- test/                        # Unit tests
|-- .gitignore                   # Git ignore file
|-- platformio.ini               # PlatformIO configuration
|-- README.md                    # Project documentation
```

---

## Setting Up the Project

1. Clone the repository:
   ```bash
   git clone https://github.com/FKammerer45/botnet_detection.git
   cd botnet_detection
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create an Access Point (AP) through Windows settings or configure your router/switch to mirror network traffic to your PC.

4. If using the ESP32 script:
   - Create a `credentials.h` file as shown above.
   - Place it in the ESP32 source directory.
   - Ensure it is ignored in `.gitignore`.

---

## Running the Tool

1. Start the Python-based packet capture tool:
   ```bash
   python3 main.py
   ```

2. Use the GUI to monitor network activity and detect suspicious traffic.

3. For temporal analysis, click on **"Temporal Analysis"** in the GUI.

---

## Contributions

We welcome contributions to enhance the tool and make it more robust. Feel free to submit pull requests or raise issues for suggestions and bug reports.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
