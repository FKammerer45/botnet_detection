
# Botnet Detection Project 🛡️

Welcome to the **Botnet Detection Project** repository! This repository contains the tools, scripts, and logic necessary to identify malicious network activity and perform analysis to detect botnet-related anomalies. This project is organized to ensure simplicity and efficiency while leveraging Python for real-time packet capture and analysis.

---

## Project Overview 🌐

The **Botnet Detection Project** aims to monitor network traffic, identify malicious behavior, and analyze data in real-time. This is achieved by:

- **Capturing Network Packets**: Utilizing Python and Scapy for packet sniffing and protocol parsing.
- **Detecting Unsafe Activity**: Leveraging configurable lists of unsafe protocols and ports.
- **Real-Time Threat Analysis**: Visualizing traffic trends, highlighting malicious activity, and logging details.
- **Custom Configuration**: Allowing users to configure unsafe ports and protocols easily.

---

## Repository Structure 📂

The repository is organized into several directories to ensure clarity:

### `localscripts` 📜
- This directory resides inside the PlatformIO project folder (`ESP 32 DDOS TEST`) for simplicity and to keep everything in one place. It holds all Python-based detection scripts.

#### Subfolders:

1. **`blocklists`**:
   - Stores blocklists downloaded during execution.
   - Blocklists are ignored by Git (via `.gitignore`) as they are dynamically generated.

2. **`config`**:
   - **`globals.py`**: Centralized configuration of unsafe protocols and ports.

3. **`core`**:
   - **`capture.py`**: Handles packet capture and processing using Scapy.
   - **`blocklist_integration.py`**: Integrates external blocklists to flag malicious IPs.

4. **`ui`**:
   - **`gui_main.py`**: Main graphical interface to display network activity.
   - **`gui_detail.py`**: Provides detailed views for individual devices and protocols.
   - **`gui_temporal.py`**: Plots traffic trends over time for specific devices.
   - **`gui_unsafe.py`**: Allows configuration of unsafe ports and protocols.

5. **`main.py`**:
   - The entry point for running the application.

6. **`udpserver.py`**:
   - (Optional) Handles UDP-related server logic, if required.

### `src` ⚙️
- Contains the PlatformIO `main.cpp` file for microcontroller-related tasks. 

### `lib` 📘
- Placeholder for additional libraries used in the PlatformIO project.

### `.gitignore` 🛑
- Ensures unnecessary files like cache directories (`__pycache__`) and dynamic blocklists are ignored by Git.

---

## Features ✨

- **Real-Time Analysis**: Analyze traffic trends and visualize data with interactive graphs.
- **Dynamic Configuration**: Add/remove unsafe ports and protocols using the GUI.
- **Threat Detection**: Detect malicious IPs and mark suspicious protocols.
- **Modular Design**: Flexible and extensible Python modules.

---

## Getting Started 🚀

### Prerequisites:
- Python 3.7+
- PlatformIO (for embedded components)
- Required Python libraries (`requirements.txt` can be generated if needed)

### Installation:
1. Clone the repository:
   ```bash
   git clone https://github.com/FKammerer45/botnet_detection.git
   ```
2. Navigate to the project directory:
   ```bash
   cd ESP 32 DDOS test
   ```
3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Usage:
1. Start the detection script:
   ```bash
   python localscripts/detectionscript/main.py
   ```
2. Use the GUI to monitor network activity, configure unsafe ports/protocols, and view traffic trends.

---

## Contribution Guidelines 🤝

Contributions are welcome! If you have suggestions, bug fixes, or new features, feel free to open an issue or create a pull request.

### Steps to Contribute:
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature-branch
   ```
3. Commit your changes and push:
   ```bash
   git commit -m "Add feature"
   git push origin feature-branch
   ```
4. Create a pull request on GitHub.

---

## License 📄

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---
