Botnet Detection Project 🛡️
Welcome to the Botnet Detection Project repository! This repository contains the tools, scripts, and logic necessary to identify malicious network activity and perform analysis to detect botnet-related anomalies. This project is organized to ensure simplicity and efficiency while leveraging Python for real-time packet capture and analysis.

Project Overview 🌐
The Botnet Detection Project aims to monitor network traffic, identify malicious behavior, and analyze data in real-time. This is achieved by:

Capturing Network Packets: Utilizing Python and Scapy for packet sniffing and protocol parsing.
Detecting Unsafe Activity: Leveraging configurable lists of unsafe protocols and ports.
Real-Time Threat Analysis: Visualizing traffic trends, highlighting malicious activity, and logging details.
Custom Configuration: Allowing users to configure unsafe ports and protocols easily.
Repository Structure 📂
The repository is organized into several directories to ensure clarity:

localscripts 📜
This directory resides inside the PlatformIO project folder (ESP 32 DDOS TEST) for simplicity and to keep everything in one place. It holds all Python-based detection scripts.
Subfolders:
blocklists:

Stores blocklists downloaded during execution.
Blocklists are ignored by Git (via .gitignore) as they are dynamically generated.
config:

globals.py: Centralized configuration of unsafe protocols and ports.
core:

capture.py: Handles packet capture and processing using Scapy.
blocklist_integration.py: Integrates external blocklists to flag malicious IPs.
ui:

gui_main.py: Main graphical interface to display network activity.
gui_detail.py: Provides detailed views for individual devices and protocols.
gui_temporal.py: Plots traffic trends over time for specific devices.
gui_unsafe.py: Allows configuration of unsafe ports and protocols.
main.py:

The entry point for running the application.
udpserver.py:

(Optional) Handles UDP-related server logic, if required.
src ⚙️
Contains the PlatformIO main.cpp file for microcontroller-related tasks.
lib 📘
Placeholder for additional libraries used in the PlatformIO project.
.gitignore 🛑
Ensures unnecessary files like cache directories (__pycache__) and dynamic blocklists are ignored by Git.
Features ✨
Real-Time Analysis: Analyze traffic trends and visualize data with interactive graphs.
Dynamic Configuration: Add/remove unsafe ports and protocols using the GUI.
Threat Detection: Detect malicious IPs and mark suspicious protocols.
Modular Design: Flexible and extensible Python modules.
Getting Started 🚀
Prerequisites:
Python 3.7+
PlatformIO (for embedded components)
Required Python libraries (requirements.txt can be generated if needed)
Installation:
Clone the repository:
bash
Code kopieren
git clone https://github.com/FKammerer45/botnet_detection.git
Navigate to the project directory:
bash
Code kopieren
cd ESP 32 DDOS test
Install Python dependencies:
bash
Code kopieren
pip install -r requirements.txt
Usage:
Start the detection script:
bash
Code kopieren
python localscripts/detectionscript/main.py
Use the GUI to monitor network activity, configure unsafe ports/protocols, and view traffic trends.
Contribution Guidelines 🤝
Contributions are welcome! If you have suggestions, bug fixes, or new features, feel free to open an issue or create a pull request.

Steps to Contribute:
Fork the repository.
Create a feature branch:
bash
Code kopieren
git checkout -b feature-branch
Commit your changes and push:
bash
Code kopieren
git commit -m "Add feature"
git push origin feature-branch
Create a pull request on GitHub.
License 📄
This project is licensed under the MIT License. See the LICENSE file for more details.
