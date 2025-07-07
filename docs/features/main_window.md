# Main Window

The main window provides a real-time overview of network activity, separated into internal and external IP addresses.

## Features

- **Real-time Monitoring:** The tables update automatically to show the latest network traffic data.
- **Threat Scoring:** Each IP address is assigned a threat score from 0 to 100, with higher scores indicating a greater potential threat.
- **Color-coded Alerts:** Rows are highlighted in red to draw attention to IPs that have triggered a detection rule.
- **Configuration:** A variety of configuration options are available to customize the detection mechanisms.
- **Detailed Analysis:** Double-clicking on an IP address opens a detailed view with more information.

## How to Use

1.  **Select Network Interfaces:** When the application starts, you will be prompted to select one or more network interfaces to monitor.
2.  **Monitor Traffic:** The main window will display two tables: one for internal IPs and one for external IPs. Each table shows the following information:
    *   **IP Address:** The source IP address.
    *   **Score:** The threat score for the IP address.
    *   **Total Pkts:** The total number of packets sent from the IP address.
    *   **Pkts/Min:** The number of packets sent in the last minute.
    *   **Pkts/Sec:** The number of packets sent in the last second.
    *   **Max P/S:** The maximum number of packets per second sent from the IP address.
3.  **Configure Detection:** Use the buttons in the configuration frame to customize the detection settings.
4.  **View Details:** Double-click on an IP address to open a detailed view with more information about its activity.
