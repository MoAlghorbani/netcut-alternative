# Netcut Alternative (Python)

This project is a Python-based network utility inspired by Netcut, providing functionalities for local network scanning, bandwidth monitoring, DNS query logging, and ARP spoofing.

## Features

*   **Network Discovery:** Scans the local network using ARP requests to find connected devices and their IP/MAC addresses.
*   **Bandwidth Monitoring:** Sniffs network traffic to estimate upload and download bandwidth usage per local IP address.
*   **DNS Query Logging:** Captures and displays recent DNS queries made by local devices.
*   **ARP Spoofing:** Allows cutting off or monitoring traffic of specific devices on the network by ARP poisoning (requires administrator privileges).
*   **Colored Console Output:** Uses Colorama for better readability of logs and statuses.

## Requirements

*   **Python 3.x**
*   **Scapy:** For packet manipulation and sniffing.
*   **Colorama:** For colored terminal output.
*   **Npcap (Windows) or libpcap (Linux/macOS):** Packet capture library required by Scapy. (User confirmed Npcap is installed).
*   **Administrator/Root Privileges:** Required for raw socket access needed for ARP scanning, packet sniffing, and ARP spoofing.

## Installation

1.  **Clone the repository (or download the script):**
    ```bash
    # If using Git
    git clone <repository_url>
    cd netcut-alternative
    ```
2.  **Install Python dependencies:**
    ```bash
    pip install scapy colorama
    ```
3.  **Ensure Npcap is installed (Windows):** Download and install Npcap from the [official website](https://npcap.com/), making sure to install in "WinPcap API-compatible Mode" if needed by older Scapy versions, though recent Scapy versions work well with the native Npcap API.

## Usage

1.  **Run the script with administrator privileges:**

    *   **Windows:** Open Command Prompt or PowerShell *as Administrator* and run:
        ```bash
        python network_scanner.py
        ```
    *   **Linux/macOS:**
        ```bash
        sudo python network_scanner.py
        ```

2.  **Select Network Interface:** The script will list available network interfaces. Choose the one connected to your local network.
3.  **Follow On-Screen Prompts:** The script will display discovered devices, bandwidth usage, DNS queries, and provide options for ARP spoofing.

## Disclaimer

ARP spoofing can disrupt network connectivity and should only be used on networks you own or have explicit permission to test. Unauthorized use is illegal and unethical. Use this tool responsibly.