# PRODIGY_CS_05


# Network Sniffer

A simple network packet sniffer implemented in Python using the Scapy library.

## Description

This project is a basic network sniffer that captures and displays information about network packets in real time.The sniffer captures data packets sent over a new network interface, analysing the types of protocols in use and allowing for packet inspection for debugging, security auditing, or general monitoring purposes.

## Features

- Captures network packets in real-time
- Displays source IP, destination IP, and protocol for each packet.
- Continuous packet capture until manually stopped.
- Options to filter specific traffic types based on protocols, IP addresses, or ports.
- Captured packet data can be logged to a file for further analysis.

## Requirements

- Python 3.x
- Scapy library

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/Jewel326/PRODIGY_CS_05.git
   ```
2. Install the required library:
   ```
   pip install scapy
   ```

## Usage

Run the script with sudo privileges:

```
sudo python3 network_sniffer.py
```

Press Ctrl+C to stop the packet capture.

## Note

This tool is for educational purposes only. Always ensure you have permission before capturing network traffic on any network.
