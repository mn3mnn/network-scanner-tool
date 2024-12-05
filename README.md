# network-scanner-tool
Data communications assignment 1, network scanner tool in python

## Overview
Network Tool GUI is a Python-based graphical user interface (GUI) application for network tools. It provides functionalities such as ARP scanning, packet sniffing, custom packet sending, and network performance measurement.

## Features
- **ARP Scan**: Scan a specified subnet for active devices.
- **Packet Sniffer**: Sniff network packets based on specified IP and protocol.
- **Custom Packet Sender**: Send custom packets to a specified IP using a specified protocol.
- **Network Performance Measurement**: Calculate and display network performance metrics.

## Requirements
- Python 3.x
- `tkinter` library (usually included with Python)
- `network_tools` package (custom package containing ARPScanner, PacketSniffer, PacketSender, and NetworkPerformanceCalculator)

## Installation
1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/network-tool-gui.git
    cd network-tool-gui
    ```

2. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

## Usage
1. Run the application:
    ```sh
    python main.py
    ```

2. Use the GUI to perform various network tasks:
    - **ARP Scan**: Enter a subnet (e.g., `192.168.1.0/24`) and click "Scan".
    - **Packet Sniffer**: Enter an IP and protocol (TCP, UDP, ICMP), enable logging if needed, and click "Start". Click "Stop" to stop sniffing.
    - **Custom Packet Sender**: Enter a target IP and protocol, and click "Send".
    - **Network Performance Measurement**: Click "Start" to measure network performance.

## File Structure
- `main.py`: Main script to run the GUI application.
- `network_tools/`: Directory containing network tool modules.
    - `arp_scanner.py`: ARP scanning functionality.
    - `packets.py`: Packet sniffing, sending, and network performance calculation functionalities.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.