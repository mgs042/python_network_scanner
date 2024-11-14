# Network Scanner

This is a Python-based network scanner that scans a given IP range or a single IP address for active devices on the network. It uses the Scapy library to send ARP requests and listens for responses to identify devices on the local network. The results include the device's IP, MAC address, and optional device name if it can be resolved.

## Features
- Scans a given IP range or a single IP address.
- Displays IP and MAC addresses of devices found on the network.
- Optionally resolves device names using `get_device_name()` function (which can be customized).
- Uses `concurrent.futures` for parallel scanning of multiple IPs.

## Requirements
- Python 3.x
- Scapy (Install with `pip install scapy`)

## Installation

1. Clone this repository to your local machine:

    ```bash
    git clone https://github.com/your-username/network-scanner.git
    cd network-scanner
    ```

2. Install the required Python dependency scapy:

    ```bash
    pip install -r scapy
    ```


## Usage

### Command Line Arguments

You can run the script with command line arguments to specify a single IP or a range of IPs to scan.

#### Syntax:
```bash
python network_scanner.py --ip <single_ip>  # To scan a single IP
python network_scanner.py --range <ip_range>  # To scan an IP range (e.g., 192.168.1.1/24)
python network_scanner.py --csv <csv_file>  # To scan a IP csv file
