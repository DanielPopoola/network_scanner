# Network CVE Scanner

This project is a network scanner that identifies devices on a network, catalogs their open ports and services, and stores this information in a database. The primary goal is to identify known CVEs based on the discovered services.

## Features

*   **Network Discovery:** Discovers live hosts on a given network CIDR.
*   **Port Scanning:** Scans for open ports on discovered devices. It can perform both quick scans (top 1000 ports) and full scans (all 65535 ports).
*   **Service and Version Detection:** Identifies services running on open ports and their versions.
*   **Smart Scanning:** The scanner performs a quick scan on known devices and a full scan on new devices or when changes in port states are detected.
*   **Database Integration:** All information is stored in a SQLite database, including device details, port information, and vulnerabilities.
*   **Vulnerability Storage:** The database schema includes tables for storing CVEs and linking them to devices.

## Dependencies

*   python-nmap>=0.7.1

## Installation

1.  Clone the repository:
    ```bash
    git clone <repository-url>
    ```
2.  Navigate to the project directory:
    ```bash
    cd network_scanner
    ```
3.  Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Database Schema

The application uses a SQLite database with the following tables:

*   `customers`: Stores customer information.
*   `networks`: Stores network CIDRs associated with customers.
*   `devices`: Stores information about each discovered device, including IP address, MAC address, hostname, and scan status.
*   `ports`: Stores information about open ports on each device, including the port number, protocol, service name, and version.
*   `vulnerabilities`: Stores information about CVEs.
*   `device_vulnerabilities`: Links devices and ports to specific CVEs.

## Usage

To run the network scanner, execute the `main.py` script:

```bash
python main.py
```

The main script will initiate the scan, and the results will be stored in the `network_scanner.db` database file.

## Project Structure

```
.
├── main.py                 # Main entry point of the application
├── pyproject.toml          # Project metadata and dependencies
├── requirements.txt        # Project dependencies
├── src
│   ├── database
│   │   ├── database.py         # Database management
│   │   └── network_scanner.db  # SQLite database
│   └── scanner
│       └── network_scanner.py  # Core network scanning logic
└── README.md               # This file
```
