# NetScan

**NetScan** is an asynchronous network discovery and asset
identification tool written in Python.

It combines:

-   ICMP host discovery
-   ARP inspection
-   TCP port scanning
-   banner grabbing
-   HTTP analysis
-   device fingerprinting

NetScan is part of the **NetTools Portfolio** by **Humbug Software**.

------------------------------------------------------------------------

# Features

-   Asynchronous high-speed scanning
-   Multi-target scanning (hosts, ranges, subnets)
-   ICMP discovery
-   ARP inspection
-   TCP port scanning
-   HTTP title and server detection
-   SSH banner grabbing
-   SMTP / FTP / POP3 / IMAP detection
-   MAC vendor lookup
-   Device fingerprinting engine
-   JSON / CSV export
-   Rich CLI output

------------------------------------------------------------------------

## 📸 Screenshot

<p align="center">
  <img src="screenshot.png" alt="NetScan Screenshot" width="900">
</p>

# Usage

Run from the project root:

    python -m cli.cli

If no target is provided NetScan scans the detected local `/24` network.

------------------------------------------------------------------------

# Supported Target Formats

Single host:

    netscan 10.1.1.10

CIDR subnet:

    netscan 10.1.1.0/24

IP range:

    netscan 10.1.1.10-10.1.1.50

Mixed targets:

    netscan 10.1.1.0/24 10.2.2.10 10.3.3.10-10.3.3.20

------------------------------------------------------------------------

# Export Results

JSON:

    python -m cli.cli 10.1.1.0/24 --json results.json

CSV:

    python -m cli.cli 10.1.1.0/24 --csv results.csv

------------------------------------------------------------------------

# Installation

Clone the repository:

    git clone https://github.com/martinarosjorde-byte/netscan
    cd netscan

Install dependencies:

    pip install -r requirements.txt

------------------------------------------------------------------------

# Build Executable

    pip install pyinstaller
    pyinstaller --onefile --name netscan --collect-all manuf cli/cli.py

------------------------------------------------------------------------

# Disclaimer

NetScan is a network discovery tool intended for authorized
environments.

Only scan systems and networks you own or have permission to test.

Unauthorized scanning may violate laws and regulations.

------------------------------------------------------------------------

# Author

Martin Røsjorde\
Humbug Software
