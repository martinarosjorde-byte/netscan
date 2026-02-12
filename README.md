# NetScan Enterprise

NetScan Enterprise is a fast asynchronous TCP network scanner with a clean terminal UI.

It is designed for internal network discovery and asset identification in enterprise environments.

---

## Features

- Async TCP port scanning
- High concurrency (masscan-inspired performance)
- Clean live terminal interface (Rich)
- Automatic local subnet suggestion
- Real-time statistics
- Lightweight and portable
- Windows-compatible
- Can be compiled to standalone EXE

---

## Default Ports

By default the scanner checks:

- 22 (SSH)
- 80 (HTTP)
- 443 (HTTPS)
- 445 (SMB)
- 3389 (RDP)

These can be modified in the source code.

---

pyinstaller --onefile --windowed netscan_gui.py

## Installation

Clone repository:

