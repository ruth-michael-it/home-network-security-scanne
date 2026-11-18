# Home Wi-Fi & Device Security Scanner

A lightweight, cross-platform Python network monitoring utility that inspects the local Address Resolution Protocol (ARP) cache to map connected IPv4 and MAC addresses, compare them against a JSON allowlist of trusted household devices, and flag unknown hardware on the local network.

## Everyday Problem Solved
Home and small-office Wi-Fi networks frequently host multiple laptops, smartphones, and smart devices. Without active visibility, unauthorized devices or rogue endpoints can remain unnoticed on a local subnet. This script provides an automated, repeatable way to baseline known devices and detect unfamiliar MAC addresses quickly from the command line.

## Key Features & Engineering Practices
* **Automatic Subnet Discovery:** Opens a lightweight UDP socket (`8.8.8.8:80`) without transmitting packets to accurately determine the host machine's active local IPv4 address and `/24` subnet prefix.
* **Cross-Platform ARP Parsing:** Executes the native `arp -a` system command via Python's `subprocess` module and uses regular expressions (`re`) to extract IPv4-to-MAC address bindings across Windows, Linux, and macOS.
* **Noise Filtering:** Automatically filters out broadcast (`ff:ff:ff:ff:ff:ff`) and multicast (`01:00:5e`, `33:33`) addresses so reports focus strictly on real endpoint hardware.
* **Persistent JSON Allowlist Baseline:** Stores approved MAC addresses and friendly device labels in `trusted_devices.json`, enabling instant detection of unauthorized devices during future scans.

## Project Structure
```text
home-network-security-scanner/
├── network_scanner.py      # Main Python ARP inspection and allowlist script
├── trusted_devices.json    # Local JSON baseline of approved MAC addresses (auto-generated)
├── README.md               # Project documentation
└── screenshots/
    └── network_audit.png   # Terminal output showing trusted vs. unknown device alerts
```

## Prerequisites
* **Python 3.8+** (Built entirely with Python standard libraries: `json`, `os`, `re`, `socket`, `subprocess`, and `datetime` — no external packet drivers required).

## How to Run
1. Clone this repository:
   ```bash
   git clone https://github.com
   cd home-network-security-scanner
   ```
2. Run the scanner from your terminal:
   ```bash
   python network_scanner.py
   ```
3. On your first scan, follow the interactive prompt (`y`) to label and save your known household devices (such as your router, laptop, and smartphone) to `trusted_devices.json`.
4. Run the script again anytime to verify your baseline and detect new connections.

## Sample Output
```text
=== Home Wi-Fi & Device Security Scanner ===
Host IP Address : 192.168.178.24
Active Subnet   : 192.168.178.0/24
Scan Timestamp  : 2026-11-18 14:00:00
-------------------------------------------------------
[TRUSTED] IP: 192.168.178.1   | MAC: aa:bb:cc:11:22:33 | Label: FritzBox Router
[TRUSTED] IP: 192.168.178.25  | MAC: dd:ee:ff:44:55:66 | Label: Ruth Laptop
[ALERT!]  IP: 192.168.178.42  | MAC: 12:34:56:78:9a:bc | Status: UNKNOWN DEVICE
-------------------------------------------------------
Total Devices Found: 3 | Unknown Devices: 1
```

## Security Best Practice Note
Before pushing this repository to a public GitHub profile, consider adding `trusted_devices.json` to your `.gitignore` file so your personal household MAC addresses remain private while sharing a sample structure in your documentation.
