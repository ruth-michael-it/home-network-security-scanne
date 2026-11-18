import json
import os
import re
import socket
import subprocess
from datetime import datetime

TRUSTED_DB_FILE = "trusted_devices.json"


def get_local_ip_and_prefix():
    """Finds the computer's active local IPv4 address and subnet prefix (e.g., 192.168.178)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        prefix = ".".join(local_ip.split(".")[:3])
        return local_ip, prefix
    except Exception:
        return "127.0.0.1", "192.168.1"


def get_arp_devices():
    """Runs 'arp -a' to extract active IPv4 and MAC addresses on the local Wi-Fi network."""
    output = subprocess.check_output(["arp", "-a"], text=True, encoding="utf-8", errors="ignore")
    devices = []

    # Matches IPv4 address followed by a MAC address (supports both '-' and ':' separators)
    pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")

    for match in pattern.finditer(output):
        ip_addr = match.group(1)
        mac_addr = match.group(2).replace("-", ":").lower()

        # Skip broadcast and multicast MAC addresses
        if mac_addr == "ff:ff:ff:ff:ff:ff" or mac_addr.startswith(("01:00:5e", "33:33")):
            continue

        devices.append({"ip": ip_addr, "mac": mac_addr})

    return devices


def load_trusted_devices():
    """Loads known household MAC addresses from trusted_devices.json."""
    if not os.path.exists(TRUSTED_DB_FILE):
        return {}
    with open(TRUSTED_DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_trusted_devices(trusted_dict):
    """Saves known household MAC addresses to trusted_devices.json."""
    with open(TRUSTED_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(trusted_dict, f, indent=4)


def scan_network():
    print("=== Home Wi-Fi & Device Security Scanner ===")
    local_ip, subnet_prefix = get_local_ip_and_prefix()
    print(f"Host IP Address : {local_ip}")
    print(f"Active Subnet   : {subnet_prefix}.0/24")
    print(f"Scan Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n" + "-" * 55)

    trusted = load_trusted_devices()
    devices = get_arp_devices()

    if not devices:
        print("No active devices found in the ARP table. Try browsing a webpage and re-running.")
        return

    unknown_count = 0

    for dev in devices:
        ip = dev["ip"]
        mac = dev["mac"]

        if mac in trusted:
            print(f"[TRUSTED] IP: {ip:<15} | MAC: {mac} | Label: {trusted[mac]}")
        else:
            print(f"[ALERT!]  IP: {ip:<15} | MAC: {mac} | Status: UNKNOWN DEVICE")
            unknown_count += 1

    print("-" * 55)
    print(f"Total Devices Found: {len(devices)} | Unknown Devices: {unknown_count}")

    # Offer to baseline/save unknown devices on first run
    if unknown_count > 0:
        choice = input("\nWould you like to label and trust any of these unknown devices now? (y/n): ").strip().lower()
        if choice == "y":
            for dev in devices:
                mac = dev["mac"]
                if mac not in trusted:
                    label = input(f"Enter a label for {dev['ip']} ({mac}) [or press Enter to skip]: ").strip()
                    if label:
                        trusted[mac] = label
            save_trusted_devices(trusted)
            print(f"Updated {TRUSTED_DB_FILE} successfully!")


if __name__ == "__main__":
    scan_network()
