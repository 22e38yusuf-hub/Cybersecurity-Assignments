"""
arp_scanner.py - Retrieve ARP table and display IP-MAC mappings
Cybersecurity Assignment | Network Scanning Tool
"""

import subprocess
import platform
import re
import sys


def get_arp_command(target: str = None) -> list:
    """Return the OS-appropriate ARP command."""
    system = platform.system().lower()
    if system == "windows":
        if target:
            return ["arp", "-a", target]
        return ["arp", "-a"]
    else:
        # Linux / macOS
        if target:
            return ["arp", "-n", target]
        return ["arp", "-n", "-a"]


def parse_arp_output(output: str) -> list:
    """
    Parse ARP output and return a list of dicts with keys:
      ip, mac, type (optional)
    Works for Windows, Linux, and macOS.
    """
    entries = []
    # Match a standard IP address
    ip_pattern = r"\b(\d{1,3}(?:\.\d{1,3}){3})\b"
    # Match MAC address in xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx formats
    mac_pattern = r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}" \
                  r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})"

    for line in output.splitlines():
        ip_match  = re.search(ip_pattern, line)
        mac_match = re.search(mac_pattern, line)
        if ip_match and mac_match:
            ip  = ip_match.group(1)
            mac = mac_match.group(1).replace("-", ":").lower()
            # Skip broadcast / incomplete entries
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue
            # Determine entry type (static / dynamic) if present
            entry_type = "unknown"
            if "dynamic" in line.lower():
                entry_type = "dynamic"
            elif "static" in line.lower():
                entry_type = "static"
            entries.append({"ip": ip, "mac": mac, "type": entry_type})

    return entries


def display_table(entries: list) -> None:
    """Pretty-print ARP entries in a table."""
    if not entries:
        print("\n  [!] No ARP entries found or table is empty.")
        return

    col_ip   = max(len(e["ip"])  for e in entries)
    col_mac  = max(len(e["mac"]) for e in entries)
    col_ip   = max(col_ip,  15)
    col_mac  = max(col_mac, 17)

    header = f"  {'IP Address':<{col_ip}}  {'MAC Address':<{col_mac}}  Type"
    sep    = f"  {'─'*col_ip}  {'─'*col_mac}  ───────"

    print(f"\n{header}")
    print(sep)
    for e in entries:
        print(f"  {e['ip']:<{col_ip}}  {e['mac']:<{col_mac}}  {e['type']}")
    print(sep)
    print(f"\n  Total entries found: {len(entries)}\n")


def scan_arp(target: str = None) -> None:
    """Run ARP scan and display the results."""
    cmd = get_arp_command(target)

    print(f"\n{'='*55}")
    print(f"  ARP Scan")
    print(f"  Platform : {platform.system()}")
    print(f"  Command  : {' '.join(cmd)}")
    if target:
        print(f"  Target   : {target}")
    else:
        print(f"  Target   : (full ARP table)")
    print(f"{'='*55}")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15
        )
        output = proc.stdout + proc.stderr

        if proc.returncode != 0 and not proc.stdout.strip():
            print(f"\n  [!] ARP command returned an error:\n{output}")
            return

        print("\n  Raw output:")
        print("  " + "\n  ".join(output.strip().splitlines()))

        entries = parse_arp_output(output)
        print(f"\n{'─'*55}")
        print("  Parsed IP → MAC Mappings")
        display_table(entries)

    except FileNotFoundError:
        print("  [!] Error: 'arp' command not found on this system.")
    except subprocess.TimeoutExpired:
        print("  [!] Timeout: ARP command did not complete in time.")
    except PermissionError:
        print("  [!] Permission denied. Try running with administrator/root privileges.")
    except Exception as exc:
        print(f"  [!] Unexpected error: {exc}")


def main():
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║         ARP SCANNER - IP to MAC Address Mapping      ║")
    print("╚══════════════════════════════════════════════════════╝")
    print("  Retrieves the local ARP table maintained by your OS.")
    print("  You may optionally filter by a specific IP address.\n")

    try:
        target = input("  Enter IP address to look up (or press Enter for full table): ").strip()
    except KeyboardInterrupt:
        print("\n  [!] Scan cancelled by user.")
        sys.exit(0)

    scan_arp(target if target else None)


if __name__ == "__main__":
    main()
