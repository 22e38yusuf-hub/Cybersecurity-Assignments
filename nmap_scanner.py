"""
nmap_scanner.py - Perform network scans using Nmap
Cybersecurity Assignment | Network Scanning Tool

Supports:
  1. Host Discovery
  2. Port Scanning (common ports)
  3. Custom Port Scan
  4. Service Detection
  5. OS Detection
"""

import subprocess
import sys
import shutil


# ─── Helpers ─────────────────────────────────────────────────────────────────

def check_nmap() -> str:
    """Return the path to nmap or exit with an error."""
    path = shutil.which("nmap")
    if not path:
        print("\n  [!] Nmap is not installed or not in PATH.")
        print("      Install it from: https://nmap.org/download.html")
        sys.exit(1)
    return path


def run_nmap(args: list, description: str) -> None:
    """Execute an nmap command and stream output to the terminal."""
    cmd = ["nmap"] + args
    print(f"\n{'='*60}")
    print(f"  Scan Type : {description}")
    print(f"  Command   : {' '.join(cmd)}")
    print(f"{'='*60}\n")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300          # 5-minute safety timeout
        )
        output = proc.stdout + proc.stderr
        print(output if output.strip() else "  (No output returned.)")

        if proc.returncode != 0 and not proc.stdout.strip():
            print(f"  [!] Nmap exited with code {proc.returncode}.")
        else:
            print(f"\n  [✓] Scan complete.")

    except subprocess.TimeoutExpired:
        print("  [!] Scan timed out after 5 minutes.")
    except PermissionError:
        print("  [!] Permission denied. OS detection (-O) and SYN scans (-sS)")
        print("      require administrator / root privileges.")
    except Exception as exc:
        print(f"  [!] Unexpected error: {exc}")

    print(f"{'='*60}\n")


# ─── Scan functions ───────────────────────────────────────────────────────────

def host_discovery(target: str) -> None:
    """Ping scan — discover live hosts without port scanning (-sn)."""
    run_nmap(["-sn", target], "Host Discovery (Ping Scan)")


def port_scan(target: str) -> None:
    """Scan the 1000 most common ports (default nmap behaviour)."""
    run_nmap([target], "Port Scan (Top 1000 Ports)")


def custom_port_scan(target: str, ports: str) -> None:
    """Scan a user-specified port or range (e.g. 22,80,443 or 1-1024)."""
    run_nmap(["-p", ports, target], f"Custom Port Scan (ports: {ports})")


def service_detection(target: str) -> None:
    """Detect service versions on open ports (-sV)."""
    run_nmap(["-sV", target], "Service Version Detection")


def os_detection(target: str) -> None:
    """Attempt OS fingerprinting (-O). Requires root/admin."""
    print("\n  [i] OS detection requires administrator / root privileges.")
    print("      If you see a permission error, re-run with sudo (Linux/macOS)")
    print("      or as Administrator (Windows).\n")
    run_nmap(["-O", target], "OS Detection")


def aggressive_scan(target: str) -> None:
    """Aggressive scan: OS + version + scripts + traceroute (-A)."""
    print("\n  [i] Aggressive scan combines OS detection, service detection,")
    print("      script scanning, and traceroute. May take longer.\n")
    run_nmap(["-A", target], "Aggressive Scan (-A)")


# ─── Menu ─────────────────────────────────────────────────────────────────────

MENU = {
    "1": ("Host Discovery",          host_discovery,    False),
    "2": ("Port Scan (top 1000)",    port_scan,         False),
    "3": ("Custom Port Scan",        custom_port_scan,  True),   # extra input
    "4": ("Service Detection",       service_detection, False),
    "5": ("OS Detection",            os_detection,      False),
    "6": ("Aggressive Scan (-A)",    aggressive_scan,   False),
}


def print_menu() -> None:
    print("\n  Select a scan type:")
    print("  " + "─"*40)
    for key, (label, _, _) in MENU.items():
        print(f"  [{key}] {label}")
    print("  [0] Exit")
    print("  " + "─"*40)


def main():
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║          NMAP SCANNER - Advanced Network Scanning        ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print("║  ⚠  ETHICAL NOTICE                                       ║")
    print("║  Only scan networks you own or have explicit permission   ║")
    print("║  to scan. Unauthorized scanning may be illegal.           ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    # Ensure nmap is available before asking for input
    check_nmap()

    try:
        target = input("  Enter IP address, hostname, or network range\n"
                       "  (e.g. 127.0.0.1  /  scanme.nmap.org  /  192.168.1.0/24): ").strip()
    except KeyboardInterrupt:
        print("\n  [!] Exiting.")
        sys.exit(0)

    if not target:
        print("  [!] No target provided. Exiting.")
        sys.exit(1)

    while True:
        print_menu()
        try:
            choice = input("  Your choice: ").strip()
        except KeyboardInterrupt:
            print("\n  [!] Exiting.")
            break

        if choice == "0":
            print("  Goodbye!\n")
            break

        if choice not in MENU:
            print("  [!] Invalid option. Please try again.")
            continue

        label, func, needs_extra = MENU[choice]

        if needs_extra:
            try:
                ports = input("  Enter port(s) to scan (e.g. 22,80,443 or 1-1024): ").strip()
            except KeyboardInterrupt:
                print("\n  [!] Cancelled.")
                continue
            if not ports:
                print("  [!] No ports entered.")
                continue
            func(target, ports)
        else:
            func(target)

        try:
            again = input("  Run another scan on the same target? [y/N]: ").strip().lower()
        except KeyboardInterrupt:
            print("\n  [!] Exiting.")
            break
        if again != "y":
            print("  Goodbye!\n")
            break


if __name__ == "__main__":
    main()
