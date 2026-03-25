"""
ping_scanner.py - Scan hosts using ping and measure response time
Cybersecurity Assignment | Network Scanning Tool
"""

import subprocess
import platform
import time
import re
import sys


def get_ping_command(host: str) -> list:
    """Return OS-appropriate ping command."""
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "4", host]
    else:
        # Linux / macOS
        return ["ping", "-c", "4", host]


def parse_ping_output(output: str, system: str) -> dict:
    """Extract summary stats from ping output."""
    result = {"packets_sent": None, "packets_received": None,
              "packet_loss": None, "min_rtt": None, "avg_rtt": None, "max_rtt": None}

    if system == "windows":
        # Packets: Sent = 4, Received = 3, Lost = 1 (25% loss)
        pkt = re.search(r"Sent\s*=\s*(\d+).*Received\s*=\s*(\d+).*\((\d+)% loss\)", output)
        if pkt:
            result["packets_sent"] = int(pkt.group(1))
            result["packets_received"] = int(pkt.group(2))
            result["packet_loss"] = int(pkt.group(3))
        # Minimum = 10ms, Maximum = 20ms, Average = 15ms
        rtt = re.search(r"Minimum\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms.*Average\s*=\s*(\d+)ms", output)
        if rtt:
            result["min_rtt"] = int(rtt.group(1))
            result["max_rtt"] = int(rtt.group(2))
            result["avg_rtt"] = int(rtt.group(3))
    else:
        # --- packets ---
        pkt = re.search(r"(\d+) packets transmitted,\s*(\d+) received", output)
        if pkt:
            result["packets_sent"] = int(pkt.group(1))
            result["packets_received"] = int(pkt.group(2))
        loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
        if loss:
            result["packet_loss"] = float(loss.group(1))
        # rtt min/avg/max/mdev = 0.123/0.456/0.789/0.111 ms
        rtt = re.search(r"rtt.*=\s*([\d.]+)/([\d.]+)/([\d.]+)", output)
        if rtt:
            result["min_rtt"] = float(rtt.group(1))
            result["avg_rtt"] = float(rtt.group(2))
            result["max_rtt"] = float(rtt.group(3))
    return result


def ping_host(host: str) -> None:
    """Ping a single host and display results."""
    system = platform.system().lower()
    cmd = get_ping_command(host)

    print(f"\n{'='*55}")
    print(f"  Target   : {host}")
    print(f"  Platform : {platform.system()}")
    print(f"  Command  : {' '.join(cmd)}")
    print(f"{'='*55}")

    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20
        )
        elapsed = time.time() - start
        output = proc.stdout + proc.stderr

        print(output)

        stats = parse_ping_output(output, system)

        print(f"{'─'*55}")
        print("  Summary")
        print(f"{'─'*55}")
        if stats["packets_sent"] is not None:
            print(f"  Packets Sent     : {stats['packets_sent']}")
            print(f"  Packets Received : {stats['packets_received']}")
            print(f"  Packet Loss      : {stats['packet_loss']}%")
        if stats["avg_rtt"] is not None:
            print(f"  Min RTT          : {stats['min_rtt']} ms")
            print(f"  Avg RTT          : {stats['avg_rtt']} ms")
            print(f"  Max RTT          : {stats['max_rtt']} ms")
        print(f"  Total Time       : {elapsed:.2f} s")

        if proc.returncode == 0:
            print(f"\n  [✓] Host {host} is REACHABLE")
        else:
            print(f"\n  [✗] Host {host} is UNREACHABLE")

    except subprocess.TimeoutExpired:
        print(f"\n  [!] Timeout: No response from {host} within 20 seconds.")
    except FileNotFoundError:
        print("  [!] Error: 'ping' command not found on this system.")
    except Exception as exc:
        print(f"  [!] Unexpected error: {exc}")

    print(f"{'='*55}\n")


def main():
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║            PING SCANNER - Network Reachability       ║")
    print("╚══════════════════════════════════════════════════════╝")
    print("  Hint: Enter an IP address (e.g. 192.168.1.1),")
    print("        a hostname (e.g. google.com), or")
    print("        'localhost' to test your own machine.\n")

    try:
        target = input("  Enter IP / Hostname: ").strip()
    except KeyboardInterrupt:
        print("\n  [!] Scan cancelled by user.")
        sys.exit(0)

    if not target:
        print("  [!] No input provided. Exiting.")
        sys.exit(1)

    ping_host(target)


if __name__ == "__main__":
    main()
