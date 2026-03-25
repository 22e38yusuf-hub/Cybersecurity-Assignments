# Network Scanning Tools – Cybersecurity Assignment

A collection of three Python-based network scanning utilities built for educational purposes.

---

## Tools Included

| File | Purpose |
|---|---|
| `ping_scanner.py` | Scan a host using ping and measure response time |
| `arp_scanner.py` | Retrieve the local ARP table and display IP–MAC mappings |
| `nmap_scanner.py` | Perform comprehensive network scans using Nmap |

---

## Prerequisites

### Python
Python **3.6 or higher** is required.

```bash
python --version
```

### Nmap
Required only for `nmap_scanner.py`.

| OS | Install Command |
|---|---|
| Windows | Download from [nmap.org](https://nmap.org/download.html) |
| macOS | `brew install nmap` |
| Ubuntu/Debian | `sudo apt install nmap` |
| Fedora/RHEL | `sudo dnf install nmap` |

No third-party Python packages are needed — all scripts use only the standard library (`subprocess`, `platform`, `re`, `sys`, `shutil`).

---

## Usage

### 1. Ping Scanner

```bash
python ping_scanner.py
```

Enter an IP address, hostname, or `localhost`. The script will:
- Send 4 ICMP echo requests
- Report packets sent / received / lost
- Report min / avg / max round-trip time (RTT)
- Confirm whether the host is reachable

**Test first:**
```
Enter IP / Hostname: 127.0.0.1
```

---

### 2. ARP Scanner

```bash
python arp_scanner.py
```

- Press **Enter** to display the full ARP table
- Or enter a specific IP address to look up just that entry

The script displays a formatted table of IP → MAC address mappings.

> **Note:** On some systems you may need administrator / root privileges to read the full ARP table.

---

### 3. Nmap Scanner

```bash
python nmap_scanner.py
```

Enter a target (IP, hostname, or CIDR range), then choose a scan type from the menu:

| Option | Scan Type | Nmap Flag(s) |
|---|---|---|
| 1 | Host Discovery | `-sn` |
| 2 | Port Scan (top 1000) | *(default)* |
| 3 | Custom Port Scan | `-p <ports>` |
| 4 | Service Detection | `-sV` |
| 5 | OS Detection | `-O` |
| 6 | Aggressive Scan | `-A` |

> **Note:** OS detection (option 5) and the aggressive scan (option 6) require **administrator / root** privileges.

```bash
# Linux / macOS — root required for OS detection
sudo python nmap_scanner.py
```

---

## Testing on Localhost

Always test on your own machine before scanning any other host:

```
127.0.0.1        # IPv4 loopback
localhost        # hostname alias
```

---

## Repository Structure

```
.
├── ping_scanner.py
├── arp_scanner.py
├── nmap_scanner.py
├── README.md
└── screenshots/
    ├── ping_scanner.png
    ├── arp_scanner.png
    └── nmap_scanner.png
```

---

## Ethical & Legal Notice

> **Only scan networks and hosts you own or have explicit written permission to scan.**
> Unauthorized port scanning or network reconnaissance may violate local, national, or international laws (e.g. the Computer Fraud and Abuse Act in the US, or the IT Act in India).
> These tools are provided for **educational purposes only**.

---

## Platform Compatibility

All scripts are tested and compatible with:
- ✅ Windows 10 / 11
- ✅ macOS (Intel & Apple Silicon)
- ✅ Linux (Ubuntu, Debian, Fedora)
