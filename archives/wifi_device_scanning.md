# Scanning Devices Connected to Your WiFi

## Quick Reference

| Method | Command | Needs Root? | Best For |
|--------|---------|-------------|----------|
| **ARP Scan** | `sudo arp-scan --localnet --interface=en0` | Yes | Complete device list (Layer 2) |
| **nmap ARP** | `sudo nmap -sn 192.168.0.0/24` | Yes | Network discovery + hostnames |
| **nmap TCP** | `nmap -sn -PS80,443 192.168.0.0/24` | No | Quick check without sudo |
| **Router UI** | Browser → `http://192.168.0.1` | No | Authoritative DHCP lease list |
| **macOS ARP** | `arp -a` | No | Recent connections only |

---

## 1. ARP Scan (Most Reliable for Local Network)

### Install
```bash
brew install arp-scan
```

### Scan
```bash
# Basic scan
sudo arp-scan --localnet --interface=en0

# With vendor lookup (built-in)
sudo arp-scan --localnet --interface=en0 --ouifile /usr/local/share/arp-scan/ieee-oui.txt

# JSON output for scripting
sudo arp-scan --localnet --interface=en0 --format=json
```

### Example Output
```
Interface: en0, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.0.100
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.0.1     00:11:22:33:44:55   TP-LINK TECHNOLOGIES CO.,LTD.
192.168.0.100   aa:bb:cc:dd:ee:ff   Apple, Inc.
192.168.0.106   11:22:33:44:55:66   Samsung Electronics Co.,Ltd
192.168.0.117   22:33:44:55:66:77   Intel Corporate
192.168.0.120   33:44:55:66:77:88   (Unknown)
4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.234 seconds (207.5 hosts/sec)
```

### Why ARP Works
- **Layer 2 protocol** — devices MUST respond to communicate on LAN
- **Firewalls don't block ARP** — it's below IP layer
- **Shows MAC addresses** — identify device vendor via OUI lookup

---

## 2. nmap Host Discovery

### ARP-based (Best Accuracy)
```bash
# Ping sweep with ARP (local network only)
sudo nmap -sn 192.168.0.0/24

# With vendor MAC lookup
sudo nmap -sn --script=arp-scan 192.168.0.0/24
```

### TCP-based (No Root Required)
```bash
# SYN to common ports
nmap -sn -PS80,443,22,21,23 192.168.0.0/24

# ACK scan (different behavior)
nmap -sn -PA80,443 192.168.0.0/24

# UDP scan
nmap -sn -PU53,67,123 192.168.0.0/24
```

### Combined (Most Thorough)
```bash
sudo nmap -sn -PS80,443 -PA80,443 -PU53 --script=arp-scan 192.168.0.0/24
```

---

## 3. Router Admin Interface (Most Complete)

### Access
1. Open browser: `http://192.168.0.1` (or your gateway IP)
2. Default credentials (check router label):
   - `admin` / `admin`
   - `admin` / `password`
   - `admin` / (blank)

### Look For
| Section Name | What It Shows |
|--------------|---------------|
| **Attached Devices** | All connected clients |
| **Device List** | IP, MAC, name, connection type |
| **DHCP Client List** | Leased IPs with hostnames |
| **Wireless Client List** | WiFi-specific connections |
| **Access Control** | Block/allow by MAC |

### Advantages
- Shows **device hostnames** (from DHCP)
- Shows **connection time / lease expiry**
- Shows **wired vs wireless** connection
- **Authoritative source** — router knows all

---

## 4. macOS Built-in Tools

### ARP Table (Recent Conversations)
```bash
# IPv4 ARP cache
arp -a

# Output example:
# ? (192.168.0.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]
# ? (192.168.0.106) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
```

### Network Neighbors (IPv4 + IPv6)
```bash
# Show all neighbors
ndp -a

# Show only reachable
ndp -an | grep reachable
```

### Airport/WiFi Info
```bash
# Current connection details
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I

# Scan nearby networks
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s
```

---

## 5. Automated Monitoring Script

### Save as `monitor_wifi.sh`
```bash
#!/bin/bash
# Continuous WiFi device monitor
# Run: sudo ./monitor_wifi.sh

INTERFACE="en0"
SUBNET="192.168.0.0/24"
KNOWN_DEVICES="/tmp/known_devices.txt"

# Initialize known devices
touch "$KNOWN_DEVICES"

echo "[$(date)] Starting WiFi monitor on $INTERFACE..."

while true; do
    # Scan with ARP
    CURRENT=$(sudo arp-scan --localnet --interface="$INTERFACE" 2>/dev/null | \
              grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
              awk '{print $1 " " $2 " " $3}' | sort)
    
    # Check for new devices
    while IFS= read -r line; do
        IP=$(echo "$line" | awk '{print $1}')
        MAC=$(echo "$line" | awk '{print $2}')
        VENDOR=$(echo "$line" | cut -d' ' -f3-)
        
        if ! grep -q "$MAC" "$KNOWN_DEVICES"; then
            echo "[$(date)] NEW DEVICE: $IP $MAC $VENDOR"
            echo "$MAC $IP $VENDOR" >> "$KNOWN_DEVICES"
        fi
    done <<< "$CURRENT"
    
    sleep 30
done
```

### Run
```bash
chmod +x monitor_wifi.sh
sudo ./monitor_wifi.sh
```

---

## 6. Python Script for Rich Output

### Save as `wifi_scan.py`
```python
#!/usr/bin/env python3
"""WiFi device scanner with rich output."""
import subprocess
import json
import sys
from datetime import datetime

def run_arp_scan(interface="en0"):
    """Run arp-scan and return parsed results."""
    try:
        result = subprocess.run(
            ["sudo", "arp-scan", "--localnet", "--interface", interface, "--format=json"],
            capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return []

def run_nmap_scan(subnet="192.168.0.0/24"):
    """Run nmap ping sweep."""
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-sn", "-oJ", "-", subnet],
            capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return {}

def main():
    print(f"\n{'='*60}")
    print(f" WiFi Device Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    # ARP Scan
    print("📡 ARP Scan Results:")
    print("-" * 60)
    devices = run_arp_scan()
    
    if devices:
        print(f"{'IP Address':<16} {'MAC Address':<18} {'Vendor'}")
        print("-" * 60)
        for d in devices:
            ip = d.get('ip', 'N/A')
            mac = d.get('mac', 'N/A')
            vendor = d.get('vendor', 'Unknown')
            print(f"{ip:<16} {mac:<18} {vendor}")
    else:
        print("No devices found (need sudo?)")
    
    # Nmap for hostnames
    print("\n🔍 Nmap Discovery (with hostnames):")
    print("-" * 60)
    nmap_data = run_nmap_scan()
    
    if 'nmaprun' in nmap_data:
        for host in nmap_data['nmaprun'].get('host', []):
            addr = host.get('address', [])
            ip = next((a['@addr'] for a in addr if a['@addrtype'] == 'ipv4'), 'N/A')
            mac = next((a['@addr'] for a in addr if a['@addrtype'] == 'mac'), 'N/A')
            vendor = next((a.get('@vendor', '') for a in addr if a['@addrtype'] == 'mac'), '')
            hostnames = host.get('hostnames', {}).get('hostname', [])
            name = hostnames[0]['@name'] if hostnames else 'Unknown'
            print(f"{ip:<16} {mac:<18} {vendor:<25} {name}")

if __name__ == "__main__":
    main()
```

### Run
```bash
chmod +x wifi_scan.py
sudo python3 wifi_scan.py
```

---

## 7. Mobile Apps (Convenient)

| App | Platform | Key Features |
|-----|----------|--------------|
| **Fing** | iOS/Android | Device recognition, network alerts, speed test |
| **Network Analyzer** | iOS/Android | Ping, traceroute, port scan, DNS lookup |
| **WiFi Analyzer** | Android | Signal strength, channel graph, device list |
| **IP Tools** | Android | Comprehensive network toolkit |

---

## 8. Understanding Your Results

### MAC Address Vendor Lookup (OUI)
First 3 octets (6 hex chars) = Organizationally Unique Identifier

```bash
# Quick lookup
curl -s "https://api.macvendors.com/00:11:22"

# Local database (arp-scan includes this)
grep -i "00:11:22" /usr/local/share/arp-scan/ieee-oui.txt
```

### Common Vendors
| OUI Prefix | Vendor |
|------------|--------|
| `00:11:22` | Cisco |
| `28:CF:E9` | Apple |
| `3C:07:54` | Apple |
| `A4:83:E7` | Samsung |
| `B8:27:EB` | Raspberry Pi |
| `00:1A:11` | Google/Nest |

---

## 9. Troubleshooting

### "No devices found"
```bash
# Check interface name
ifconfig | grep -E "^[a-z].*:"

# Try correct interface
sudo arp-scan --interface=en0 --localnet
```

### "Permission denied"
```bash
# Must run with sudo for raw sockets
sudo arp-scan --localnet --interface=en0
```

### Missing devices
- Device firewall blocking ICMP/TCP (ARP still works)
- Device asleep (WiFi power save)
- Different VLAN/subnet
- MAC randomization (iOS 14+, Android 10+)

---

## 10. Security Notes

### Detecting Unauthorized Devices
```bash
# Compare against known good list
sudo arp-scan --localnet --interface=en0 | \
  grep -v -f known_macs.txt | \
  grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
```

### MAC Randomization
Modern phones use **randomized MACs** when scanning, but use **real MAC** when connected. Connected devices show real MAC in ARP table.

---

## Quick Start Commands (Copy-Paste)

```bash
# 1. Best single command (install first)
brew install arp-scan && sudo arp-scan --localnet --interface=en0

# 2. Quick nmap (no install needed)
sudo nmap -sn 192.168.0.0/24

# 3. Router login (open in browser)
open http://192.168.0.1

# 4. Built-in only
arp -a
```

---

## Files in This Project
- `LEARNING_PLAN.md` — Full penetration testing curriculum
- `wifi_scanning_guide.md` — Network scanning methodology
- `wifi_device_scanning.md` — This file (device discovery focus)

---

*Last updated: 2026-11-02 | Tested on macOS 27.0 (Darwin)*