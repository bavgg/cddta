# WiFi Device Discovery - Complete Methodology & Lessons Learned

## Overview

This document teaches the complete methodology used to discover **7 devices** on your WiFi network, including the challenges encountered and how to overcome them.

---

## Phase 1: Reconnaissance Setup

### 1.1 Identify Your Network Context
```bash
# Find your interface and IP
ifconfig | grep -E "^[a-z]|inet "

# Result: en0 → 192.168.0.100/24
# Gateway: 192.168.0.1 (TP-Link)
```

### 1.2 Check Available Tools
```bash
which nmap arp-scan airport
# nmap: ✓ | arp-scan: needed install | airport: macOS built-in (hidden path)
```

**Lesson**: Always verify tool availability first. Install missing tools (`brew install arp-scan`).

---

## Phase 2: Layered Scanning Methodology

### The Core Principle: **Scan at Multiple Layers**

```
Layer 2 (Data Link)     → ARP Scan          → MAC addresses, vendor
Layer 3 (Network)       → ICMP/Ping Sweep   → IP reachability
Layer 4 (Transport)     → TCP SYN Scan      → Port responses, wakes sleeping devices
Layer 7 (Application)   → Service Scan      → Device fingerprinting
```

### 2.1 ARP Scan (Layer 2) - The Foundation
```bash
sudo arp-scan --localnet --interface=en0
```

**Why start here?**
- ARP is **mandatory** for LAN communication — devices CAN'T opt out
- Works even if firewall blocks everything else
- Reveals MAC vendor (identifies device manufacturer)
- **Fast**: ~2 seconds for /24 subnet

**Result**: Only 2 devices (router + your Mac)

---

### 2.2 TCP SYN Ping Sweep (Layer 4) - The Wake-Up Call
```bash
nmap -sn -PS80,443,22,23,21 192.168.0.0/24
```

**Why TCP SYN?**
- `-sn` = ping scan (no port scan)
- `-PS<ports>` = send SYN to these ports
- **Wakes sleeping WiFi radios** — phones in deep sleep respond to TCP but not ARP
- **Bypasses AP Isolation** — Layer 3 passes where Layer 2 is blocked

**Result**: 5 devices found (3 new: .104, .105, .117)

---

### 2.3 Broadcast Ping - The Broad Wake-Up
```bash
ping -c 3 192.168.0.255
```


**Why broadcast?**
- Reaches all devices simultaneously
- Some devices ignore unicast but respond to broadcast
- Woke `.102` which then appeared in ARP

**Result**: `.102` responded, `.101` appeared in follow-up ARP

---

### 2.4 Follow-up ARP Scan - Catch the Woken
```bash
sudo arp-scan --localnet --interface=en0
```

**Critical Step**: Re-scan ARP **after** TCP/broadcast woke devices.

**Result**: `.101` now visible with randomized MAC (`96:2d:fc:a5:07:ff`)

---

### 2.5 Service Version Scan (Layer 7) - Device Fingerprinting
```bash
nmap -sT -sV -T4 <target_ips>
```

**Why service scan?**
- Open ports + service versions = device identification
- Port 62078 = `iphone-sync` = definitive Apple device
- Port 5000/7000 = AirPlay = macOS/iOS
- Port 22/80/1900 = Router services

**Result**: Identified 2 iPhones/iPads definitively

---

## Phase 3: Problems Encountered & Solutions

### Problem 1: sudo Password Required
```
sudo: a terminal is required to read the password
```

**Cause**: macOS requires TTY for sudo by default.

**Solutions**:
```bash
# Option A: Run commands manually in your terminal
# Option B: Configure passwordless sudo (security risk)
# Option C: Use expect/sshpass for automation
```

**Lesson**: In automated scripts, handle sudo via:
- `sudo -S` (read password from stdin)
- NOPASSWD in sudoers (for specific commands only)
- Run interactive session manually

---

### Problem 2: ARP Scan Misses Sleeping Devices
```
ARP found 2, TCP found 5
```

**Cause**: 
- WiFi power save mode (phones sleep radio)
- AP Isolation (blocks wireless-to-wireless Layer 2)
- MAC randomization (different MAC when scanning vs connected)

**Solutions**:
```bash
# 1. TCP SYN scan wakes radios
nmap -sn -PS80,443 192.168.0.0/24

# 2. Broadcast ping
ping -c 3 192.168.0.255

# 3. Re-run ARP after wake-up
sudo arp-scan --localnet --interface=en0
```

**Lesson**: **Never trust a single scan**. Layer 2 ≠ Layer 3 visibility.

---

### Problem 3: nmap Script Engine Errors
```
'arp-scan' did not match a category, filename, or directory
```

**Cause**: Script name was wrong (`arp-scan` vs actual script names).

**Solution**: List available scripts first:
```bash
ls /opt/homebrew/share/nmap/scripts/ | grep -i arp
# Only found: dns-ip6-arpa-scan.nse
```

**Lesson**: Always verify script names with `nmap --script-help <name>` or list directory.

---

### Problem 4: Scan Timeouts on Full Port Scan
```
Command did not complete within its 120s timeout
```

**Cause**: Scanning 5 IPs × 1000 ports with service detection = slow.

**Solutions**:
```bash
# Fast scan (top 100 ports)
nmap -sT -F -T4 <targets>

# Specific ports only
nmap -sT -p 49152,62078 -sV <targets>

# Increase timeout
nmap --max-retries 1 --host-timeout 30s <targets>
```

**Lesson**: Use `-F` (fast) for reconnaissance; full scan only on targets of interest.

---

### Problem 5: MAC Randomization Confusion
```
Your Mac: 5e:ed:d5:5b:8b:0b (5e: = locally administered)
Device .101: 96:2d:fc:a5:07:ff (96: = locally administered)
```

**Cause**: 
- macOS/iOS/Android 10+ use randomized MAC per network
- `5e:`, `96:`, `a6:`, `d6:` prefixes = locally administered (randomized)

**Solutions**:
```bash
# 1. Use ARP scan (shows REAL MAC when connected)
# 2. Check router DHCP table (shows real MAC + hostname)
# 3. Use service fingerprinting (ports don't randomize)
```

**Lesson**: MAC ≠ Identity. Use **behavioral fingerprinting** (open ports, services).

---

### Problem 6: Filtered vs Closed Ports
```
.117: All 1000 ports filtered (firewall)
.104: All 1000 ports closed (no firewall, no services)
```

**Difference**:
| State | Meaning |
|-------|---------|
| **open** | Service listening |
| **closed** | No service, host responds (RST) |
| **filtered** | Firewall drops/silently blocks |
| **open|filtered** | Can't determine (UDP) |

**Lesson**: `filtered` = firewall present; `closed` = host up but no services.

---

## Phase 4: Complete Command Reference

### Discovery Commands (Run in Order)

```bash
# 1. Network context
ifconfig en0

# 2. ARP scan (Layer 2 - baseline)
sudo arp-scan --localnet --interface=en0

# 3. TCP SYN ping sweep (Layer 4 - wake sleepers)
nmap -sn -PS80,443,22,23,21 192.168.0.0/24

# 4. Broadcast ping (wake all)
ping -c 3 192.168.0.255

# 5. ARP scan again (catch woken)
sudo arp-scan --localnet --interface=en0

# 6. Fast port scan on new IPs
nmap -sT -F -T4 <new_ips>

# 7. Service scan on interesting ports
nmap -sT -sV -p <ports> <targets>

# 8. Full scan on high-value targets
nmap -sT -sV -p- -T4 <target>
```

### Identification Commands

```bash
# Router admin (ground truth)
open http://192.168.0.1

# SNMP from router (if enabled)
snmpwalk -v2c -c public 192.168.0.1 1.3.6.1.2.1.4.22.1.2

# Vendor lookup from MAC
curl "https://api.macvendors.com/28:ee:52:f7:74:dc"

# Continuous monitoring
watch -n 30 'sudo arp-scan --localnet --interface=en0 | grep -E "^[0-9]"'
```

---

## Phase 5: Device Fingerprinting Cheatsheet

### Common Device Signatures

| Device | Key Ports | Services |
|--------|-----------|----------|
| **iPhone/iPad** | 62078, 49152, 49157 | iphone-sync, AirPlay |
| **Mac** | 5000, 7000, 8082 | AirPlay, AirDrop, custom |
| **Apple TV** | 3689, 5000, 7000 | DAAP, AirPlay |
| **Android** | 5555, 8080, 9000 | ADB, HTTP, custom |
| **Windows** | 135, 139, 445, 3389 | RPC, SMB, RDP |
| **Router** | 22, 53, 80, 443, 1900 | SSH, DNS, HTTP, UPnP |
| **Printer** | 9100, 631, 515 | JetDirect, IPP, LPD |
| **Smart TV** | 8008, 8009, 9000 | Chromecast, DIAL |
| **IoT/Camera** | 554, 8000, 8080 | RTSP, HTTP |

### Port 62078 Deep Dive
```
Service: iphone-sync
Protocol: TCP
Purpose: Wireless iTunes/Finder sync
Exclusive to: Apple devices (iOS, iPadOS, macOS)
Reliability: 100% indicator of Apple device
```

---

## Phase 6: Automation Script

Save as `discover_wifi.sh`:

```bash
#!/bin/bash
# Complete WiFi device discovery
# Usage: sudo ./discover_wifi.sh

IFACE="en0"
SUBNET="192.168.0.0/24"
OUTDIR="./scans/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTDIR"

echo "[1/5] ARP Baseline Scan..."
sudo arp-scan --localnet --interface="$IFACE" > "$OUTDIR/01_arp_baseline.txt"

echo "[2/5] TCP SYN Ping Sweep..."
nmap -sn -PS80,443,22,23,21 "$SUBNET" -oN "$OUTDIR/02_tcp_syn.txt"

echo "[3/5] Broadcast Ping Wake..."
ping -c 3 192.168.0.255 > "$OUTDIR/03_broadcast_ping.txt"
sleep 2

echo "[4/5] ARP Follow-up Scan..."
sudo arp-scan --localnet --interface="$IFACE" > "$OUTDIR/04_arp_followup.txt"

echo "[5/5] Fast Port Scan on All Live Hosts..."
LIVE_IPS=$(grep "Host is up" "$OUTDIR/02_tcp_syn.txt" | awk '{print $2}' | tr '\n' ' ')
nmap -sT -F -T4 $LIVE_IPS -oN "$OUTDIR/05_fast_scan.txt"

echo "Done! Results in $OUTDIR/"
ls -la "$OUTDIR/"
```

---

## Phase 7: Key Takeaways

### Methodology Principles

1. **Multi-layer scanning** — Each layer reveals different devices
2. **Iterative approach** — Scan → Wake → Re-scan → Identify
3. **Correlate evidence** — MAC + ports + services = confident ID
4. **Document everything** — Save outputs with timestamps

### Common Pitfalls to Avoid

| Pitfall | Prevention |
|---------|------------|
| Single scan = complete picture | Always use 3+ methods |
| Trust MAC addresses | Use behavioral fingerprinting |
| Skip service detection | It's the only way to ID device type |
| Ignore filtered ports | They reveal firewall presence |
| Scan everything deeply | Use fast scan first, deep scan targeted |

### Your Network Reality

```
Discovered: 7 devices
Identified: 4 (Router, Mac, 2× iPhone/iPad)
Unknown:    3 (firewalled/closed)
```

The 3 unknowns are likely:
- IoT devices (smart plugs, bulbs) with minimal ports
- Guest devices with firewalls
- Devices on isolated VLAN/SSID

---

## Next Learning Steps

1. **Practice**: Run this methodology on different networks (home, lab, authorized)
2. **Automate**: Build the script above into a reusable tool
3. **Learn NSE**: Nmap Scripting Engine for vuln detection
4. **Wireless-specific**: Get USB WiFi adapter + Kali for monitor mode
5. **Passive analysis**: Wireshark/tcpdump for traffic analysis

---

*Session Date: 2026-11-02 | Methodology: Multi-layer iterative discovery*