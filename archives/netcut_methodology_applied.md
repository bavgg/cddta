# Applying Netcut Methodology to Your Network Discovery

## Netcut's Device Discovery Techniques (From Reverse Engineering)

| Technique | Netcut Implementation | Your Equivalent |
|-----------|----------------------|-----------------|
| **ARP Scanning** | `CAdapterMonitor::_LoopDevs()` sends ARP requests to all IPs | `sudo arp-scan --localnet` |
| **Neighbor Discovery (IPv6)** | `OnICMP6()`, `MakeSureOffOn6()` | `ndp -a` |
| **NetBIOS/NBTS** | Embedded nbtscan 1.0.35 | `nmap -sU -p 137 --script=nbstat` |
| **DHCP Monitoring** | `OnDHCPPacket()` passive listen | `tcpdump -i en0 port 67 or 68` |
| **Passive Packet Sniffing** | BPF/libpcap capture all traffic | `sudo tcpdump -i en0` |
| **MAC Vendor Lookup** | 737KB `macdata` OUI database | `arp-scan` built-in / `curl macvendors.com` |
| **Local REST API** | HTTP on 127.0.0.1:4625 `/list/` | Manual nmap/arp-scan |

---

## Your Network: Complete Device Identification Using Netcut Methods

### Phase 1: Active ARP Discovery (Netcut's Primary Method)

```bash
# Netcut-style ARP scan with vendor lookup
sudo arp-scan --localnet --interface=en0 --ouifile /usr/local/share/arp-scan/ieee-oui.txt
```

**Your Results:**
| IP | MAC | Vendor | Netcut Would Show |
|----|-----|--------|-------------------|
| 192.168.0.1 | 28:ee:52:f7:74:dc | TP-Link | Router/Gateway |
| 192.168.0.100 | 5e:ed:d5:5b:8b:0b | Apple (randomized) | Your Mac |
| 192.168.0.101 | 96:2d:fc:a5:07:ff | Randomized | iPhone #1 |
| 192.168.0.104 | (not in ARP) | — | OPPO A3x |
| 192.168.0.105 | (not in ARP) | — | OPPO Reno8 |
| 192.168.0.117 | (not in ARP) | — | Unknown |

---

### Phase 2: TCP Service Fingerprinting (Netcut's Traffic Analysis)

```bash
# Full port scan on all discovered IPs (Netcut does this passively)
nmap -sT -sV -p- -T4 192.168.0.1 192.168.0.100 192.168.0.101 192.168.0.102 192.168.0.104 192.168.0.105 192.168.0.117
```

**Netcut-Style Device Fingerprints Found:**

| Device | Open Ports | Fingerprint | Netcut Classification |
|--------|------------|-------------|----------------------|
| **Router** | 22, 53, 80, 1900 | TP-Link TD-W8968 HTTP admin | Gateway |
| **Mac** | 5000, 7000, 8082 | AirPlay (5000/7000), Uvicorn | Apple Computer |
| **iPhone #1** | 62078 | `iphone-sync` | Apple Mobile |
| **iPhone #2** | 62078 | `iphone-sync` | Apple Mobile |
| **OPPO A3x** | **46888** | `CPH2641...OPPO` (OAFP) | **OPPO Phone** |
| **OPPO Reno8** | **46888**, 10152 | `CPH2591...OPPO...PrlmC` (OAFP) | **OPPO Phone** |
| **Unknown .117** | 26123, 31819, 44190 (filtered) | High-port firewall | Sleeping/IoT |

---

### Phase 3: Passive Traffic Analysis (Netcut's `_processTraffic()`)

```bash
# Capture traffic to identify devices by behavior (run 30-60 sec)
sudo timeout 30 tcpdump -i en0 -nn -v | grep -E "ARP|DHCP|MDNS|SSDP"
```

**What Netcut Would Capture:**
- ARP requests/replies → MAC-IP mapping
- DHCP requests → hostname, vendor class
- mDNS (port 5353) → service names, hostnames
- SSDP (port 1900) → UPnP device descriptions
- DNS queries → visited domains per device

---

### Phase 4: NetBIOS/Hostname Resolution (Netcut's nbtscan)

```bash
# NetBIOS name scan (Windows/Samba devices)
nmap -sU -p 137 --script=nbstat 192.168.0.0/24

# mDNS hostname resolution
nmap -sU -p 5353 --script=dns-service-discovery 192.168.0.0/24
```

---

## Netcut-Style Automated Scanner for Your Network

Save as `netcut_style_scan.sh`:

```bash
#!/bin/bash
# Netcut-inspired network device discovery
# Run: sudo ./netcut_style_scan.sh

IFACE="en0"
SUBNET="192.168.0.0/24"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="./netcut_scan_$TIMESTAMP"

mkdir -p "$OUTDIR"

echo "=== Netcut-Style Network Discovery ==="
echo "Interface: $IFACE"
echo "Subnet: $SUBNET"
echo "Output: $OUTDIR/"
echo ""

# 1. ARP Scan (Primary discovery)
echo "[1/6] ARP Scan with Vendor Lookup..."
sudo arp-scan --localnet --interface="$IFACE" --ouifile /usr/local/share/arp-scan/ieee-oui.txt > "$OUTDIR/01_arp_scan.txt" 2>&1

# 2. Extract live IPs
LIVE_IPS=$(grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$OUTDIR/01_arp_scan.txt" | awk '{print $1}')
echo "    Found $(echo "$LIVE_IPS" | wc -w) devices via ARP"

# 3. TCP SYN Ping Sweep (Wake sleepers)
echo "[2/6] TCP SYN Ping Sweep (wake sleeping devices)..."
nmap -sn -PS80,443,22,23,21 "$SUBNET" -oN "$OUTDIR/02_tcp_syn.txt" >/dev/null 2>&1

# 4. Full Service Scan on Live Hosts
echo "[3/6] Full Service Scan (this takes 2-5 min)..."
echo "$LIVE_IPS" | xargs nmap -sT -sV -p- -T4 -oN "$OUTDIR/03_full_scan.txt" >/dev/null 2>&1

# 5. NetBIOS/mDNS Hostnames
echo "[4/6] NetBIOS & mDNS Hostname Resolution..."
nmap -sU -p 137,5353 --script=nbstat,dns-service-discovery "$SUBNET" -oN "$OUTDIR/04_hostnames.txt" >/dev/null 2>&1

# 6. MAC Vendor Enrichment
echo "[5/6] MAC Vendor Enrichment..."
> "$OUTDIR/05_vendors.txt"
for ip in $LIVE_IPS; do
    mac=$(grep "^$ip " "$OUTDIR/01_arp_scan.txt" | awk '{print $2}')
    if [ -n "$mac" ]; then
        vendor=$(curl -s "https://api.macvendors.com/$mac" 2>/dev/null || echo "Unknown")
        echo "$ip | $mac | $vendor" >> "$OUTDIR/05_vendors.txt"
    fi
done

# 6. Generate Summary Report
echo "[6/6] Generating Summary Report..."
cat > "$OUTDIR/SUMMARY.md" << EOF
# Netcut-Style Network Discovery Report
**Date**: $(date)
**Interface**: $IFACE
**Subnet**: $SUBNET

## Discovered Devices

| IP | MAC | Vendor | Hostname | Open Ports | Classification |
|----|-----|--------|----------|------------|----------------|
EOF

for ip in $LIVE_IPS; do
    mac=$(grep "^$ip " "$OUTDIR/01_arp_scan.txt" 2>/dev/null | awk '{print $2}')
    vendor=$(grep "^$ip |" "$OUTDIR/05_vendors.txt" 2>/dev/null | cut -d'|' -f3 | xargs)
    ports=$(grep "Nmap scan report for $ip" -A 50 "$OUTDIR/03_full_scan.txt" 2>/dev/null | grep "open" | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
    hostname=$(grep "$ip" "$OUTDIR/04_hostnames.txt" 2>/dev/null | head -1 | awk '{print $NF}')
    [ -z "$hostname" ] && hostname="Unknown"
    
    # Classification logic
    if echo "$ports" | grep -q "62078"; then class="Apple iPhone/iPad";
    elif echo "$ports" | grep -q "46888"; then class="OPPO Android";
    elif echo "$ports" | grep -q "5000,7000"; then class="Apple Mac";
    elif echo "$ports" | grep -q "80,1900"; then class="Router/Gateway";
    else class="Unknown"; fi
    
    echo "| $ip | ${mac:-N/A} | ${vendor:-N/A} | $hostname | ${ports:-None} | $class |" >> "$OUTDIR/SUMMARY.md"
done

echo "" >> "$OUTDIR/SUMMARY.md"
echo "## Files Generated" >> "$OUTDIR/SUMMARY.md"
ls -la "$OUTDIR/" >> "$OUTDIR/SUMMARY.md"

echo ""
echo "=== DISCOVERY COMPLETE ==="
echo "Results in: $OUTDIR/SUMMARY.md"
cat "$OUTDIR/SUMMARY.md"
```

---

## Your Current Network: Netcut-Style Summary

| # | IP | MAC | Vendor | Hostname | Key Ports | Type |
|---|-----|-----|--------|----------|-----------|------|
| 1 | 192.168.0.1 | 28:ee:52:f7:74:dc | TP-Link | TD-W8968 | 22,53,80,1900 | **Router** |
| 2 | 192.168.0.100 | 5e:ed:d5:5b:8b:0b | Apple (rand) | MacBook | 5000,7000,8082 | **Mac** |
| 3 | 192.168.0.101 | 96:2d:fc:a5:07:ff | Randomized | iPhone | 62078 | **iPhone** |
| 4 | 192.168.0.102 | (via ping) | — | iPhone | 62078 | **iPhone** |
| 5 | **192.168.0.104** | (via TCP) | **OPPO** | **A3x** | **46888** | **OPPO Phone** |
| 6 | **192.168.0.105** | (via TCP) | **OPPO** | **Reno8** | **46888,10152** | **OPPO Phone** |
| 7 | 192.168.0.117 | (via TCP) | Unknown | — | 26123,31819,44190 | **Unknown** |

---

## Netcut's Local API Equivalent (What `/list/` Would Show)

If Netcut were running, its `http://127.0.0.1:4625/list/` would return:

```json
[
  {"ip":"192.168.0.1","mac":"28:ee:52:f7:74:dc","name":"TD-W8968","vendor":"TP-Link","type":"gateway"},
  {"ip":"192.168.0.100","mac":"5e:ed:d5:5b:8b:0b","name":"MacBook","vendor":"Apple","type":"computer"},
  {"ip":"192.168.0.101","mac":"96:2d:fc:a5:07:ff","name":"iPhone","vendor":"Apple","type":"mobile"},
  {"ip":"192.168.0.102","mac":"(pending)","name":"iPhone","vendor":"Apple","type":"mobile"},
  {"ip":"192.168.0.104","mac":"(pending)","name":"OPPO A3x","vendor":"OPPO","type":"mobile"},
  {"ip":"192.168.0.105","mac":"(pending)","name":"OPPO Reno8","vendor":"OPPO","type":"mobile"},
  {"ip":"192.168.0.117","mac":"(pending)","name":"Unknown","vendor":"Unknown","type":"unknown"}
]
```

---

## Key Differences: Netcut vs Manual Scanning

| Aspect | Netcut | Manual (What We Did) |
|--------|--------|---------------------|
| **Speed** | Real-time continuous | Point-in-time |
| **ARP Spoofing** | Active MITM for traffic | Passive only |
| **Traffic Analysis** | Per-device bandwidth | Manual tcpdump |
| **Hostname** | DHCP/mDNS/NetBIOS sniffing | Active queries |
| **Persistence** | Daemon + auto-restart | One-off scripts |
| **Remote Access** | Cloud sync (arcai.com) | Local only |
| **Control** | Bandwidth limiting, blocking | Read-only |

---

## To Replicate Netcut Fully on macOS

```bash
# 1. Continuous ARP monitoring (like Netcut's LoopDevs)
while true; do sudo arp-scan --localnet --interface=en0; sleep 10; done

# 2. Passive traffic capture (like _processTraffic)
sudo tcpdump -i en0 -w capture.pcap -s 0

# 3. Local web API (like port 4625)
# Would need: Python Flask + nmap/arp-scan wrappers + WebSocket

# 4. MAC vendor database (like macdata)
# Download: wget https://standards-oui.ieee.org/oui/oui.txt
```

---

## Next Steps for You

1. **Run the Netcut-style script** above for automated future scans
2. **Check router admin** for .117 hostname: `open http://192.168.0.1`
3. **Monitor continuously** to catch .117 when it wakes
4. **Learn packet capture** (`tcpdump`, `Wireshark`) for passive analysis like Netcut

---

*Methodology derived from: Netcut_macOS_Reverse_Engineering_Analysis.md*
*Applied to: Your 192.168.0.0/24 network (7 devices discovered)*