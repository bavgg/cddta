# WiFi & Network Scanning Guide (macOS)

## Your Current Network
- **Interface**: `en0` 
- **IP**: `192.168.0.100/24`
- **Gateway**: Likely `192.168.0.1`

---

## 1. Passive WiFi Reconnaissance (No Association Required)

### List nearby WiFi networks (macOS built-in):
```bash
# Requires location services enabled
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s
```

### With more details (BSSID, channel, security, signal):
```bash
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I
```

### Monitor mode (for packet capture) - requires external USB WiFi adapter:
```bash
# macOS doesn't support monitor mode on built-in WiFi well
# Use a compatible USB adapter (Alfa AWUS036ACH, etc.) with Kali Linux VM
```

---

## 2. Active Network Host Discovery

### Ping sweep (no port scan) - finds live hosts:
```bash
# Using nmap (requires sudo for ARP scan on local network)
sudo nmap -sn 192.168.0.0/24

# Without sudo (TCP SYN to port 80/443 - less reliable)
nmap -sn -PS80,443 192.168.0.0/24
```

### ARP scan (fastest for local network):
```bash
# Install first: brew install arp-scan
sudo arp-scan --localnet --interface=en0
```

### Using fping (fast parallel ping):
```bash
# Install: brew install fping
fping -a -g 192.168.0.0/24 2>/dev/null
```

---

## 3. Port Scanning Discovered Hosts

### Quick scan of top 1000 ports:
```bash
nmap -sS -T4 192.168.0.100  # Replace with target IP
```

### Full port scan (all 65535 ports):
```bash
sudo nmap -sS -p- -T4 192.168.0.100
```

### Service version detection:
```bash
sudo nmap -sS -sV -T4 192.168.0.100
```

### OS fingerprinting:
```bash
sudo nmap -O 192.168.0.100
```

### Aggressive scan (OS + version + scripts + traceroute):
```bash
sudo nmap -A -T4 192.168.0.100
```

---

## 4. Nmap Scripting Engine (NSE) - Powerful Enumeration

### Vulnerability scanning:
```bash
sudo nmap --script vuln 192.168.0.100
```

### SMB enumeration:
```bash
nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery -p 445 192.168.0.100
```

### HTTP enumeration:
```bash
nmap --script http-enum,http-title,http-headers -p 80,443,8080,8443 192.168.0.100
```

### DNS enumeration:
```bash
nmap --script dns-zone-transfer,dns-brute -p 53 192.168.0.1
```

---

## 5. Output Formats for Documentation

```bash
# Normal + XML + Greppable
sudo nmap -sS -sV -oA scan_results 192.168.0.0/24

# Generates: scan_results.nmap, scan_results.xml, scan_results.gnmap
```

---

## 6. WiFi-Specific Tools (Better on Linux/Kali)

### Install aircrack-ng suite (macOS via Homebrew - limited):
```bash
brew install aircrack-ng
# Note: monitor mode requires compatible hardware + Linux
```

### Better approach: Use Kali Linux VM
```bash
# In Kali VM with USB WiFi adapter in monitor mode:
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
# Captures: BSSID, ESSID, channel, encryption, clients, signal
```

---

## 7. Practical Exercise: Scan Your Own Network

### Step 1: Discover hosts
```bash
sudo nmap -sn 192.168.0.0/24 -oG live_hosts.gnmap
```

### Step 2: Extract live IPs
```bash
grep "Up" live_hosts.gnmap | awk '{print $2}' > live_ips.txt
```

### Step 3: Scan each live host
```bash
while read ip; do
  sudo nmap -sS -sV -T4 "$ip" -oA "scan_${ip}"
done < live_ips.txt
```

### Step 4: Analyze results
```bash
# Find open ports across all scans
grep "open" scan_*.nmap

# Find specific services
grep -i "http\|ssh\|smb\|rdp" scan_*.nmap
```

---

## 8. Key Nmap Flags Cheatsheet

| Flag | Purpose |
|------|---------|
| `-sS` | SYN stealth scan (requires root) |
| `-sT` | TCP connect scan (no root) |
| `-sU` | UDP scan |
| `-sV` | Service version detection |
| `-O` | OS detection |
| `-A` | Aggressive (OS + version + scripts + traceroute) |
| `-p-` | All 65535 ports |
| `-p 80,443` | Specific ports |
| `-T4` | Timing template (faster) |
| `-sn` | Ping scan only (no port scan) |
| `-Pn` | Skip host discovery (treat all as online) |
| `--script` | NSE scripts |
| `-oA` | Output all formats |
| `-v` | Verbose |
| `--open` | Only show open ports |

---

## 9. Legal Reminder

> **Only scan networks you own or have explicit written permission to test.**
> 
> - Home network: ✅ You own it
> - Work network: ❌ Need written authorization from IT/security
> - Public WiFi: ❌ Illegal
> - Neighbor's WiFi: ❌ Illegal
> - CTF/Lab environments: ✅ Designed for this

---

## Next Learning Steps

1. **Run the commands above** on your home network
2. **Analyze the output** - identify services, versions, potential vulnerabilities
3. **Learn to interpret nmap output** - what does each open port mean?
4. **Practice with NSE scripts** - they automate vulnerability detection
5. **Set up a Kali VM** for WiFi-specific tools (monitor mode, packet injection)
6. **Try Hack The Box / TryHackMe** for guided practice

---

## Recommended First Commands to Run (copy-paste):

```bash
# 1. See your network details
ifconfig en0

# 2. Quick ping sweep (no sudo needed, less accurate)
nmap -sn -PS80,443 192.168.0.0/24

# 3. Full discovery (requires sudo - run this yourself)
# sudo nmap -sn 192.168.0.0/24

# 4. Scan your own machine first (safe practice)
nmap -sS -sV localhost
```