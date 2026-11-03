# Penetration Testing Learning Path

## Phase 1: Network Reconnaissance & Scanning (Current Focus)

### 1.1 WiFi Network Discovery
- **Tools**: `airport`, `iwlist`, `nmcli`, `wifi-scanner` (macOS/Linux)
- **Concepts**: SSID, BSSID, channels, encryption types (WEP/WPA/WPA2/WPA3)
- **Passive vs Active scanning**

### 1.2 Network Host Discovery
- **ARP scanning**: `arp-scan`, `netdiscover` (local network)
- **ICMP/TCP/UDP ping sweeps**: `nmap -sn`, `fping`
- **Neighbor Discovery Protocol (NDP)** for IPv6

### 1.3 Port Scanning
- **TCP SYN scan** (`nmap -sS`) - stealthy, requires root
- **TCP Connect scan** (`nmap -sT`) - no root needed
- **UDP scan** (`nmap -sU`) - slower, often overlooked
- **Service/version detection** (`nmap -sV`)
- **OS fingerprinting** (`nmap -O`)

### 1.4 WiFi-Specific Attacks (Authorized Lab Only)
- **WPA/WPA2 handshake capture**: `airodump-ng`, `aireplay-ng`
- **WPS attacks**: `reaver`, `bully`
- **PMKID attacks**: `hcxdumptool`
- **Evil Twin / Rogue AP**: `hostapd-wpe`, `wifiphisher`

---

## Phase 2: Enumeration & Service Analysis
- SMB/NetBIOS enumeration
- SNMP enumeration
- LDAP/Active Directory enumeration
- Web application discovery
- DNS enumeration

## Phase 3: Vulnerability Assessment
- Automated scanners: Nessus, OpenVAS, Nuclei
- Manual vulnerability verification
- CVE research and exploit development basics

## Phase 4: Exploitation
- Metasploit Framework
- Custom exploit development
- Client-side attacks
- Privilege escalation (Linux/Windows)

## Phase 5: Post-Exploitation
- Persistence mechanisms
- Lateral movement
- Data exfiltration
- Covering tracks

## Phase 6: Reporting & Remediation
- Professional report writing
- Risk rating (CVSS)
- Remediation guidance

---

## Recommended Lab Environments
1. **Hack The Box** - Real-world machines
2. **TryHackMe** - Guided learning paths
3. **VulnHub** - Downloadable VMs
4. **Proxmox/VMware/VirtualBox** - Your own lab
5. **AWS/Azure/GCP** - Cloud labs (free tiers)

---

## Essential Tools to Master
| Category | Tools |
|----------|-------|
| Network Scanning | nmap, masscan, zmap, arp-scan |
| WiFi | aircrack-ng suite, kismet, wifite, bettercap |
| Web | Burp Suite, OWASP ZAP, nikto, gobuster, ffuf |
| Exploitation | Metasploit, Cobalt Strike (trial), Sliver |
| Post-Exploit | Mimikatz, BloodHound, CrackMapExec, Impacket |
| Wireless | airodump-ng, aircrack-ng, hashcat, hcxtools |

---

## Learning Resources
- **Books**: "The Web Application Hacker's Handbook", "Practical Malware Analysis", "RTFM"
- **Certifications**: OSCP, OSWE, OSEP, PNPT, CRTO
- **Practice**: Start with TryHackMe "Complete Beginner" → "Pre-Security" → "Complete Beginner" paths

---

## Next Steps for You
1. Set up a lab environment (VM with Kali Linux or Parrot OS)
2. Practice on authorized networks only
3. Start with passive reconnaissance
4. Move to active scanning with nmap
5. Document everything

**Remember**: Always get written authorization before testing any network you don't own.