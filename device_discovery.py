#!/usr/bin/env python3
"""
Standalone Continuous Device Discovery - Fully Dynamic
=======================================================
Discovers and tracks devices on the network WITHOUT any pre-configured known devices.
Uses dynamic identity resolution to track devices across DHCP lease changes and MAC randomization.

Usage:
    sudo python3 device_discovery.py
    sudo python3 device_discovery.py --interval 10 --subnet 192.168.1.0/24
    sudo python3 device_discovery.py -i en0 -s 10.0.0.0/8 --quick-discovery 5
"""

import argparse
import subprocess
import threading
import time
import signal
import sys
import os
import re
import ipaddress
from datetime import datetime
from collections import defaultdict

# ============================================================
# CONFIGURATION (no hardcoded devices)
# ============================================================

DEFAULT_CONFIG = {
    'interface': 'en0',
    'subnet': '192.168.0.0/24',
    'discovery_interval': 30,       # seconds between full discovery scans
    'quick_discovery_interval': 10, # seconds between quick ARP scans
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
# DISCOVERY STATE - Fully Dynamic
# ============================================================

class DiscoveryState:
    def __init__(self, config):
        self.config = config
        # device_map: MAC -> {name, type, ip, vendor, ports, hostname, identity_id}
        self.device_map = {}  # Start EMPTY - no pre-known devices
        # ip_to_mac: IP -> MAC (for quick reverse lookup)
        self.ip_to_mac = {}
        self.discovered_devices = {}  # IP -> {mac, vendor, source}

        # === DYNAMIC IDENTITY RESOLUTION ===
        # identity_id -> {macs: set(), ips: set(), name, type, confidence, signals: {...}}
        self.device_identities = {}
        # MAC -> identity_id
        self.mac_to_identity = {}
        # identity counter
        self.next_identity_id = 1

        self.running = True
        self.cycle_count = 0
        self.new_devices = set()

        # Subnet info for display
        self.network = ipaddress.ip_network(config['subnet'], strict=False)

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
            # Merge signals
            new_signals = self._compute_identity_signals(mac, info)
            identity['signals'] = new_signals
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
            # Generate dynamic name from vendor/IP if no name provided
            if not name and vendor:
                name = f'{vendor} ({ip})'
            elif not name:
                name = f'Device-{ip}'
            self.device_map[mac] = {'name': name, 'type': 'unknown', 'ip': ip}
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

def get_broadcast_ip(subnet):
    """Calculate broadcast IP from subnet"""
    network = ipaddress.ip_network(subnet, strict=False)
    return str(network.broadcast_address)

def clean_vendor_name(vendor):
    """Clean up vendor name from arp-scan/nmap output"""
    if not vendor:
        return 'Unknown'

    # Remove "(DUP: X)" suffix
    vendor = re.sub(r'\s*\(DUP:\s*\d+\)', '', vendor)

    # Remove "(Unknown: locally administered)"
    vendor = re.sub(r'\(Unknown: locally administered\)', '', vendor)

    # Remove common suffixes
    vendor = re.sub(r'\s*\(.*?\)\s*$', '', vendor)  # Remove trailing (xxx)
    vendor = vendor.replace('CO.,LTD.', '').replace('CO., LTD.', '').replace('CO. LTD.', '')
    vendor = vendor.replace('CORPORATION', '').replace('CORP.', '')
    vendor = vendor.replace('TECHNOLOGIES', '').replace('TECHNOLOGY', '')
    vendor = vendor.replace('INC.', '').replace('INC', '')
    vendor = vendor.replace('LTD.', '').replace('LTD', '')

    # Clean up extra whitespace
    vendor = ' '.join(vendor.split())

    # Capitalize properly
    if vendor.isupper():
        vendor = vendor.title()

    return vendor.strip() or 'Unknown'

# ============================================================
# PHASE 1: DEVICE DISCOVERY
# ============================================================

def discover_network(state):
    """Run full device discovery cycle - updates MAC→IP mappings dynamically"""
    print_section(f"DISCOVERY CYCLE #{state.cycle_count} - {timestamp()}")

    discovered = {}

    # 1.1 ARP Scan (without --quiet to get vendor info)
    stdout, _, _ = run_cmd([
        'sudo', 'arp-scan', '--localnet',
        '--interface', state.config['interface']
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
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    continue
                # Validate MAC format
                if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                    continue
                # Filter by subnet
                if not is_ip_in_subnet(ip, state.config['subnet']):
                    continue
                raw_vendor = ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
                vendor = clean_vendor_name(raw_vendor)
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
                raw_vendor = ' '.join(parts[1:]).strip('()')
                vendor = clean_vendor_name(raw_vendor)
                if current_ip not in discovered:
                    discovered[current_ip] = {'mac': mac, 'vendor': vendor, 'source': 'tcp_syn'}
                # Update device map with current IP for this MAC
                state.update_device(current_ip, mac=mac, vendor=vendor)

    # 1.3 Broadcast Ping (to populate ARP cache)
    broadcast_ip = get_broadcast_ip(state.config['subnet'])
    run_cmd(['ping', '-c', '2', '-W', '1', broadcast_ip], timeout=5)
    time.sleep(1)

    # 1.4 ARP Follow-up
    stdout, _, _ = run_cmd([
        'sudo', 'arp-scan', '--localnet',
        '--interface', state.config['interface']
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
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    continue
                # Validate MAC format
                if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                    continue
                # Filter by subnet
                if not is_ip_in_subnet(ip, state.config['subnet']):
                    continue
                if ip not in discovered:
                    discovered[ip] = {'mac': mac, 'source': 'arp_followup'}
                # Update device map with current IP for this MAC
                state.update_device(ip, mac=mac)

    # 1.5 Service Fingerprinting for new/unknown devices
    for ip, info in discovered.items():
        mac = info['mac']
        if mac in state.device_map and state.device_map[mac].get('type') == 'unknown':
            fingerprint_device(ip, state, mac)

    state.discovered_devices = discovered

    print(f"  Discovered {len(discovered)} devices in {state.config['subnet']}:")
    for ip, info in sorted(discovered.items()):
        mac = info.get('mac', 'unknown')
        name = state.get_identity_name(mac)
        dtype = state.get_identity_type(mac)
        vendor = info.get('vendor', '')
        vendor_str = f" [{vendor}]" if vendor else ""
        print(f"    {ip:15}  {mac:17}  {name} [{dtype}]{vendor_str}")

    return discovered

def is_ip_in_subnet(ip, subnet):
    """Check if IP is in the given subnet"""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except:
        return False

def fingerprint_device(ip, state, mac):
    """Quick port scan to identify device type"""
    # Key ports for identification
    key_ports = [62078, 49152, 5000, 7000, 46888, 10152, 5353, 137, 139, 22, 80, 443]
    port_str = ','.join(map(str, key_ports))

    # Use SYN scan (-sS) which is faster than TCP connect (-sT), requires root (we have it)
    # Don't use sudo since we're already running as root
    stdout, stderr, rc = run_cmd([
        'nmap', '-sS', '--version-light', '-p', port_str,
        '--host-timeout', '8s', '--max-retries', '1',
        ip
    ], timeout=15)

    device_type = 'unknown'
    open_ports = []
    if rc == 0 and stdout:
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
    elif rc != 0:
        pass  # nmap failed, will use vendor fallback

    # Fallback: infer type from vendor if no ports found
    if device_type == 'unknown':
        vendor = state.device_map.get(mac, {}).get('vendor', '')
        if vendor:
            vendor_lower = vendor.lower()
            if 'apple' in vendor_lower:
                device_type = 'mobile (Apple)'
            elif 'samsung' in vendor_lower:
                device_type = 'mobile (Samsung)'
            elif 'oppo' in vendor_lower:
                device_type = 'mobile (OPPO)'
            elif 'xiaomi' in vendor_lower:
                device_type = 'mobile (Xiaomi)'
            elif 'huawei' in vendor_lower:
                device_type = 'mobile (Huawei)'
            elif 'router' in vendor_lower or 'tp-link' in vendor_lower or 'netgear' in vendor_lower or 'asus' in vendor_lower:
                device_type = 'router'
            elif 'intel' in vendor_lower or 'dell' in vendor_lower or 'hp' in vendor_lower or 'lenovo' in vendor_lower:
                device_type = 'computer'
            elif 'raspberry' in vendor_lower:
                device_type = 'IoT (Raspberry Pi)'
            elif 'locally administered' in vendor_lower or vendor_lower == 'unknown':
                # Locally administered MAC - could be randomized, check OUI
                pass

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
# DASHBOARD
# ============================================================

def print_dashboard(state):
    """Print live dashboard"""
    os.system('clear' if os.name == 'posix' else 'cls')

    print(f"\n{'='*70}")
    print(f"  CONTINUOUS DEVICE DISCOVERY  |  Cycle: {state.cycle_count}  |  {timestamp()}")
    print(f"  Interface: {state.config['interface']}  |  Subnet: {state.config['subnet']}")
    print(f"{'='*70}")

    # Devices table (Identity-based)
    print(f"\n  {'IDENTITY':<22} {'IP':<15} {'MAC':<17} {'TYPE':<14} {'VENDOR'}")
    print(f"  {'-'*95}")

    for mac, info in state.device_map.items():
        name = state.get_identity_name(mac)
        ip = info.get('ip', 'unknown')
        dtype = state.get_identity_type(mac)
        vendor = info.get('vendor', 'Unknown')

        # Truncate name
        name_short = name[:21]
        vendor_short = vendor[:30]
        print(f"  {name_short:<22} {ip:<15} {mac:<17} {dtype:<14} {vendor_short}")

    # Show merged identities
    if state.device_identities:
        merged_identities = []
        for identity_id, identity in state.device_identities.items():
            if len(identity['macs']) > 1 or len(identity['ips']) > 1:
                merged_identities.append((identity_id, identity))

        if merged_identities:
            print(f"\n  {'MERGED IDENTITIES (tracked across MAC/IP changes)'}")
            print(f"  {'-'*95}")
            for identity_id, identity in merged_identities:
                macs = ', '.join(sorted(identity['macs']))
                ips = ', '.join(sorted(identity['ips']))
                print(f"  {identity['name'][:20]:<20} [{identity['type']}] MACs: {macs} | IPs: {ips}")

    print(f"\n  Press Ctrl+C to stop | Next full discovery in ~{state.config['discovery_interval']}s")


# ============================================================
# MAIN LOOP
# ============================================================

def signal_handler(sig, frame):
    print("\n\nShutting down...")
    state.running = False

def main_loop(config):
    global state
    state = DiscoveryState(config)

    print_banner("CONTINUOUS DEVICE DISCOVERY STARTED (Fully Dynamic)")
    print(f"  Interface: {config['interface']}")
    print(f"  Subnet: {config['subnet']} ({state.network.num_addresses} addresses)")
    print(f"  Full discovery interval: {config['discovery_interval']}s")
    print(f"  Quick ARP scan interval: {config['quick_discovery_interval']}s")
    print(f"  No pre-configured devices - discovering dynamically")

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
                '--interface', state.config['interface']
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
                        # Filter by subnet
                        if not is_ip_in_subnet(ip, state.config['subnet']):
                            continue
                        raw_vendor = ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
                        vendor = clean_vendor_name(raw_vendor)
                        # Check if new device
                        is_new = state.update_device(ip, mac=mac, vendor=vendor)
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

            # Full discovery every N seconds
            if state.cycle_count % max(1, config['discovery_interval'] // config['quick_discovery_interval']) == 0:
                discover_network(state)

            # Print dashboard
            print_dashboard(state)

            # Wait for next cycle
            if state.running:
                time.sleep(quick_interval)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    finally:
        state.running = False
        print_final_summary(state)

def print_final_summary(state):
    print_banner("FINAL SUMMARY")
    print(f"  Total discovery cycles: {state.cycle_count}")
    print(f"  Devices discovered: {len(state.device_map)}")
    print(f"\n  Device List:")
    for mac, info in sorted(state.device_map.items(), key=lambda x: x[1].get('name', '')):
        name = info.get('name', 'Unknown')
        ip = info.get('ip', 'unknown')
        dtype = info.get('type', 'unknown')
        vendor = info.get('vendor', 'Unknown')
        ports = info.get('ports', [])
        identity_id = info.get('identity_id', 'none')
        port_str = f" (ports: {ports})" if ports else ""
        print(f"    {name:<22} {ip:15} {mac:17} [{dtype}] {vendor}{port_str} [id: {identity_id}]")

    if state.device_identities:
        print(f"\n  Identities ({len(state.device_identities)}):")
        for identity_id, identity in state.device_identities.items():
            macs = ', '.join(sorted(identity['macs']))
            ips = ', '.join(sorted(identity['ips']))
            merged = " 🔗 MERGED" if len(identity['macs']) > 1 or len(identity['ips']) > 1 else ""
            print(f"    {identity['name'][:22]:<22} [{identity['type']}] MACs: {macs} | IPs: {ips}{merged}")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Continuous Network Device Discovery (Fully Dynamic)')
    parser.add_argument('-i', '--interface', default='en0', help='Network interface (default: en0)')
    parser.add_argument('-s', '--subnet', default='192.168.0.0/24', help='Subnet to scan (default: 192.168.0.0/24)')
    parser.add_argument('-d', '--discovery-interval', type=int, default=30, help='Seconds between full discovery scans')
    parser.add_argument('-q', '--quick-discovery', type=int, default=10, help='Seconds between quick ARP scans')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This script requires root privileges (sudo)")
        sys.exit(1)

    config = DEFAULT_CONFIG.copy()
    config['interface'] = args.interface
    config['subnet'] = args.subnet
    config['discovery_interval'] = args.discovery_interval
    config['quick_discovery_interval'] = args.quick_discovery

    # Check dependencies
    required_cmds = ['arp-scan', 'nmap']
    for cmd in required_cmds:
        if subprocess.run(['which', cmd], capture_output=True).returncode != 0:
            print(f"Error: '{cmd}' not found. Install with: brew install {cmd}")
            sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    main_loop(config)