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
    'discovery_interval': 30,      # seconds between discovery scans
    'capture_interval': 30,        # seconds of capture per cycle (longer to catch TLS handshakes)
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
        '192.168.0.1':    {'mac': '28:ee:52:f7:74:dc', 'name': 'TP-Link Router', 'type': 'router'},
        '192.168.0.100':  {'mac': '5e:ed:d5:5b:8b:0b', 'name': 'MacBook (Scanner)', 'type': 'computer'},
        '192.168.0.101':  {'mac': '96:2d:fc:a5:07:ff', 'name': 'iPhone', 'type': 'mobile'},
        '192.168.0.102':  {'mac': 'c2:28:11:41:95:0d', 'name': 'iPhone 2', 'type': 'mobile'},
        '192.168.0.104':  {'mac': 'ba:1a:f1:50:dd:40', 'name': 'OPPO A3x', 'type': 'mobile'},
        '192.168.0.105':  {'mac': '0e:70:b3:1a:68:38', 'name': 'OPPO Reno8', 'type': 'mobile'},
        '192.168.0.117':  {'mac': '7e:8c:7f:7f:2f:ed', 'name': 'Unknown Device', 'type': 'unknown'},
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
        self.device_map = config['known_devices'].copy()
        self.discovered_devices = {}
        self.traffic_stats = defaultdict(lambda: {
            'bytes': 0, 'packets': 0, 'domains': set(),
            'dns_queries': set(), 'connections': set(),
            'first_seen': None, 'last_seen': None
        })
        self.alert_queue = queue.Queue()
        self.running = True
        self.cycle_count = 0

    def get_device_name(self, ip):
        return self.device_map.get(ip, {}).get('name', f'Unknown ({ip})')

    def get_device_type(self, ip):
        return self.device_map.get(ip, {}).get('type', 'unknown')

    def update_device(self, ip, mac=None, name=None, dtype=None):
        if ip not in self.device_map:
            self.device_map[ip] = {}
        if mac: self.device_map[ip]['mac'] = mac
        if name: self.device_map[ip]['name'] = name
        if dtype: self.device_map[ip]['type'] = dtype

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
    """Run full device discovery cycle"""
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
                ip, mac = parts[0], parts[1]
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
                mac = parts[0]
                vendor = ' '.join(parts[1:]).strip('()')
                if current_ip not in discovered:
                    discovered[current_ip] = {'mac': mac, 'vendor': vendor, 'source': 'tcp_syn'}
                # Update device map (create entry if new)
                if current_ip in state.device_map:
                    state.device_map[current_ip]['mac'] = mac
                else:
                    state.device_map[current_ip] = {'mac': mac, 'name': f'Unknown ({current_ip})', 'type': 'unknown'}

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
                ip, mac = parts[0], parts[1]
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

    # 1.5 Service Fingerprinting for new devices
    for ip in discovered:
        if ip not in state.device_map or 'type' not in state.device_map[ip]:
            fingerprint_device(ip, state)

    state.discovered_devices = discovered

    print(f"  Discovered {len(discovered)} devices:")
    for ip, info in sorted(discovered.items()):
        name = state.get_device_name(ip)
        dtype = state.get_device_type(ip)
        mac = info.get('mac', 'unknown')
        print(f"    {ip:15}  {mac:17}  {name} [{dtype}]")

    return discovered

def fingerprint_device(ip, state):
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
    for line in stdout.split('\n'):
        if 'open' in line and '/' in line:
            parts = line.split()
            if len(parts) >= 3:
                port = int(parts[0].split('/')[0])
                service = parts[2]
                # Identify by port
                if port in state.config['port_fingerprints']:
                    device_type = state.config['port_fingerprints'][port]
                    break

    # Update device map
    state.update_device(ip, dtype=device_type)

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
    """Analyze capture and attribute to devices"""
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
                name = state.get_device_name(ip)
                sni_results[name].add(sni)

                # Check for alerts
                for alert_domain in state.config['alert_domains']:
                    if alert_domain in sni:
                        state.alert_queue.put({
                            'type': 'DOMAIN_ALERT',
                            'device': name,
                            'ip': ip,
                            'domain': sni,
                            'matched': alert_domain,
                            'time': timestamp(),
                            'source': 'SNI'
                        })

                # Update traffic stats
                state.traffic_stats[name]['domains'].add(sni)
                state.traffic_stats[name]['last_seen'] = timestamp()

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
                name = state.get_device_name(ip)
                state.traffic_stats[name]['dns_queries'].add(domain)
                state.traffic_stats[name]['last_seen'] = timestamp()

                # Check DNS for alerts (catches domains even with TLS session resumption)
                for alert_domain in state.config['alert_domains']:
                    if alert_domain in domain:
                        state.alert_queue.put({
                            'type': 'DOMAIN_ALERT',
                            'device': name,
                            'ip': ip,
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
                name = state.get_device_name(ip)
                state.traffic_stats[name]['bytes'] += length
                state.traffic_stats[name]['packets'] += 1
                if state.traffic_stats[name]['first_seen'] is None:
                    state.traffic_stats[name]['first_seen'] = timestamp()
                state.traffic_stats[name]['last_seen'] = timestamp()

    # Clean up pcap
    try:
        os.remove(pcap_file)
    except:
        pass

    return sni_results

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

    # Devices table
    print(f"\n  {'DEVICE':<20} {'IP':<15} {'MAC':<17} {'TYPE':<12} {'BYTES':>10} {'PKTS':>6} {'DOMAINS':>6}")
    print(f"  {'-'*90}")

    for ip, info in state.device_map.items():
        name = info.get('name', 'Unknown')
        mac = info.get('mac', 'unknown')
        dtype = info.get('type', 'unknown')
        stats = state.traffic_stats.get(name, {})
        mb = stats.get('bytes', 0) / 1024 / 1024
        pkts = stats.get('packets', 0)
        domains = len(stats.get('domains', set()))
        last = stats.get('last_seen', 'never')

        # Truncate name
        name_short = name[:19]
        print(f"  {name_short:<20} {ip:<15} {mac:<17} {dtype:<12} {mb:>10.2f} {pkts:>6} {domains:>6}  [{last}]")

    # Recent domains per device
    print(f"\n  {'RECENT ACTIVITY (Domains)'}")
    print(f"  {'-'*70}")
    for name, stats in state.traffic_stats.items():
        if stats.get('domains'):
            domains = sorted(stats['domains'])[-5:]  # Last 5
            print(f"  {name[:20]:<20}: {', '.join(domains)}")

    # DNS queries
    print(f"\n  {'RECENT DNS QUERIES'}")
    print(f"  {'-'*70}")
    for name, stats in state.traffic_stats.items():
        if stats.get('dns_queries'):
            dns = sorted(stats['dns_queries'])[-3:]  # Last 3
            print(f"  {name[:20]:<20}: {', '.join(dns)}")

    # Alerts
    print(f"\n  {'ALERTS'}")
    print(f"  {'-'*70}")
    alerts_shown = 0
    while not state.alert_queue.empty() and alerts_shown < 5:
        try:
            alert = state.alert_queue.get_nowait()
            src = alert.get('source', 'SNI')
            print(f"  🚨 [{src}] {alert['time']}  {alert['device']} → {alert['domain']}  (matched: {alert['matched']})")
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
    print(f"\n  Press Ctrl+C to stop\n")

    # Initial discovery
    discover_network(state)

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
    parser.add_argument('-d', '--discovery-interval', type=int, default=30, help='Seconds between discovery scans')
    parser.add_argument('-c', '--capture-interval', type=int, default=15, help='Seconds of capture per cycle')
    parser.add_argument('--alert-domains', help='Comma-separated domains to alert on')
    parser.add_argument('--list-devices', action='store_true', help='List known devices and exit')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This script requires root privileges (sudo)")
        sys.exit(1)

    config = DEFAULT_CONFIG.copy()
    config['interface'] = args.interface
    config['subnet'] = args.subnet
    config['discovery_interval'] = args.discovery_interval
    config['capture_interval'] = args.capture_interval

    if args.alert_domains:
        config['alert_domains'] = [d.strip() for d in args.alert_domains.split(',')]

    if args.list_devices:
        print("Known devices:")
        for ip, info in config['known_devices'].items():
            print(f"  {ip:15}  {info['mac']:17}  {info['name']}  [{info['type']}]")
        sys.exit(0)

    # Check dependencies
    for cmd in ['arp-scan', 'nmap', 'tcpdump', 'tshark']:
        if not shutil.which(cmd):
            print(f"Error: {cmd} not found. Install with: brew install {cmd}")
            sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    main_loop(config)