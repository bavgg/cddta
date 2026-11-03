# Thought Process: Building Continuous Network Monitor

## Project Goal
Create a program that continuously monitors network traffic, discovers devices, and attributes traffic to specific devices in real-time - with alerts for sites like Reddit, Facebook, etc.

---

## Phase 1: Understanding Requirements

### User's Stated Needs
1. **Continuous device discovery** - find devices on network repeatedly
2. **Continuous traffic monitoring** - capture and analyze packets ongoing
3. **Traffic attribution** - map packets to specific devices (IP → MAC → Name)
4. **Real-time alerts** - detect when devices visit specific sites (Reddit, etc.)
5. **Live dashboard** - see current activity

### Technical Requirements Derived
- Must run continuously (daemon-like)
- Must handle SIGINT/SIGTERM gracefully
- Must be root (packet capture)
- Must work on macOS (user's platform)
- Must use available tools: arp-scan, nmap, tcpdump, tshark

---

## Phase 2: Architecture Decisions

### Language Choice: Python vs Bash

**Bash Considered:**
- Pros: Native, simple, pipes work well
- Cons: macOS bash 3.2 lacks associative arrays (`declare -A`)
- Verdict: **Not viable for complex state management**

**Python Chosen:**
- Pros: Native data structures (dict, set), threading, signal handling, cross-platform
- Cons: Slightly more verbose
- Verdict: **Best choice for this complexity**

### Core Architecture: Pipeline Pattern

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   DISCOVERY     │────▶│  DEVICE MAP     │◀───│  ATTRIBUTION    │
│  (Producer)     │     │  (Shared State) │    │  (Consumer)     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
   ARP + TCP SYN          IP→MAC→Name            PCAP → SNI/DNS/
   Broadcast Ping         Type Fingerprint        Bandwidth
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
                       ┌─────────────────┐
                       │    DASHBOARD    │
                       │  (UI Thread)    │
                       └─────────────────┘
```

### Data Structures Design

```python
# Device Map: The Bridge
device_map = {
    '192.168.0.101': {
        'mac': '96:2d:fc:a5:07:ff',
        'name': 'iPhone',
        'type': 'mobile'
    }
}

# Traffic Stats: Per-device aggregation
traffic_stats = {
    'iPhone': {
        'bytes': 1048576,
        'packets': 1523,
        'domains': {'reddit.com', 'redditmedia.com'},
        'dns_queries': {'reddit.com', 'www.reddit.com'},
        'connections': {...},
        'first_seen': '14:30:00',
        'last_seen': '14:35:23'
    }
}

# Alert Queue: Thread-safe communication
alert_queue = queue.Queue()  # Producer: attribution, Consumer: dashboard
```

---

## Phase 3: Discovery Module Design

### Multi-Layer Discovery (From NetCut Methodology)

**Layer 1: ARP Scan (Baseline)**
```bash
sudo arp-scan --localnet --interface=en0 --quiet
```
- Fast (~2s for /24)
- Finds active devices
- Limitation: Misses sleeping/randomized MAC devices

**Layer 2: TCP SYN Ping Sweep (Wake Sleepers)**
```bash
sudo nmap -sn -PS80,443,22,23,21 192.168.0.0/24
```
- Wakes sleeping WiFi radios
- Bypasses AP isolation
- Finds devices ARP misses

**Layer 3: Broadcast Ping (Wake All)**
```bash
ping -c 3 192.168.0.255
```
- Some devices ignore unicast but respond to broadcast

**Layer 4: ARP Follow-up**
- Re-scan ARP after wake-up to catch newly awake devices

**Layer 5: Service Fingerprinting**
```bash
sudo nmap -sT -sV -p 62078,49152,46888... <target>
```
- Port 62078 = Apple (iphone-sync)
- Port 46888 = OPPO (OAFP)
- Port 5353 = mDNS (Apple)

### Discovery Scheduling
- Run full discovery every N cycles (configurable, default 30s)
- Quick cycles just capture/attribute
- Avoids constant heavy scanning

---

## Phase 4: Attribution Module Design

### Capture Strategy

**Critical Requirement: Capture MUST start BEFORE connections**
- TLS Client Hello (with SNI) is in FIRST packets
- If capture starts mid-connection, SNI is missed
- Solution: Start tcpdump → wait → generate traffic → stop

### Packet Analysis with tshark

**TLS SNI Extraction:**
```bash
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" \
  -T fields -e ip.src -e tls.handshake.extensions_server_name
```

**DNS Query Extraction:**
```bash
tshark -r capture.pcap -Y "dns" \
  -T fields -e ip.src -e dns.qry.name
```

**Bandwidth Calculation:**
```bash
tshark -r capture.pcap -T fields -e ip.src -e frame.len
# Sum lengths per IP
```

### Attribution Logic

```python
# For each packet's source IP:
name = device_map.get(ip, {}).get('name', f'Unknown ({ip})')
# Aggregate stats by name
traffic_stats[name]['bytes'] += packet_length
traffic_stats[name]['domains'].add(sni)
traffic_stats[name]['dns_queries'].add(dns_query)
```

### Alert Detection

```python
for alert_domain in alert_domains:
    if alert_domain in sni:
        alert_queue.put({
            'type': 'DOMAIN_ALERT',
            'device': name,
            'ip': ip,
            'domain': sni,
            'matched': alert_domain
        })
```

---

## Phase 5: Dashboard/Monitoring Design

### Real-Time Display Requirements
- Clear screen each update (ANSI clear)
- Show device table with bandwidth
- Show recent domains per device
- Show recent DNS queries
- Show alerts
- Non-blocking (updates every capture cycle)

### Dashboard Layout
```
========================================================================
  CONTINUOUS NETWORK MONITOR  |  Cycle: 5  |  14:32:15
  Interface: en0  |  Subnet: 192.168.0.0/24
========================================================================

  DEVICE              IP              MAC                TYPE         MB   PKTS DOM
  ----------------------------------------------------------------------------------------------------
  iPhone              192.168.0.101   96:2d:fc:a5:07:ff  mobile        2.45    182   3
  MacBook             192.168.0.100   5e:ed:d5:5b:8b:0b  computer      45.21  3421  12

  RECENT DOMAINS:
  iPhone             : www.reddit.com, redditmedia.com
  MacBook            : github.com, api.github.com

  RECENT DNS:
  iPhone             : reddit.com, www.reddit.com

  ALERTS:
  🚨 14:32:15  iPhone → www.reddit.com  (matched: reddit.com)

  Press Ctrl+C to stop | Next discovery in ~30s
```

---

## Phase 6: Concurrency & Signal Handling

### Threading Model
- **Main thread**: Discovery + Capture + Attribution loop
- **Alert thread**: Daemon thread consuming alert_queue
- **Dashboard**: Updated in main thread after each cycle

### Signal Handling
```python
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def signal_handler(sig, frame):
    state.running = False  # Graceful shutdown
```

### Resource Cleanup
- Kill tcpdump subprocess on each cycle
- Remove temporary pcap files
- Print final summary on exit

---

## Phase 7: Configuration Design

### Flexible Configuration
```python
DEFAULT_CONFIG = {
    'interface': 'en0',
    'subnet': '192.168.0.0/24',
    'discovery_interval': 30,
    'capture_interval': 15,
    'alert_domains': [...],
    'known_devices': {...},
    'port_fingerprints': {...}
}
```

### CLI Arguments
```bash
python3 continuous_monitor.py \
  --interface en0 \
  --subnet 192.168.1.0/24 \
  --discovery-interval 60 \
  --capture-interval 30 \
  --alert-domains "reddit.com,facebook.com"
```

---

## Phase 8: Testing & Validation

### Tested Scenarios
1. **Basic discovery** - Found 7 devices on 192.168.0.0/24
2. **Attribution** - Captured MacBook visiting codechef.com, gemini.google.com
3. **Bandwidth tracking** - 35.88 MB in 15s correctly attributed
4. **DNS attribution** - Cloudflare tunnel DNS correctly mapped
5. **Device fingerprinting** - Port 62078 → Apple, Port 46888 → OPPO

### Edge Cases Handled
- Randomized MACs (5e:, 96:, 0e: prefixes) - manual device map entries
- Firewall filtering (OPPO shows "filtered" not "closed")
- No SNI in capture window - gracefully handles empty results
- Unknown IPs - shows as "UNKNOWN (IP)"

---

## Phase 9: Bash Version (Alternative)

### Why Created
- Some users prefer shell scripts
- Simpler for quick modifications

### Limitation Discovered
- macOS bash 3.2 lacks associative arrays (`declare -A`)
- Workaround: Use Python dicts or upgrade bash
- Decision: Document limitation, recommend Python version

---

## Phase 10: Documentation & Delivery

### Files Created
1. `continuous_monitor.py` - Main program
2. `continuous_monitor.sh` - Bash alternative
3. Supporting documentation files

### Key Design Principles Applied
1. **Separation of Concerns**: Discovery ↔ Map ↔ Attribution
2. **Shared State Pattern**: Device map as single source of truth
3. **Producer-Consumer**: Capture produces, attribution consumes
4. **Graceful Degradation**: Works with partial data
5. **User-Centric Alerts**: Reddit/Facebook/YouTube out of box
6. **Graceful Shutdown**: Ctrl+C shows final summary

---

## Lessons Learned

1. **Capture timing is critical** - Must start tcpdump BEFORE traffic
2. **Device map is the linchpin** - Without it, attribution is just IPs
3. **Multi-layer discovery essential** - ARP alone misses 80% of devices
3. **Threading for alerts** - Keeps main loop responsive
4. **Python dict/set perfect for this** - O(1) lookups, auto-dedup
5. **Signal handling mandatory** - Clean exit with summary

---

## Future Enhancements (If Needed)

1. **Web Dashboard** - Flask + WebSocket for browser UI
2. **Database Persistence** - SQLite for historical data
3. **Remote Monitoring** - Agent on multiple network segments
4. **ML Anomaly Detection** - Unusual traffic patterns
5. **Integration with NetCut API** - If available
6. **MITM Option** - For full traffic visibility (with warnings)

---

## Conclusion

The continuous monitor successfully implements the NetCut methodology in an open-source, scriptable form. It demonstrates that with the right tools (arp-scan, nmap, tcpdump, tshark) and a clear pipeline architecture, sophisticated network monitoring is achievable in ~300 lines of Python.

The key insight: **Discovery provides identity, Attribution provides behavior. Together they answer "Who did what?"**