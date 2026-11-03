#!/bin/bash
# continuous_monitor.sh - Continuous Network Monitor (Discovery + Attribution)
# ============================================================================
# Real-time network monitoring with device discovery and traffic attribution
# Detects when devices visit specific sites (Reddit, Facebook, etc.)
#
# Usage: sudo ./continuous_monitor.sh [interval_seconds]
#        sudo ./continuous_monitor.sh 30
#
# Requirements: arp-scan, nmap, tcpdump, tshark (brew install arp-scan nmap wireshark)
# ============================================================================

set -euo pipefail

# ============================================================
# CONFIGURATION
# ============================================================

IFACE="${1:-en0}"
SUBNET="${2:-192.168.0.0/24}"
DISCOVERY_INTERVAL="${3:-30}"    # seconds between discovery scans
CAPTURE_INTERVAL="${4:-15}"       # seconds of capture per cycle

# Alert domains (comma-separated)
ALERT_DOMAINS="reddit.com,www.reddit.com,facebook.com,www.facebook.com,fbcdn.net,instagram.com,www.instagram.com,youtube.com,www.youtube.com,googlevideo.com,twitter.com,www.twitter.com,x.com,tiktok.com,www.tiktok.com,netflix.com,nflxvideo.net,pornhub.com,www.pornhub.com,xnxx.com,www.xnxx.com,xvideos.com,www.xvideos.com,redtube.com,www.redtube.com,youporn.com,www.youporn.com,xhamster.com,www.xhamster.com,spankbang.com,www.spankbang.com"

# Known devices (IP\tMAC\tName\tType)
# Add your devices here:
KNOWN_DEVICES=$(cat << 'EOF'
192.168.0.1	28:ee:52:f7:74:dc	TP-Link Router	router
192.168.0.100	5e:ed:d5:5b:8b:0b	MacBook (Scanner)	computer
192.168.0.101	96:2d:fc:a5:07:ff	iPhone	mobile
192.168.0.102	c2:28:11:41:95:0d	iPhone 2	mobile
192.168.0.104	ba:1a:f1:50:dd:40	OPPO A3x	mobile
192.168.0.105	0e:70:b3:1a:68:38	OPPO Reno8	mobile
192.168.0.117	7e:8c:7f:7f:2f:ed	Unknown Device	unknown
EOF
)

# Port fingerprints for device identification
declare -A PORT_FINGERPRINTS=(
    [62078]="Apple (iphone-sync)"
    [49152]="Apple (AirPlay)"
    [5000]="Apple (AirPlay)"
    [7000]="Apple (AirPlay)"
    [46888]="OPPO (OAFP)"
    [10152]="OPPO (PrlmC)"
    [5353]="mDNS/Bonjour"
    [137]="NetBIOS (Windows)"
    [138]="NetBIOS (Windows)"
    [139]="NetBIOS (Windows)"
    [22]="SSH"
    [53]="DNS"
    [80]="HTTP"
    [443]="HTTPS"
    [1900]="UPnP"
)

# ============================================================
# GLOBAL STATE
# ============================================================

declare -A DEVICE_MAP       # IP -> "MAC|Name|Type"
declare -A TRAFFIC_BYTES    # Name -> bytes
declare -A TRAFFIC_PACKETS  # Name -> packets
declare -A TRAFFIC_DOMAINS  # Name -> domains (space-separated)
declare -A TRAFFIC_DNS      # Name -> DNS queries (space-separated)
declare -A TRAFFIC_FIRST    # Name -> first_seen
declare -A TRAFFIC_LAST     # Name -> last_seen

CYCLE_COUNT=0
RUNNING=true

# ============================================================
# INITIALIZATION
# ============================================================

init_device_map() {
    echo "$KNOWN_DEVICES" | while IFS=$'\t' read -r ip mac name type; do
        DEVICE_MAP["$ip"]="$mac|$name|$type"
    done
}

get_device_name() {
    local ip="$1"
    if [[ -n "${DEVICE_MAP[$ip]:-}" ]]; then
        echo "${DEVICE_MAP[$ip]}" | cut -d'|' -f2
    else
        echo "Unknown ($ip)"
    fi
}

get_device_type() {
    local ip="$1"
    if [[ -n "${DEVICE_MAP[$ip]:-}" ]]; then
        echo "${DEVICE_MAP[$ip]}" | cut -d'|' -f3
    else
        echo "unknown"
    fi
}

update_device() {
    local ip="$1"
    local mac="${2:-}"
    local name="${3:-}"
    local dtype="${4:-}"

    local current_mac current_name current_type
    if [[ -n "${DEVICE_MAP[$ip]:-}" ]]; then
        current_mac=$(echo "${DEVICE_MAP[$ip]}" | cut -d'|' -f1)
        current_name=$(echo "${DEVICE_MAP[$ip]}" | cut -d'|' -f2)
        current_type=$(echo "${DEVICE_MAP[$ip]}" | cut -d'|' -f3)
    fi

    DEVICE_MAP["$ip"]="${mac:-$current_mac}|${name:-$current_name}|${dtype:-$current_type}"
}

timestamp() {
    date '+%H:%M:%S'
}

print_banner() {
    echo ""
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
}

print_section() {
    echo ""
    echo "--- $1 ---"
}

# ============================================================
# PHASE 1: DEVICE DISCOVERY
# ============================================================

discover_network() {
    print_section "DISCOVERY CYCLE #$CYCLE_COUNT - $(timestamp)"

    local discovered_ips=()

    # 1.1 ARP Scan
    print_section "ARP Scan (Layer 2)"
    sudo arp-scan --localnet --interface="$IFACE" --quiet 2>/dev/null | \
    grep -E "^[0-9]" | while IFS=$'\t' read -r ip mac vendor; do
        if [[ -n "$ip" && -n "$mac" ]]; then
            discovered_ips+=("$ip")
            if [[ -n "${DEVICE_MAP[$ip]:-}" ]]; then
                DEVICE_MAP["$ip"]="$mac|${DEVICE_MAP[$ip]#*|}"
            else
                DEVICE_MAP["$ip"]="$mac|Unknown|unknown"
            fi
        fi
    done

    # 1.2 TCP SYN Ping Sweep (wakes sleepers)
    print_section "TCP SYN Ping Sweep (Layer 4)"
    local current_ip=""
    sudo nmap -sn -PS80,443,22,23,21 "$SUBNET" 2>/dev/null | \
    while IFS= read -r line; do
        if [[ "$line" =~ "Nmap scan report for" ]]; then
            current_ip=$(echo "$line" | awk '{print $NF}' | sed 's/[()]//g')
        elif [[ "$line" =~ "MAC Address:" && -n "$current_ip" ]]; then
            local mac=$(echo "$line" | sed 's/.*MAC Address: //' | awk '{print $1}')
            local vendor=$(echo "$line" | sed 's/.*MAC Address: [^ ]* //' | sed 's/^[()]//' | sed 's/[)]$//')
            if [[ -n "${DEVICE_MAP[$current_ip]:-}" ]]; then
                DEVICE_MAP["$current_ip"]="$mac|${DEVICE_MAP[$current_ip]#*|}"
            else
                DEVICE_MAP["$current_ip"]="$mac|Unknown|unknown"
            fi
            discovered_ips+=("$current_ip")
        fi
    done

    # 1.3 Broadcast Ping
    print_section "Broadcast Ping Wake"
    ping -c 2 -W 1 192.168.0.255 >/dev/null 2>&1
    sleep 1

    # 1.4 ARP Follow-up
    print_section "ARP Follow-up Scan"
    sudo arp-scan --localnet --interface="$IFACE" --quiet 2>/dev/null | \
    grep -E "^[0-9]" | while IFS=$'\t' read -r ip mac vendor; do
        if [[ -n "$ip" && -n "$mac" ]]; then
            if [[ -z "${DEVICE_MAP[$ip]:-}" ]]; then
                DEVICE_MAP["$ip"]="$mac|Unknown|unknown"
                discovered_ips+=("$ip")
            fi
        fi
    done

    # 1.5 Service Fingerprinting for new devices
    print_section "Service Fingerprinting"
    for ip in "${discovered_ips[@]}"; do
        if [[ -z "${DEVICE_MAP[$ip]:-}" ]] || [[ $(echo "${DEVICE_MAP[$ip]}" | cut -d'|' -f3) == "unknown" ]]; then
            fingerprint_device "$ip"
        fi
    done

    # Print discovered devices
    print_section "Discovered Devices (${#DEVICE_MAP[@]} total)"
    for ip in $(printf '%s\n' "${!DEVICE_MAP[@]}" | sort -V); do
        local info="${DEVICE_MAP[$ip]}"
        local mac=$(echo "$info" | cut -d'|' -f1)
        local name=$(echo "$info" | cut -d'|' -f2)
        local dtype=$(echo "$info" | cut -d'|' -f3)
        printf "  %-15s  %-17s  %s [%s]\n" "$ip" "$mac" "$name" "$dtype"
    done
}

fingerprint_device() {
    local ip="$1"
    local key_ports="62078,49152,5000,7000,46888,10152,5353,137,139,22,80,443"

    local stdout
    stdout=$(sudo nmap -sT -sV -p "$key_ports" --host-timeout 10s --max-retries 1 "$ip" 2>/dev/null)

    local device_type="unknown"
    while IFS= read -r line; do
        if [[ "$line" =~ "open" ]] && [[ "$line" =~ "/" ]]; then
            local port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
            if [[ -n "${PORT_FINGERPRINTS[$port]:-}" ]]; then
                device_type="${PORT_FINGERPRINTS[$port]}"
                break
            fi
        fi
    done <<< "$stdout"

    if [[ "$device_type" != "unknown" ]]; then
        local current_info="${DEVICE_MAP[$ip]:-||unknown}"
        local mac=$(echo "$current_info" | cut -d'|' -f1)
        local name=$(echo "$current_info" | cut -d'|' -f2)
        update_device "$ip" "$mac" "$name" "$device_type"
    fi
}

# ============================================================
# PHASE 2: TRAFFIC CAPTURE & ATTRIBUTION
# ============================================================

capture_traffic() {
    local pcap_file="/tmp/monitor_capture_${CYCLE_COUNT}.pcap"

    # Start tcpdump in background
    sudo tcpdump -i "$IFACE" -n -w "$pcap_file" 2>/dev/null &
    local pid=$!

    # Wait for capture interval
    sleep "$CAPTURE_INTERVAL"

    # Stop tcpdump
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null

    echo "$pcap_file"
}

analyze_capture() {
    local pcap_file="$1"
    local alerts=()

    # Extract TLS SNI
    local sni_output
    sni_output=$(tshark -r "$pcap_file" -Y "tls.handshake.extensions_server_name" -T fields -e ip.src -e tls.handshake.extensions_server_name 2>/dev/null)

    if [[ -n "$sni_output" ]]; then
        while IFS=$'\t' read -r ip sni; do
            [[ -z "$ip" || -z "$sni" ]] && continue

            local name=$(get_device_name "$ip")

            # Add to domains
            TRAFFIC_DOMAINS["$name"]="${TRAFFIC_DOMAINS[$name]:-} $sni"

            # Update stats
            TRAFFIC_LAST["$name"]=$(timestamp)
            if [[ -z "${TRAFFIC_FIRST[$name]:-}" ]]; then
                TRAFFIC_FIRST["$name"]=$(timestamp)
            fi

            # Check alerts
            for alert_domain in ${ALERT_DOMAINS//,/ }; do
                if [[ "$sni" == *"$alert_domain"* ]]; then
                    alerts+=("🚨 ALERT [$(timestamp)] Device: $name ($ip) → Domain: $sni (matched: $alert_domain)")
                fi
            done
        done <<< "$sni_output"
    fi

    # Extract DNS
    local dns_output
    dns_output=$(tshark -r "$pcap_file" -Y "dns" -T fields -e ip.src -e dns.qry.name 2>/dev/null)

    if [[ -n "$dns_output" ]]; then
        while IFS=$'\t' read -r ip domain; do
            [[ -z "$ip" || -z "$domain" ]] && continue

            local name=$(get_device_name "$ip")
            TRAFFIC_DNS["$name"]="${TRAFFIC_DNS[$name]:-} $domain"
            TRAFFIC_LAST["$name"]=$(timestamp)
            if [[ -z "${TRAFFIC_FIRST[$name]:-}" ]]; then
                TRAFFIC_FIRST["$name"]=$(timestamp)
            fi
        done <<< "$dns_output"
    fi

    # Bandwidth
    local bw_output
    bw_output=$(tshark -r "$pcap_file" -T fields -e ip.src -e frame.len 2>/dev/null)

    if [[ -n "$bw_output" ]]; then
        while IFS=$'\t' read -r ip length; do
            [[ -z "$ip" || -z "$length" ]] && continue

            local name=$(get_device_name "$ip")
            TRAFFIC_BYTES["$name"]=$((${TRAFFIC_BYTES[$name]:-0} + length))
            TRAFFIC_PACKETS["$name"]=$((${TRAFFIC_PACKETS[$name]:-0} + 1))
            TRAFFIC_LAST["$name"]=$(timestamp)
            if [[ -z "${TRAFFIC_FIRST[$name]:-}" ]]; then
                TRAFFIC_FIRST["$name"]=$(timestamp)
            fi
        done <<< "$bw_output"
    fi

    # Clean up
    rm -f "$pcap_file"

    # Print alerts
    for alert in "${alerts[@]}"; do
        echo "$alert"
    done
}

# ============================================================
# DASHBOARD
# ============================================================

print_dashboard() {
    clear

    echo ""
    echo "========================================================================"
    echo "  CONTINUOUS NETWORK MONITOR  |  Cycle: $CYCLE_COUNT  |  $(timestamp)"
    echo "  Interface: $IFACE  |  Subnet: $SUBNET"
    echo "========================================================================"

    # Devices table
    echo ""
    printf "  %-20s %-15s %-17s %-12s %10s %6s %6s\n" "DEVICE" "IP" "MAC" "TYPE" "MB" "PKTS" "DOM"
    printf "  %s\n" "----------------------------------------------------------------------------------------------------"

    for ip in $(printf '%s\n' "${!DEVICE_MAP[@]}" | sort -V); do
        local info="${DEVICE_MAP[$ip]}"
        local mac=$(echo "$info" | cut -d'|' -f1)
        local name=$(echo "$info" | cut -d'|' -f2)
        local dtype=$(echo "$info" | cut -d'|' -f3)

        local bytes=${TRAFFIC_BYTES[$name]:-0}
        local mb=$(echo "scale=2; $bytes/1024/1024" | bc 2>/dev/null || echo "0.00")
        local pkts=${TRAFFIC_PACKETS[$name]:-0}
        local domains=$(echo "${TRAFFIC_DOMAINS[$name]:-}" | wc -w)
        local last=${TRAFFIC_LAST[$name]:-never}

        printf "  %-20s %-15s %-17s %-12s %10s %6s %6s  [%s]\n" \
            "${name:0:19}" "$ip" "$mac" "$dtype" "$mb" "$pkts" "$domains" "$last"
    done

    # Recent activity
    echo ""
    echo "  RECENT DOMAINS:"
    for name in "${!TRAFFIC_DOMAINS[@]}"; do
        local domains="${TRAFFIC_DOMAINS[$name]}"
        if [[ -n "$domains" ]]; then
            local recent=$(echo "$domains" | tr ' ' '\n' | tail -5 | tr '\n' ',' | sed 's/,$//')
            printf "  %-20s: %s\n" "$name" "$recent"
        fi
    done

    # DNS
    echo ""
    echo "  RECENT DNS:"
    for name in "${!TRAFFIC_DNS[@]}"; do
        local dns="${TRAFFIC_DNS[$name]}"
        if [[ -n "$dns" ]]; then
            local recent=$(echo "$dns" | tr ' ' '\n' | tail -3 | tr '\n' ',' | sed 's/,$//')
            printf "  %-20s: %s\n" "$name" "$recent"
        fi
    done

    echo ""
    echo "  Press Ctrl+C to stop | Next discovery in ~${DISCOVERY_INTERVAL}s"
}

print_final_summary() {
    print_banner "FINAL SUMMARY"
    echo "  Total cycles: $CYCLE_COUNT"
    echo "  Devices monitored: ${#DEVICE_MAP[@]}"
    echo ""
    echo "  Traffic Summary (sorted by bandwidth):"

    # Sort by bytes (using a temp file)
    local temp_file=$(mktemp)
    for name in "${!TRAFFIC_BYTES[@]}"; do
        local bytes=${TRAFFIC_BYTES[$name]:-0}
        local pkts=${TRAFFIC_PACKETS[$name]:-0}
        local domains=$(echo "${TRAFFIC_DOMAINS[$name]:-}" | wc -w)
        local dns=$(echo "${TRAFFIC_DNS[$name]:-}" | wc -w)
        local mb=$(echo "scale=2; $bytes/1024/1024" | bc 2>/dev/null || echo "0.00")
        echo "$bytes|$name|$mb|$pkts|$domains|$dns" >> "$temp_file"
    done

    sort -rn "$temp_file" | while IFS='|' read -r bytes name mb pkts domains dns; do
        if (( $(echo "$mb > 0.01" | bc -l 2>/dev/null || echo 0) )) || (( pkts > 0 )); then
            printf "    %-20s: %8s MB  %6s pkts  %3s domains  %3s DNS\n" "$name" "$mb" "$pkts" "$domains" "$dns"
        fi
    done
    rm -f "$temp_file"
}

# ============================================================
# MAIN LOOP
# ============================================================

cleanup() {
    print_final_summary
    exit 0
}

trap cleanup SIGINT SIGTERM

main() {
    # Check root
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script requires root privileges (sudo)"
        exit 1
    fi

    # Check dependencies
    for cmd in arp-scan nmap tcpdump tshark bc; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "Error: $cmd not found. Install with: brew install $cmd"
            exit 1
        fi
    done

    # Initialize
    init_device_map

    print_banner "CONTINUOUS NETWORK MONITOR STARTED"
    echo "  Interface: $IFACE"
    echo "  Subnet: $SUBNET"
    echo "  Discovery interval: ${DISCOVERY_INTERVAL}s"
    echo "  Capture interval: ${CAPTURE_INTERVAL}s"
    echo "  Alert domains: $(echo $ALERT_DOMAINS | tr ',' '\n' | wc -l) configured"
    echo "  Known devices: ${#DEVICE_MAP[@]}"
    echo ""
    echo "  Press Ctrl+C to stop"
    echo ""

    # Initial discovery
    discover_network

    # Main loop
    while true; do
        CYCLE_COUNT=$((CYCLE_COUNT + 1))

        # Discovery every N cycles
        local discovery_every=$((DISCOVERY_INTERVAL / CAPTURE_INTERVAL))
        if [[ $discovery_every -lt 1 ]]; then discovery_every=1; fi

        if [[ $CYCLE_COUNT -eq 1 ]] || [[ $((CYCLE_COUNT % discovery_every)) -eq 0 ]]; then
            discover_network
        fi

        # Capture & Attribution
        print_section "CAPTURE CYCLE #$CYCLE_COUNT - $(timestamp)"
        echo "  Capturing for ${CAPTURE_INTERVAL}s..."

        local pcap_file=$(capture_traffic)
        echo "  Analyzing..."

        analyze_capture "$pcap_file"

        # Dashboard
        print_dashboard

        # Brief pause
        sleep 2
    done
}

# Run
main "$@"