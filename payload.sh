#!/bin/sh
# SharkJack payload by Hackazillarex : Proof-of-entry scan with OS, ports, and services
# Public IP + first 5 live hosts, top 10 ports
# LED blinks while scanning, solid green when done

LOOT_DIR=/root/loot
LOG_FILE="$LOOT_DIR/proof_of_entry_log.txt"
LATEST_FILE="$LOOT_DIR/latest_scan.txt"
POST_DHCP_WAIT=20

mkdir -p "$LOOT_DIR"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE" > /dev/null; }
log_latest() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" > "$LATEST_FILE"; }

# ---- LED CONTROL ----
led_setup() { LED SETUP; }
led_blink_start() { (while true; do LED ATTACK; sleep 0.5; LED OFF; sleep 0.5; done) & BLINK_PID=$!; }
led_blink_stop() { [ ! -z "$BLINK_PID" ] && kill "$BLINK_PID" 2>/dev/null || true; unset BLINK_PID; }
led_done() { LED FINISH; }
led_off() { LED OFF; }

require_nmap_or_exit() {
    command -v nmap >/dev/null 2>&1 || { log "ERROR: nmap not installed"; return 1; }
    return 0
}

setup_network() {
    led_setup
    NETMODE DHCP_CLIENT
    COUNT=0
    while [ $COUNT -lt 60 ]; do
        ip addr show eth0 2>/dev/null | grep -q "inet " && break
        COUNT=$((COUNT+1))
        sleep 1
    done
    sleep $POST_DHCP_WAIT
    grep -q "nameserver" /etc/resolv.conf || echo "nameserver 8.8.8.8" > /etc/resolv.conf
}

fetch_public_ip() {
    PUBLIC_IP=""
    SERVICES="https://api.ipify.org?format=text https://ifconfig.me https://ident.me https://checkip.amazonaws.com http://ipecho.net/plain"
    for svc in $SERVICES; do
        [ -n "$PUBLIC_IP" ] && break
        [ -x "$(command -v wget)" ] && PUBLIC_IP=$(wget -qO- --timeout=6 "$svc" 2>/dev/null)
        [ -n "$PUBLIC_IP" ] && break
        [ -x "$(command -v curl)" ] && PUBLIC_IP=$(curl -s --max-time 6 "$svc")
    done
    PUBLIC_IP=${PUBLIC_IP:-unknown}
    log "Public IP: $PUBLIC_IP"
    echo "$PUBLIC_IP" > "$LOOT_DIR/public_ip.txt"
}

get_first_5_live_hosts() {
    IPADDR=$(ip -4 addr show eth0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
    NETPREFIX=$(echo $IPADDR | awk -F. '{print $1"."$2}')
    LIVE_HOSTS=""
    COUNT=0
    for OCT3 in $(seq 0 255); do
        for OCT4 in $(seq 1 254); do
            HOST="$NETPREFIX.$OCT3.$OCT4"
            ping -c 1 -W 1 "$HOST" >/dev/null 2>&1 || continue
            LIVE_HOSTS="$LIVE_HOSTS $HOST"
            COUNT=$((COUNT+1))
            [ $COUNT -eq 5 ] && break 2
        done
    done
    echo "$LIVE_HOSTS"
}

scan_first_5_hosts() {
    HOSTS="$1"
    TMPFILE=$(mktemp)
    log "Running detailed scan on hosts: $HOSTS"

    # Use normal output for reliable parsing
    nmap -Pn -sV -O --top-ports 10 $HOSTS -oN "$TMPFILE" >/dev/null 2>&1

    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    {
        echo "Proof-of-entry Scan Report"
        echo "Timestamp: $TIMESTAMP"
        echo "Public IP: $PUBLIC_IP"
        echo ""
        echo "IP | OS | top_ports | services"
    } > "$LOOT_DIR/proof_of_entry.txt"

    awk '
    /^Nmap scan report for /{
        if(ip!="" && ports!=""){ print ip " | " os " | " ports " | " services }
        ip=$NF; os="unknown"; ports=""; services=""
    }
    /^OS details: /{os=substr($0, 12)}
    /^[0-9]+\/tcp /{
        split($0,f," "); 
        portnum=f[1]; service=f[3]; 
        ports=(ports?ports";"portnum:portnum); 
        services=(services?services";"service:service)
    }
    END{ if(ip!="" && ports!=""){ print ip " | " os " | " ports " | " services } }
    ' "$TMPFILE" >> "$LOOT_DIR/proof_of_entry.txt"

    rm -f "$TMPFILE"
}

# ---- MAIN ----
setup_network
led_blink_start

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
log "Scan started at $TIMESTAMP"
log_latest "Scan started at $TIMESTAMP"

fetch_public_ip
require_nmap_or_exit

FIRST_5_HOSTS=$(get_first_5_live_hosts)
log "Running detailed scan on hosts: $FIRST_5_HOSTS"
[ -z "$FIRST_5_HOSTS" ] && log "No live hosts found" && exit 0

scan_first_5_hosts "$FIRST_5_HOSTS"

led_blink_stop
led_done
log "Proof-of-entry scan complete."
