#!/bin/sh
# Created by Hackazillarex - Hackazillarex@gmail.com and all social media.
# Use only on environments that you have explicit permissions to do so. 
# SharkJack payload: Guaranteed Public IP + OS + top 10 ports on local subnet
# LED blinks while scanning, solid green when done

LOOT_DIR=/root/loot
LOG_FILE="$LOOT_DIR/minimal_log.txt"
LATEST_FILE="$LOOT_DIR/latest_scan.txt"
POST_DHCP_WAIT=20

ALLOW_LOCAL_SCAN=1
LOCAL_SCAN_SLOW_TIMING=1

mkdir -p "$LOOT_DIR"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE" > /dev/null; }
log_latest() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" > "$LATEST_FILE"; }

# ---- LED CONTROL ----
led_setup()   { LED SETUP; }
led_blink_start() { ( while true; do LED ATTACK; sleep 0.5; LED OFF; sleep 0.5; done ) & BLINK_PID=$!; }
led_blink_stop()  { if [ ! -z "$BLINK_PID" ]; then kill "$BLINK_PID" 2>/dev/null || true; unset BLINK_PID; fi }
led_done()    { LED FINISH; }  # solid green
led_off()     { LED OFF; }

require_nmap_or_exit() {
    if ! command -v nmap >/dev/null 2>&1; then
        log "ERROR: nmap not installed; skipping local scan."
        return 1
    fi
    return 0
}

setup_network() {
    led_setup
    NETMODE DHCP_CLIENT
    COUNT=0
    while [ $COUNT -lt 60 ]; do
        if ip addr show eth0 2>/dev/null | grep -q "inet "; then break; fi
        COUNT=$((COUNT+1)); sleep 1
    done
    sleep $POST_DHCP_WAIT
    if ! grep -q "nameserver" /etc/resolv.conf 2>/dev/null; then
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
    fi
}

# ---- ROBUST PUBLIC IP FETCH WITH LAST-RESORT FALLBACK ----
fetch_public_ip() {
    PUBLIC_IP=""
    MAX_IP_RETRIES=10
    IP_RETRY_DELAY=5

    for i in $(seq 1 $MAX_IP_RETRIES); do
        # Method 1: wget with multiple HTTP services
        if command -v wget >/dev/null 2>&1; then
            SERVICES="https://api.ipify.org?format=text https://ifconfig.me https://ident.me https://checkip.amazonaws.com http://ipecho.net/plain"
            for svc in $SERVICES; do
                PUBLIC_IP=$(wget -qO- --timeout=6 "$svc" 2>/dev/null)
                [ -n "$PUBLIC_IP" ] && break 2
            done
        fi

        # Method 2: curl fallback
        if [ -z "$PUBLIC_IP" ] && command -v curl >/dev/null 2>&1; then
            for svc in $SERVICES; do
                PUBLIC_IP=$(curl -s --max-time 6 "$svc")
                [ -n "$PUBLIC_IP" ] && break 2
            done
        fi

        # Method 3: DNS lookup using dig
        if [ -z "$PUBLIC_IP" ] && command -v dig >/dev/null 2>&1; then
            PUBLIC_IP=$(dig +short myip.opendns.com @resolver1.opendns.com)
            [ -n "$PUBLIC_IP" ] && break
        fi

        # Method 4: Last-resort local approximation
        if [ -z "$PUBLIC_IP" ]; then
            GW=$(ip route 2>/dev/null | awk '/default/ {print $3; exit}')
            if [ -n "$GW" ]; then
                ping -c 1 -W 1 "$GW" >/dev/null 2>&1
                PUBLIC_IP=$(ip addr show eth0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
                [ -n "$PUBLIC_IP" ] && break
            fi
        fi

        log "Public IP fetch attempt $i failed; retrying in $IP_RETRY_DELAY seconds..."
        sleep $IP_RETRY_DELAY
    done

    if [ -n "$PUBLIC_IP" ]; then
        log "Public IP: $PUBLIC_IP"
        echo "$PUBLIC_IP" > "$LOOT_DIR/public_ip.txt"
        echo "Public IP: $PUBLIC_IP" > "$LOOT_DIR/minimal_scan.txt"
    else
        log "Failed to fetch public IP after all attempts."
        echo "Public IP: unknown" > "$LOOT_DIR/minimal_scan.txt"
    fi
}

# ---- MINIMAL LOCAL SCAN ----
run_local_minimal_scan() {
    [ "$ALLOW_LOCAL_SCAN" -ne 1 ] && return 0
    require_nmap_or_exit || return 1

    log "Starting minimal local scan (OS + top 10 ports)"
    log_latest "Local scan started"

    CIDR=$(ip -4 addr show eth0 2>/dev/null | awk '/inet /{print $2; exit}' || true)
    [ -z "$CIDR" ] && { log "Could not determine local CIDR"; echo "Could not determine local CIDR" >> "$LATEST_FILE"; return 1; }

    OUT_N="$LOOT_DIR/local_minimal.txt"
    OUT_GN="$LOOT_DIR/local_minimal.gnmap"
    OUT_TXT="$LOOT_DIR/minimal_scan.txt"

    TFLAG="-T3"; [ "$LOCAL_SCAN_SLOW_TIMING" -eq 0 ] && TFLAG="-T4"
    NMAP_OPTS="$TFLAG --top-ports 10 -sV -O -Pn"

    log "Running: nmap $NMAP_OPTS $CIDR"
    nmap $NMAP_OPTS "$CIDR" -oN "$OUT_N" -oG "$OUT_GN" >>"$LOG_FILE" 2>&1

    if [ ! -s "$OUT_N" ] && [ ! -s "$OUT_GN" ]; then
        log "Nmap scan failed or empty."
        return 1
    fi

    # Parse nmap output to compact form: IP | OS | top_ports
    awk '
    BEGIN { OFS=" | " }
    FNR==NR {
        if ($0 ~ /^Nmap scan report for /) {
            line=$0
            if (match(line, /\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)/, m)) { curip = m[1] }
            else { n=split(line,a," "); curip=a[n] }
        }
        if ($0 ~ /OS details: /) {
            pos=index($0,"OS details: ")
            s=substr($0,pos+11)
            gsub(/,/," ",s)
            os[curip]=s
        }
        next
    }
    /^Host:/ {
        ip=$2
        ports_field=""
        for(i=1;i<=NF;i++){ if($i=="Ports:"){for(j=i+1;j<=NF;j++){ports_field=ports_field $j " "} break} }
        n=split(ports_field,arr,";")
        out_ports=""
        for(k=1;k<=n;k++){ if(arr[k]=="") continue; if(match(arr[k],/^([0-9]+)\//,p)){ if(out_ports!="") out_ports=out_ports ";" p[1]; else out_ports=p[1] } }
        if(out_ports=="") out_ports="none"
        out_os=(ip in os ? os[ip] : "unknown")
        gsub(/\r/,"",out_os)
        print ip, out_os, out_ports
    }' "$OUT_N" "$OUT_GN" >> "$OUT_TXT" 2>/dev/null

    # Ensure header after public IP line
    sed -i '/^IP | OS | top_ports/d' "$OUT_TXT"
    sed -i '2iIP | OS | top_ports' "$OUT_TXT"

    log "Minimal scan complete. TXT: $OUT_TXT"
}

# ---- MAIN ----
setup_network
led_blink_start

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
log "Scan started at $TIMESTAMP"
log_latest "Scan started at $TIMESTAMP"

# Guaranteed public IP fetch first
fetch_public_ip

# Run local minimal scan
run_local_minimal_scan

led_blink_stop
led_done  # solid green when done
