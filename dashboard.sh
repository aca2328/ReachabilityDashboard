#!/bin/bash

# --- CONFIGURATION: Diverse Targets ---
TARGETS=(
    "Cloudflare (Anycast)|1.1.1.1|AS13335|UDP/53"
    "Quad9 (Privacy)|9.9.9.9|AS19281|UDP/53"
    "Google (Global)|8.8.8.8|AS15169|UDP/53"
    "Wikipedia (Global)|wikipedia.org|AS14907|TCP/443"
    "Alibaba (China)|alibaba.com|AS37963|TCP/443"
    "Meta (US)|facebook.com|AS32934|TCP/443"
    "Orange France|80.10.246.2|France|ICMP"
    "D. Telekom|194.25.0.60|Europe|ICMP"
    "NTT Japan|129.250.35.250|Asia|ICMP"
    "Telstra Australia|139.130.4.5|Oceania|ICMP"
)

TIMEOUT=3
REFRESH=5

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- CLEANUP ---
cleanup() {
    # Kill all background check jobs spawned by this script
    kill -- -$$ 2>/dev/null
    # Restore cursor and newline
    printf "\033[?25h\n"
    exit 0
}
trap cleanup SIGINT SIGTERM

# --- LATENCY HELPERS ---
# Measure TCP connect time in ms using /dev/tcp (no external tool needed)
tcp_latency() {
    local host=$1 port=$2
    local start end
    start=$(date +%s%3N)
    timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null && {
        end=$(date +%s%3N)
        echo $(( end - start ))
        return 0
    }
    return 1
}

# Measure DNS query latency in ms using dig
dns_latency() {
    local host=$1
    local ms
    ms=$(dig +tries=1 +time="$TIMEOUT" @"$host" google.com 2>/dev/null \
         | awk '/Query time:/ {print $4}')
    [[ -n "$ms" ]] && echo "$ms" && return 0
    return 1
}

# --- ASYNC WORKER FUNCTION ---
run_check() {
    local row=$1 label=$2 target=$3 info=$4 proto=$5
    local success=1
    local lat_ms=""

    if [[ "$proto" == "UDP/53" ]]; then
        lat_ms=$(dns_latency "$target") && success=0
    elif [[ "$proto" == "TCP/443" ]]; then
        lat_ms=$(tcp_latency "$target" 443) && success=0
    else
        # ICMP: use ping for both connectivity and latency
        local raw
        raw=$(timeout "$TIMEOUT" ping -c 1 -W "$TIMEOUT" "$target" 2>/dev/null \
              | awk -F '/' 'END {if ($5) print int($5)}')
        if [[ -n "$raw" ]]; then
            success=0
            lat_ms="$raw"
        fi
    fi

    local status_out lat_out
    if [[ $success -eq 0 ]]; then
        status_out="${GREEN}ONLINE${NC} "
        lat_out="${lat_ms:-?} ms"
    else
        status_out="${RED}OFFLINE${NC}"
        lat_out="${RED}---${NC}   "
    fi

    printf "\033[$((row + 5));0H %-25s | %-12s | %-10s | %b | %-10s\n" \
           "$label" "$info" "$proto" "$status_out" "$lat_out"
}

# --- MAIN LOOP ---
printf "\033[?25l"  # hide cursor

while true; do
    clear
    echo -e "${CYAN}================================================================================${NC}"
    echo -e "           ${YELLOW}DIVERSE ASYNCHRONOUS NETWORK DASHBOARD${NC} | $(date '+%H:%M:%S')"
    echo -e "${CYAN}================================================================================${NC}"

    printf " %-25s | %-12s | %-10s | %-10s | %-10s\n" "TARGET" "ASN/REGION" "PROTOCOL" "STATUS" "LATENCY"
    echo "---------------------------|--------------|------------|------------|-----------"

    for i in "${!TARGETS[@]}"; do
        IFS='|' read -r label target info proto <<< "${TARGETS[$i]}"
        printf " %-25s | %-12s | %-10s | %-10s | %-10s\n" "$label" "$info" "$proto" "CHECKING.." "..."
    done

    echo "---------------------------|--------------|------------|------------|-----------"
    echo " [Performing parallel backbone checks...]"

    for i in "${!TARGETS[@]}"; do
        IFS='|' read -r label target info proto <<< "${TARGETS[$i]}"
        run_check "$i" "$label" "$target" "$info" "$proto" &
    done

    wait

    printf "\033[$(( ${#TARGETS[@]} + 7 ));0H"
    sleep "$REFRESH"
done
