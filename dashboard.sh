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

TIMEOUT=2
# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- ASYNC WORKER FUNCTION ---
run_check() {
    local row=$1; local label=$2; local target=$3; local info=$4; local proto=$5
    local success=1
    
    # 1. Connectivity Test
    if [[ "$proto" == "UDP/53" ]]; then
        nc -zuw $TIMEOUT "$target" 53 2>/dev/null && success=0
    elif [[ "$proto" == "TCP/443" ]]; then
        nc -zw $TIMEOUT "$target" 443 2>/dev/null && success=0
    else
        ping -c 1 -W $TIMEOUT "$target" >/dev/null 2>&1 && success=0
    fi

    # 2. Results Formatting
    local status_out
    local lat_out
    
    if [ $success -eq 0 ]; then
        status_out="${GREEN}ONLINE${NC} " # Added space to match 'OFFLINE' length
        local raw_lat=$(ping -c 1 -W $TIMEOUT "$target" 2>/dev/null | awk -F '/' 'END {print $5}')
        lat_out="${raw_lat:-0} ms"
    else
        status_out="${RED}OFFLINE${NC}"
        lat_out="${RED}---${NC}"
    fi

    # 3. Precise UI Update
    # Moves cursor to Row (row+5) and Column 0 to overwrite the placeholder
    # We use a literal string for the status to prevent ANSI codes from breaking the printf width
    printf "\033[$((row + 5));0H %-25s | %-12s | %-10s | %b | %-10s\n" \
           "$label" "$info" "$proto" "$status_out" "$lat_out"
}

# --- MAIN LOOP ---
# Trap Ctrl+C to clean up and show cursor (if hidden)
trap "echo -e '\n'; exit" SIGINT

while true; do
    clear
    echo -e "${CYAN}================================================================================${NC}"
    echo -e "           ${YELLOW}DIVERSE ASYNCHRONOUS NETWORK DASHBOARD${NC} | $(date '+%H:%M:%S')"
    echo -e "${CYAN}================================================================================${NC}"
    
    # Standardized Header
    printf " %-25s | %-12s | %-10s | %-10s | %-10s\n" "TARGET" "ASN/REGION" "PROTOCOL" "STATUS" "LATENCY"
    echo "---------------------------|--------------|------------|------------|-----------"

    # 1. Draw Static Placeholders (Instantly)
    for i in "${!TARGETS[@]}"; do
        IFS='|' read -r label target info proto <<< "${TARGETS[$i]}"
        printf " %-25s | %-12s | %-10s | %-10s | %-10s\n" "$label" "$info" "$proto" "CHECKING.." "..."
    done
    
    echo "---------------------------|--------------|------------|------------|-----------"
    echo " [Performing parallel backbone checks...]"

    # 2. Launch Background Checks
    for i in "${!TARGETS[@]}"; do
        IFS='|' read -r label target info proto <<< "${TARGETS[$i]}"
        run_check "$i" "$label" "$target" "$info" "$proto" &
    done

    # 3. Wait for the slowest response (max 2s) before restarting loop
    wait
    
    # Return cursor to a safe place at the bottom
    printf "\033[$(( ${#TARGETS[@]} + 7 ));0H"
    sleep 5
done
