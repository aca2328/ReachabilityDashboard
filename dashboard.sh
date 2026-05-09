#!/bin/bash

# Peering quality probes.
# Format: "label|target|network/region|scope|probe"
# Probe types:
#   ICMP_ECHO     - RTT from ping, when the target accepts ICMP.
#   DNS_RECURSOR  - Recursive DNS query latency through a public resolver.
#   DNS_AUTH      - Authoritative DNS query latency against a known auth server.
#   HTTPS_CONNECT - TCP+TLS establishment time to an HTTPS endpoint.
#   HTTPS_GET     - Full HTTPS request time and HTTP status validation.
TARGETS=(
    "Cloudflare DNS|1.1.1.1|AS13335 / anycast|global|DNS_RECURSOR"
    "Quad9 DNS|9.9.9.9|AS19281 / anycast|global|DNS_RECURSOR"
    "Google DNS|8.8.8.8|AS15169 / anycast|global|DNS_RECURSOR"
    "114DNS China|114.114.114.114|AS38283 / CN|regional|DNS_RECURSOR"
    "K-root RIPE NCC|193.0.14.129|AS25152 / root|anycast-root|DNS_AUTH"
    "M-root WIDE|202.12.27.33|WIDE / root|anycast-root|DNS_AUTH"
    "Cloudflare HTTPS|www.cloudflare.com|AS13335 / CDN|global|HTTPS_CONNECT"
    "Wikipedia HTTPS|www.wikipedia.org|AS14907 / CDN|global|HTTPS_GET"
    "Deutsche Telekom|194.25.0.60|AS3320 / DE|operator|ICMP_ECHO"
    "Hurricane Electric|184.105.213.138|AS6939 / US|operator|ICMP_ECHO"
    "Telstra|139.130.4.5|AS1221 / AU|operator|ICMP_ECHO"
    "LACNIC|200.3.14.1|AS28001 / UY|operator|ICMP_ECHO"
)

TIMEOUT=3
REFRESH=5

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

declare -a PREV_LAT
declare -a CHECK_PASS
declare -a CHECK_TOTAL
declare -a TARGET_VALID
declare -a TARGET_ERROR

CYCLE=0
DASH_TMP=$(mktemp -d)

cleanup() {
    local child
    trap - SIGINT SIGTERM
    for child in $(jobs -pr); do
        kill "$child" 2>/dev/null
    done
    wait 2>/dev/null
    rm -rf "$DASH_TMP"
    printf "\033[?25h\n"
    exit 0
}
trap cleanup SIGINT SIGTERM

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

is_ipv4() {
    local ip=$1 octet
    local -a octets
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( octet >= 0 && octet <= 255 )) || return 1
    done
}

is_hostname() {
    local host=$1
    [[ ${#host} -le 253 ]] || return 1
    [[ "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

is_target_name() {
    is_ipv4 "$1" || is_hostname "$1"
}

lat_color() {
    local ms=$1
    [[ "$ms" =~ ^[0-9]+$ ]] || { printf '%s' "$GREEN"; return; }
    if   (( ms <  50 )); then printf '%s' "$GREEN"
    elif (( ms < 150 )); then printf '%s' "$YELLOW"
    else                      printf '%s' "$RED"
    fi
}

probe_label() {
    case "$1" in
        ICMP_ECHO)     printf 'ICMP' ;;
        DNS_RECURSOR)  printf 'DNS-REC' ;;
        DNS_AUTH)      printf 'DNS-AUTH' ;;
        HTTPS_CONNECT) printf 'HTTPS-C' ;;
        HTTPS_GET)     printf 'HTTPS-GET' ;;
        *)             printf '%s' "$1" ;;
    esac
}

validate_probe_requirements() {
    local probe=$1
    case "$probe" in
        ICMP_ECHO)
            need_cmd ping || { printf 'missing ping'; return 1; }
            ;;
        DNS_RECURSOR|DNS_AUTH)
            need_cmd dig || { printf 'missing dig'; return 1; }
            ;;
        HTTPS_CONNECT|HTTPS_GET)
            need_cmd curl || { printf 'missing curl'; return 1; }
            ;;
        *)
            printf 'unsupported probe %s' "$probe"
            return 1
            ;;
    esac
}

validate_target() {
    local row=$1 entry=$2
    local label target info scope probe extra

    IFS='|' read -r label target info scope probe extra <<< "$entry"

    if [[ -n "$extra" || -z "$label" || -z "$target" || -z "$info" || -z "$scope" || -z "$probe" ]]; then
        TARGET_VALID[$row]=0
        TARGET_ERROR[$row]="bad fields"
        return
    fi

    if ! is_target_name "$target"; then
        TARGET_VALID[$row]=0
        TARGET_ERROR[$row]="bad target"
        return
    fi

    local err
    if ! err=$(validate_probe_requirements "$probe"); then
        TARGET_VALID[$row]=0
        TARGET_ERROR[$row]="$err"
        return
    fi

    case "$probe" in
        DNS_RECURSOR|DNS_AUTH)
            if ! is_ipv4 "$target"; then
                TARGET_VALID[$row]=0
                TARGET_ERROR[$row]="DNS probe target must be IP"
                return
            fi
            ;;
    esac

    TARGET_VALID[$row]=1
    TARGET_ERROR[$row]=""
}

validate_targets() {
    local i
    local invalid=0

    for i in "${!TARGETS[@]}"; do
        validate_target "$i" "${TARGETS[$i]}"
        [[ "${TARGET_VALID[$i]}" == "1" ]] || (( invalid++ ))
    done

    if (( invalid > 0 )); then
        printf '%bTarget configuration has %d invalid row(s):%b\n' "$RED" "$invalid" "$NC" >&2
        for i in "${!TARGETS[@]}"; do
            [[ "${TARGET_VALID[$i]}" == "1" ]] && continue
            printf '  [%d] %s: %s\n' "$i" "${TARGETS[$i]}" "${TARGET_ERROR[$i]}" >&2
        done
        printf '\nInvalid rows will be shown as CONFIG_BAD and skipped.\n' >&2
        sleep 2
    fi
}

icmp_latency() {
    local host=$1 raw
    if [[ "$(uname -s)" == "Darwin" ]]; then
        raw=$(ping -c 1 -W "$(( TIMEOUT * 1000 ))" "$host" 2>/dev/null |
              awk -F'time=' '/time=/ {split($2,a," "); printf "%d\n", a[1] + 0.5; exit}')
    else
        raw=$(ping -c 1 -W "$TIMEOUT" "$host" 2>/dev/null |
              awk -F'time=' '/time=/ {split($2,a," "); printf "%d\n", a[1] + 0.5; exit}')
    fi
    [[ -n "$raw" ]] && printf '%s\n' "$raw" && return 0
    return 1
}

dns_rec_latency() {
    local host=$1 ms status
    status=$(dig +tries=1 +time="$TIMEOUT" @"$host" example.com A 2>/dev/null)
    ms=$(awk '/Query time:/ {print $4}' <<< "$status")
    [[ -n "$ms" ]] && grep -q 'status: NOERROR' <<< "$status" && printf '%s\n' "$ms" && return 0
    return 1
}

dns_auth_latency() {
    local host=$1 ms status
    status=$(dig +tries=1 +time="$TIMEOUT" +norecurse @"$host" . NS 2>/dev/null)
    ms=$(awk '/Query time:/ {print $4}' <<< "$status")
    [[ -n "$ms" ]] && grep -Eq 'status: (NOERROR|REFUSED)' <<< "$status" && printf '%s\n' "$ms" && return 0
    return 1
}

https_latency() {
    local host=$1 mode=$2 out url http_code metric
    local time_connect time_appconnect time_total
    url="https://${host}/"
    out=$(curl --silent --output /dev/null --max-time "$TIMEOUT" \
        --write-out '%{time_connect} %{time_appconnect} %{time_total} %{http_code}' \
        "$url" 2>/dev/null) || return 1

    read -r time_connect time_appconnect time_total http_code <<< "$out"
    [[ "$http_code" =~ ^[234][0-9][0-9]$ ]] || return 1

    if [[ "$mode" == "connect" ]]; then
        metric=$time_appconnect
        awk "BEGIN {exit !($metric > 0)}" || metric=$time_connect
    else
        metric=$time_total
    fi

    awk -v seconds="$metric" 'BEGIN {printf "%d\n", (seconds * 1000) + 0.5}'
}

run_probe() {
    local target=$1 probe=$2
    case "$probe" in
        ICMP_ECHO)     icmp_latency "$target" ;;
        DNS_RECURSOR)  dns_rec_latency "$target" ;;
        DNS_AUTH)      dns_auth_latency "$target" ;;
        HTTPS_CONNECT) https_latency "$target" connect ;;
        HTTPS_GET)     https_latency "$target" get ;;
        *)             return 2 ;;
    esac
}

status_text() {
    local state=$1
    case "$state" in
        OK)         printf '%bOK        %b' "$GREEN" "$NC" ;;
        CONFIG_BAD) printf '%bCONFIG_BAD%b' "$YELLOW" "$NC" ;;
        PROBE_FAIL) printf '%bPROBE_FAIL%b' "$RED" "$NC" ;;
        *)          printf '%bUNKNOWN   %b' "$RED" "$NC" ;;
    esac
}

render_row() {
    local row=$1 label=$2 info=$3 scope=$4 probe=$5 state=$6 lat_ms=$7 prev_lat=$8 pass=$9 total=${10}
    local new_pass new_total pct pct_col pct_vis upad uptime_out
    local lat_out lc trend lat_vis lpad status_out probe_out

    status_out=$(status_text "$state")
    probe_out=$(probe_label "$probe")

    if [[ "$state" == "OK" && "$lat_ms" =~ ^[0-9]+$ ]]; then
        lc=$(lat_color "$lat_ms")
        if [[ -n "$prev_lat" && "$prev_lat" =~ ^[0-9]+$ ]]; then
            local diff=$(( lat_ms - prev_lat ))
            if   (( diff >  5 )); then trend="↑"
            elif (( diff < -5 )); then trend="↓"
            else                       trend="↔"
            fi
        else
            trend=" "
        fi
        lat_vis="${lat_ms} ms ${trend}"
        lpad=$(( 12 - ${#lat_vis} ))
        (( lpad < 0 )) && lpad=0
        lat_out="${lc}${lat_ms} ms${NC} ${trend}$(printf '%*s' "$lpad" '')"
    else
        lat_out="${RED}---${NC}         "
    fi

    if [[ "$state" == "OK" ]]; then
        new_pass=$(( pass + 1 ))
    else
        new_pass=$pass
    fi
    new_total=$(( total + 1 ))
    pct=$(( new_pass * 100 / new_total ))
    pct_vis="${pct}%"

    if   (( pct == 100 )); then pct_col="$GREEN"
    elif (( pct >=  80 )); then pct_col="$YELLOW"
    else                        pct_col="$RED"
    fi

    upad=$(( 6 - ${#pct_vis} ))
    (( upad < 0 )) && upad=0
    uptime_out="${pct_col}${pct_vis}${NC}$(printf '%*s' "$upad" '')"

    printf "\033[$((row + 6));0H %-22s | %-18s | %-12s | %-9s | %b | %b | %b\n" \
        "$label" "$info" "$scope" "$probe_out" "$status_out" "$lat_out" "$uptime_out"
}

run_check() {
    local row=$1 label=$2 target=$3 info=$4 scope=$5 probe=$6 prev_lat=$7 pass=$8 total=$9
    local lat_ms state

    rm -f "$DASH_TMP/result_$row"

    if [[ "${TARGET_VALID[$row]}" != "1" ]]; then
        state="CONFIG_BAD"
    elif lat_ms=$(run_probe "$target" "$probe"); then
        state="OK"
    else
        state="PROBE_FAIL"
    fi

    printf '%s %s\n' "$state" "${lat_ms:-}" > "$DASH_TMP/result_$row"
    render_row "$row" "$label" "$info" "$scope" "$probe" "$state" "${lat_ms:-}" \
        "$prev_lat" "$pass" "$total"
}

validate_targets
printf "\033[?25l"

while true; do
    (( CYCLE++ ))
    clear

    echo -e "${CYAN}================================================================================${NC}"
    echo -e "              ${YELLOW}OPERATOR PEERING QUALITY DASHBOARD${NC} | $(date '+%H:%M:%S')"
    echo -e "${CYAN}================================================================================${NC}"
    printf " %-22s | %-18s | %-12s | %-9s | %-10s | %-12s | %-6s\n" \
        "TARGET" "NETWORK" "SCOPE" "PROBE" "STATUS" "RTT/TIME" "SUCCESS"
    echo "------------------------|--------------------|--------------|-----------|------------|--------------|-------"

    for i in "${!TARGETS[@]}"; do
        IFS='|' read -r label target info scope probe <<< "${TARGETS[$i]}"
        printf " %-22s | %-18s | %-12s | %-9s | %-10s | %-12s | %-6s\n" \
            "$label" "$info" "$scope" "$(probe_label "$probe")" "CHECKING" "..." "-"
    done

    echo "------------------------|--------------------|--------------|-----------|------------|--------------|-------"
    printf " Cycle #%-4d | Running peering probes...%*s\n" "$CYCLE" 42 ""

    for i in "${!TARGETS[@]}"; do
        IFS='|' read -r label target info scope probe <<< "${TARGETS[$i]}"
        run_check "$i" "$label" "$target" "$info" "$scope" "$probe" \
            "${PREV_LAT[$i]:-}" "${CHECK_PASS[$i]:-0}" "${CHECK_TOTAL[$i]:-0}" &
    done

    wait

    online=0; lat_sum=0; lat_count=0; invalid=0
    for i in "${!TARGETS[@]}"; do
        [[ -f "$DASH_TMP/result_$i" ]] || continue
        read -r state latency < "$DASH_TMP/result_$i"
        CHECK_TOTAL[$i]=$(( ${CHECK_TOTAL[$i]:-0} + 1 ))

        case "$state" in
            OK)
                CHECK_PASS[$i]=$(( ${CHECK_PASS[$i]:-0} + 1 ))
                (( online++ ))
                if [[ "$latency" =~ ^[0-9]+$ ]]; then
                    (( lat_sum += latency, lat_count++ ))
                    PREV_LAT[$i]="$latency"
                fi
                ;;
            CONFIG_BAD)
                (( invalid++ ))
                PREV_LAT[$i]=""
                ;;
            *)
                PREV_LAT[$i]=""
                ;;
        esac
    done

    avg_ms="-"
    (( lat_count > 0 )) && avg_ms="$(( lat_sum / lat_count ))ms"

    footer_row=$(( ${#TARGETS[@]} + 7 ))
    printf "\033[${footer_row};0H Cycle #%-4d | %d/%d probes OK | %d config bad | avg %s%*s\n" \
        "$CYCLE" "$online" "${#TARGETS[@]}" "$invalid" "$avg_ms" 20 ""

    for (( s=REFRESH; s>0; s-- )); do
        printf "\033[$(( footer_row + 1 ));0H Next refresh in ${s}s...   "
        sleep 1
    done
done
