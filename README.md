# ReachabilityDashboard

Native macOS dashboard for monitoring operator peering quality with ICMP, DNS, and HTTPS probes.

## Run

```sh
swift run ReachabilityDashboard
```

The legacy Bash TUI remains available as:

```sh
./dashboard.sh
```

## Probe Types

- `ICMP_ECHO`: ping RTT for targets that accept ICMP.
- `DNS_RECURSOR`: recursive DNS query timing through public resolvers.
- `DNS_AUTH`: authoritative DNS query timing against root/auth servers.
- `HTTPS_CONNECT`: TCP/TLS setup timing for HTTPS endpoints.
- `HTTPS_GET`: full HTTPS request timing and HTTP status validation.