# ReachabilityDashboard

Native macOS menu bar app for monitoring operator peering quality with ICMP, DNS, and HTTPS probes.

## Features

- **Menu bar app**: starts as a menu bar icon only (no Dock icon). The icon is green when all probes are OK, orange when some fail, red when all fail, and gray before the first results.
- **Popover**: click the icon for a per-target summary with live sparklines and latency, plus Open Dashboard, Edit Targets…, and Quit. Opening it doesn't bring the dashboard window forward.
- **Dashboard window**: a smooth, continuously scrolling neon latency graph (60 s of history) with floating labels. The y-axis eases to fit the data instead of snapping. Closing the window keeps the app running in the menu bar.
- **Independent probes**: each target runs on its own loop and interval, so a slow target never holds up the others.
- **Editable targets**: add, remove, and edit targets, test one before saving, or reset to the defaults.

## Install

Download `ReachabilityDashboard.zip` from the [latest release](https://github.com/aca2328/ReachabilityDashboard/releases/latest), unzip it, and move `ReachabilityDashboard.app` to Applications. It runs on macOS 13 or later, on Apple silicon and Intel Macs.

The app is ad-hoc signed, not notarized, so macOS blocks it the first time. Either open it once, then choose **Open Anyway** in System Settings › Privacy & Security, or clear the download flag in Terminal:

```sh
xattr -dr com.apple.quarantine /Applications/ReachabilityDashboard.app
```

To build it yourself instead, create a signed universal `.app` bundle (with icon) and copy it to Applications:

```sh
./bundle.sh
cp -R .build/ReachabilityDashboard.app /Applications/
```

The build number shown in the app is the git commit count at bundle time. Re-run `./bundle.sh` after pulling new commits.

## Run from source

```sh
swift run ReachabilityDashboard
```

Or pull the latest changes, do a clean release build, and run it:

```sh
./run.sh
```

The legacy Bash TUI remains available as:

```sh
./dashboard.sh
```

## Editing targets

Choose **Edit Targets…** from the menu bar popover. Select a target to edit its name, host, probe type, network, and scope. **Test** runs one probe against the entered values without saving. **Save** checks every target, then applies the list immediately (unchanged targets keep their graph history).

The list is stored in `~/Library/Application Support/ReachabilityDashboard/targets.json`. Delete that file to go back to the built-in defaults. `dashboard.sh` keeps its own hardcoded list and doesn't follow these edits.

## Probe Types

- `ICMP_ECHO`: ping RTT for targets that accept ICMP.
- `DNS_RECURSOR`: recursive DNS query timing through public resolvers.
- `DNS_AUTH`: authoritative DNS query timing against root/auth servers.
- `HTTPS_CONNECT`: TCP/TLS setup timing for HTTPS endpoints.
- `HTTPS_GET`: full HTTPS request timing and HTTP status validation.

DNS probes need an IPv4 host. Probes call `/sbin/ping`, `/usr/bin/dig`, and `/usr/bin/curl`; a target whose tool is missing is marked config bad rather than failing the app.

## License

MIT, see [LICENSE](LICENSE).
