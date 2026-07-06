# CLAUDE.md

Native macOS dashboard (AppKit, Swift 6) monitoring ICMP/DNS/HTTPS probe latency to a fixed set of targets.

## Commands
- Run in dev: `swift run ReachabilityDashboard`
- Build release: `swift build --configuration release`
- Build+run latest (pulls origin, clean rebuild): `./run.sh`
- Legacy bash TUI (still maintained as fallback): `./dashboard.sh`
- Run unit tests: `swift test` (Swift Testing, in `Tests/ReachabilityDashboardTests/`). Requires full Xcode installed (not just Command Line Tools) — without it, `swift test` can't locate the `Testing` framework.

## Architecture
Single file: `Sources/ReachabilityDashboard/main.swift` (~800 lines).
- `ProbeTarget`/`ProbeRow` — static target list (`configuredTargets`) + per-target running state/history
- `ProbeEngine` — validates and executes probes by shelling out to `/sbin/ping`, `/usr/bin/dig`, `/usr/bin/curl`; pure parsing logic (`parsePingOutput`, `parseDigOutput`, `parseCurlOutput`, `isIPv4`, `isHostname`) is split out from process execution so it's unit-testable
- `ProbeGraphView` — custom NSView drawing the neon multi-line latency graph (Catmull-Rom smoothing, glow, floating labels)
- `DashboardController` — AppKit app delegate; owns the window and the per-probe scheduling loop

## Gotchas
- Each probe runs its own independent async loop (`probeOnce`/`scheduleNext`), not a shared refresh timer — a slow target never blocks the others. Refresh interval is per-`ProbeType` (`ProbeType.refreshInterval`), not a single global constant — heavier probes (`HTTPS_GET`, `DNS_AUTH`) refresh less often than `ICMP_ECHO`.
- Probes require system binaries at fixed paths (`/sbin/ping`, `/usr/bin/dig`, `/usr/bin/curl`); missing ones mark a row `CONFIG_BAD` rather than failing the app.
- App version is derived at runtime from `git rev-list --count HEAD` (see `buildNumber`), not hand-bumped — don't add a manual version constant.
- `run.sh` does `git pull origin HEAD` + `rm -rf .build` before building — don't run it with uncommitted local changes you want to keep.
