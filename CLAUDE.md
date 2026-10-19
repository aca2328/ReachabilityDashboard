# CLAUDE.md

Native macOS dashboard (AppKit, Swift 6) monitoring ICMP/DNS/HTTPS probe latency to a fixed set of targets.

## Commands
- Run in dev: `swift run ReachabilityDashboard`
- Build release: `swift build --configuration release`
- Build+run latest (pulls origin, clean rebuild): `./run.sh`
- Package `.app` (universal, ad-hoc signed): `./bundle.sh`; publish a GitHub release `v1.0.<commit count>` with the zipped app: `./release.sh` (needs a clean tree pushed to `main`)
- Legacy bash TUI (still maintained as fallback): `./dashboard.sh`
- Run unit tests: `swift test` (Swift Testing, in `Tests/ReachabilityDashboardTests/`). Requires full Xcode installed (not just Command Line Tools) — without it, `swift test` can't locate the `Testing` framework.

## Architecture
Single file: `Sources/ReachabilityDashboard/main.swift` (~800 lines).
- `ProbeTarget`/`ProbeRow` — target list + per-target running state/history. `TargetStore` loads the list from `~/Library/Application Support/ReachabilityDashboard/targets.json` (falls back to `defaultTargets` if missing or undecodable); `TargetEditorController` edits it from the popover. `dashboard.sh` keeps its own hardcoded list
- `ProbeEngine` — validates and executes probes by shelling out to `/sbin/ping`, `/usr/bin/dig`, `/usr/bin/curl`; pure parsing logic (`parsePingOutput`, `parseDigOutput`, `parseCurlOutput`, `isIPv4`, `isHostname`) is split out from process execution so it's unit-testable
- `ProbeGraphView` — custom NSView drawing the neon multi-line latency graph (Catmull-Rom smoothing, glow, floating labels)
- `DashboardController` — AppKit app delegate; owns the window, the menu bar status item/popover, and the per-probe scheduling loop. Runs as an accessory app (no Dock icon); closing the window keeps it running, quit from the popover

## Gotchas
- Each probe runs its own independent async loop (`probeOnce`/`scheduleNext`), not a shared refresh timer — a slow target never blocks the others. Refresh interval is per-`ProbeType` (`ProbeType.refreshInterval`), not a single global constant — heavier probes (`HTTPS_GET`, `DNS_AUTH`) refresh less often than `ICMP_ECHO`.
- Probes require system binaries at fixed paths (`/sbin/ping`, `/usr/bin/dig`, `/usr/bin/curl`); missing ones mark a row `CONFIG_BAD` rather than failing the app.
- App version is derived at runtime from `git rev-list --count HEAD` (see `buildNumber`), not hand-bumped — don't add a manual version constant.
- `run.sh` does `git pull origin HEAD` + `rm -rf .build` before building — don't run it with uncommitted local changes you want to keep.
- The graph is time-based: samples are timestamped when a probe completes, and a 60 fps timer only advances `ProbeGraphView.now`. The right edge deliberately shows `now - displayDelay` (4s, just over the slowest cadence) so the newest segment sits between known samples and never reshapes — keep `displayDelay` above the largest `refreshInterval`.
- Performance: no `setShadow` blur in per-frame drawing — CG computes it with a CPU convolution every frame (measured ~77% vs ~30% CPU with the window open); the neon glow is layered translucent strokes instead. The 60 fps frame timer only runs while the dashboard or popover is visible (`startFrameTimer`/`stopFrameTimerIfIdle`, driven by occlusion and popover delegates), the dashboard window is created with `defer: true` and drops its layer contents on close, and the status item image is only rebuilt when overall health changes — keep all of these, they're what keep the menu-bar-idle state near 1% CPU / 16 MB.
