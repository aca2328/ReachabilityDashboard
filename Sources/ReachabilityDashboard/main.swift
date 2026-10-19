import AppKit
import Foundation

enum ProbeType: String, Codable, CaseIterable {
    case icmpEcho = "ICMP_ECHO"
    case dnsRecursor = "DNS_RECURSOR"
    case dnsAuth = "DNS_AUTH"
    case httpsConnect = "HTTPS_CONNECT"
    case httpsGet = "HTTPS_GET"

    var label: String {
        switch self {
        case .icmpEcho: "ICMP"
        case .dnsRecursor: "DNS-REC"
        case .dnsAuth: "DNS-AUTH"
        case .httpsConnect: "HTTPS-C"
        case .httpsGet: "HTTPS-GET"
        }
    }

    // Heavier probes (full HTTPS GET, authoritative root DNS) refresh less
    // often so we don't hammer those targets as hard as a plain ping.
    var refreshInterval: TimeInterval {
        switch self {
        case .icmpEcho: 1.0
        case .dnsRecursor: 1.0
        case .dnsAuth: 3.0
        case .httpsConnect: 2.0
        case .httpsGet: 5.0
        }
    }
}

enum ProbeStatus: String {
    case pending = "PENDING"
    case checking = "CHECKING"
    case ok = "OK"
    case configBad = "CONFIG_BAD"
    case failed = "PROBE_FAIL"
}

struct ProbeTarget: Codable, Equatable {
    let name: String
    let host: String
    let network: String
    let scope: String
    let probe: ProbeType
}

struct ProbeOutcome {
    let status: ProbeStatus
    let latencyMs: Int?
    let error: String?
}

struct ProbeRow {
    let target: ProbeTarget
    var status: ProbeStatus = .pending
    var latencyMs: Int?
    var previousLatencyMs: Int?
    var successCount = 0
    var totalCount = 0
    var lastError: String?
    // Timestamped probe results (nil latency = failed probe), oldest first.
    // The graph positions points by time, so rows with different refresh
    // intervals share one continuously scrolling time axis.
    var samples: [(time: TimeInterval, latency: Int?)] = []

    var successRate: String {
        guard totalCount > 0 else { return "-" }
        return "\(successCount * 100 / totalCount)%"
    }

    var latencyText: String {
        guard let latencyMs else { return "-" }
        return "\(latencyMs) ms"
    }

    var trend: String {
        guard let latencyMs, let previousLatencyMs else { return "-" }
        let delta = latencyMs - previousLatencyMs
        if delta > 5 { return "up" }
        if delta < -5 { return "down" }
        return "flat"
    }
    
    mutating func addSample(_ latency: Int?, at time: TimeInterval) {
        samples.append((time, latency))
    }

    /// Drops samples older than `cutoff`, keeping one just before it so the
    /// line slides in from the left edge instead of popping into view.
    mutating func pruneSamples(before cutoff: TimeInterval) {
        while samples.count > 1, samples[1].time < cutoff {
            samples.removeFirst()
        }
    }
}

enum CommandResult {
    case success(String)
    case failure(String)
}

extension Character {
    var isASCIILetterOrNumber: Bool {
        guard let scalar = unicodeScalars.first, unicodeScalars.count == 1 else { return false }
        return CharacterSet.alphanumerics.contains(scalar)
    }
}

let defaultTargets: [ProbeTarget] = [
    .init(name: "Cloudflare DNS", host: "1.1.1.1", network: "AS13335 / anycast", scope: "global", probe: .dnsRecursor),
    .init(name: "Quad9 DNS", host: "9.9.9.9", network: "AS19281 / anycast", scope: "global", probe: .dnsRecursor),
    .init(name: "Google DNS", host: "8.8.8.8", network: "AS15169 / anycast", scope: "global", probe: .dnsRecursor),
    .init(name: "114DNS China", host: "114.114.114.114", network: "AS38283 / CN", scope: "regional", probe: .dnsRecursor),
    .init(name: "K-root RIPE NCC", host: "193.0.14.129", network: "AS25152 / root", scope: "anycast-root", probe: .dnsAuth),
    .init(name: "M-root WIDE", host: "202.12.27.33", network: "WIDE / root", scope: "anycast-root", probe: .dnsAuth),
    .init(name: "Cloudflare HTTPS", host: "www.cloudflare.com", network: "AS13335 / CDN", scope: "global", probe: .httpsConnect),
    .init(name: "Deutsche Telekom", host: "194.25.0.60", network: "AS3320 / DE", scope: "operator", probe: .icmpEcho),
    .init(name: "Hurricane Electric", host: "184.105.213.138", network: "AS6939 / US", scope: "operator", probe: .icmpEcho),
    .init(name: "LACNIC", host: "200.3.14.1", network: "AS28001 / UY", scope: "operator", probe: .icmpEcho)
]

/// Persists the user-edited target list as JSON in Application Support, so
/// `swift run` and the .app bundle share it (UserDefaults domains would differ).
enum TargetStore {
    static let fileURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("ReachabilityDashboard/targets.json")

    /// The saved list, or `defaultTargets` if there is none or it can't be
    /// decoded. A bad file is left in place, never overwritten on load.
    static func load() -> [ProbeTarget] {
        guard let data = try? Data(contentsOf: fileURL),
              let targets = try? JSONDecoder().decode([ProbeTarget].self, from: data) else {
            return defaultTargets
        }
        return targets
    }

    static func save(_ targets: [ProbeTarget]) throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(targets).write(to: fileURL, options: .atomic)
    }
}

final class CommandRunner {
    static func run(_ launchPath: String, _ arguments: [String], timeout: TimeInterval) -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments

        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error

        let lock = NSLock()
        var didTimeout = false
        let timeoutWork = DispatchWorkItem {
            lock.lock()
            didTimeout = true
            lock.unlock()
            if process.isRunning {
                process.terminate()
            }
        }

        do {
            try process.run()
        } catch {
            return .failure("cannot run \(launchPath): \(error.localizedDescription)")
        }

        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timeoutWork)
        process.waitUntilExit()
        timeoutWork.cancel()

        lock.lock()
        let timedOut = didTimeout
        lock.unlock()

        if timedOut {
            return .failure("timeout")
        }

        let outData = output.fileHandleForReading.readDataToEndOfFile()
        let errData = error.fileHandleForReading.readDataToEndOfFile()
        let out = String(data: outData, encoding: .utf8) ?? ""
        let err = String(data: errData, encoding: .utf8) ?? ""

        guard process.terminationStatus == 0 else {
            return .failure(err.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "exit \(process.terminationStatus)" : err)
        }

        return .success(out)
    }
}


final class ProbeEngine: @unchecked Sendable {
    private let timeout: TimeInterval

    init(timeout: TimeInterval) {
        self.timeout = timeout
    }

    func validate(_ target: ProbeTarget) -> String? {
        guard isIPv4(target.host) || isHostname(target.host) else {
            return "bad target"
        }

        switch target.probe {
        case .icmpEcho:
            return executableExists("/sbin/ping") ? nil : "missing ping"
        case .dnsRecursor, .dnsAuth:
            guard isIPv4(target.host) else { return "DNS probe target must be IP" }
            return executableExists("/usr/bin/dig") ? nil : "missing dig"
        case .httpsConnect, .httpsGet:
            return executableExists("/usr/bin/curl") ? nil : "missing curl"
        }
    }

    func run(_ target: ProbeTarget) -> ProbeOutcome {
        if let validationError = validate(target) {
            return .init(status: .configBad, latencyMs: nil, error: validationError)
        }

        switch target.probe {
        case .icmpEcho:
            return ping(target.host)
        case .dnsRecursor:
            return dig(target.host, arguments: ["+tries=1", "+time=\(Int(timeout))", "@\(target.host)", "example.com", "A"], requireNoError: true)
        case .dnsAuth:
            return dig(target.host, arguments: ["+tries=1", "+time=\(Int(timeout))", "+norecurse", "@\(target.host)", ".", "NS"], requireNoError: false)
        case .httpsConnect:
            return curl(target.host, metric: .connect)
        case .httpsGet:
            return curl(target.host, metric: .total)
        }
    }

    private func ping(_ host: String) -> ProbeOutcome {
        let timeoutArgument: String
        if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 0 {
            timeoutArgument = "\(Int(timeout * 1000))"
        } else {
            timeoutArgument = "\(Int(timeout))"
        }

        let result = CommandRunner.run("/sbin/ping", ["-c", "1", "-W", timeoutArgument, host], timeout: timeout + 1)
        guard case let .success(output) = result else {
            return failure(from: result)
        }

        return parsePingOutput(output)
    }

    func parsePingOutput(_ output: String) -> ProbeOutcome {
        if let latency = firstMatch(in: output, pattern: #"time=([0-9.]+)"#).flatMap(milliseconds) {
            return .init(status: .ok, latencyMs: latency, error: nil)
        }

        return .init(status: .failed, latencyMs: nil, error: "no RTT in ping output")
    }

    private func dig(_ host: String, arguments: [String], requireNoError: Bool) -> ProbeOutcome {
        let result = CommandRunner.run("/usr/bin/dig", arguments, timeout: timeout + 1)
        guard case let .success(output) = result else {
            return failure(from: result)
        }

        return parseDigOutput(output, requireNoError: requireNoError)
    }

    func parseDigOutput(_ output: String, requireNoError: Bool) -> ProbeOutcome {
        if requireNoError, !output.contains("status: NOERROR") {
            return .init(status: .failed, latencyMs: nil, error: "DNS status not NOERROR")
        }

        if !requireNoError, !(output.contains("status: NOERROR") || output.contains("status: REFUSED")) {
            return .init(status: .failed, latencyMs: nil, error: "unexpected authoritative DNS status")
        }

        if let latency = firstMatch(in: output, pattern: #"Query time: ([0-9]+) msec"#).flatMap(Int.init) {
            return .init(status: .ok, latencyMs: latency, error: nil)
        }

        return .init(status: .failed, latencyMs: nil, error: "no query time")
    }

    enum CurlMetric {
        case connect
        case total
    }

    private func curl(_ host: String, metric: CurlMetric) -> ProbeOutcome {
        let format = "%{time_connect} %{time_appconnect} %{time_total} %{http_code}"
        let result = CommandRunner.run(
            "/usr/bin/curl",
            ["--silent", "--output", "/dev/null", "--max-time", "\(Int(timeout))", "--write-out", format, "https://\(host)/"],
            timeout: timeout + 1
        )

        guard case let .success(output) = result else {
            return failure(from: result)
        }

        return parseCurlOutput(output, metric: metric)
    }

    func parseCurlOutput(_ output: String, metric: CurlMetric) -> ProbeOutcome {
        let parts = output.split(separator: " ").map(String.init)
        guard parts.count == 4 else {
            return .init(status: .failed, latencyMs: nil, error: "bad curl metrics")
        }

        guard let statusCode = Int(parts[3]), (200..<500).contains(statusCode) else {
            return .init(status: .failed, latencyMs: nil, error: "bad HTTP status")
        }

        let seconds: Double?
        switch metric {
        case .connect:
            seconds = Double(parts[1]).flatMap { $0 > 0 ? $0 : Double(parts[0]) }
        case .total:
            seconds = Double(parts[2])
        }

        guard let seconds else {
            return .init(status: .failed, latencyMs: nil, error: "bad curl timing")
        }

        return .init(status: .ok, latencyMs: Int((seconds * 1000).rounded()), error: nil)
    }

    private func failure(from result: CommandResult) -> ProbeOutcome {
        if case let .failure(error) = result {
            return .init(status: .failed, latencyMs: nil, error: error)
        }
        return .init(status: .failed, latencyMs: nil, error: "unknown failure")
    }

    private func executableExists(_ path: String) -> Bool {
        FileManager.default.isExecutableFile(atPath: path)
    }

    func isIPv4(_ value: String) -> Bool {
        let parts = value.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            guard let octet = Int(part) else { return false }
            return octet >= 0 && octet <= 255
        }
    }

    func isHostname(_ value: String) -> Bool {
        guard value.count <= 253, value.contains(".") else { return false }
        let labels = value.split(separator: ".")
        return labels.allSatisfy { label in
            guard !label.isEmpty, label.count <= 63 else { return false }
            guard label.first?.isASCIILetterOrNumber == true, label.last?.isASCIILetterOrNumber == true else { return false }
            return label.allSatisfy { $0.isASCIILetterOrNumber || $0 == "-" }
        }
    }

    private func firstMatch(in text: String, pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, range: range), match.numberOfRanges > 1 else { return nil }
        guard let swiftRange = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[swiftRange])
    }

    private func milliseconds(_ value: String) -> Int? {
        Double(value).map { Int($0.rounded()) }
    }
}

/// A y-axis range that eases toward its target each frame instead of
/// snapping. Shared by the main graph and the popover sparklines.
struct EasedRange {
    private var shownMin: CGFloat?
    private var shownMax: CGFloat?
    private var lastTime: TimeInterval?

    mutating func update(min targetMin: CGFloat, max targetMax: CGFloat, at now: TimeInterval) -> (CGFloat, CGFloat) {
        let dt = lastTime.map { now - $0 } ?? .infinity
        lastTime = now
        // First frame, or the view was hidden for a while: jump straight there.
        guard let currentMin = shownMin, let currentMax = shownMax, dt < 1 else {
            shownMin = targetMin
            shownMax = targetMax
            return (targetMin, targetMax)
        }
        // Expand fast so a new peak stays on the canvas; contract slowly so
        // the axis doesn't pump as small spikes come and go.
        func step(_ current: CGFloat, toward target: CGFloat, expanding: Bool) -> CGFloat {
            let timeConstant: TimeInterval = expanding ? 0.15 : 0.8
            return current + (target - current) * CGFloat(1 - exp(-dt / timeConstant))
        }
        let newMin = step(currentMin, toward: targetMin, expanding: targetMin < currentMin)
        let newMax = step(currentMax, toward: targetMax, expanding: targetMax > currentMax)
        shownMin = newMin
        shownMax = newMax
        return (newMin, newMax)
    }
}

final class ProbeGraphView: NSView {
    var rows: [ProbeRow] = []
    /// Current time (system uptime); advanced every frame so lines scroll
    /// continuously rather than stepping when a sample arrives.
    var now: TimeInterval = ProcessInfo.processInfo.systemUptime

    /// Seconds of history visible across the graph's width.
    static let visibleWindow: TimeInterval = 60
    /// The right edge shows the state from this many seconds ago — a bit more
    /// than the slowest probe cadence (DNS_AUTH, 3s) — so the newest stretch of
    /// line is almost always between two known samples and never reshapes.
    static let displayDelay: TimeInterval = 4

    // Displayed y-range, eased so the axis glides instead of snapping when a
    // spike enters or scrolls off.
    private var yRange = EasedRange()

    static let colors: [NSColor] = [
        .systemRed, .systemBlue, .systemGreen, .systemOrange, .systemPurple,
        .systemYellow, .systemPink, .systemTeal, .systemCyan, .systemBrown,
        .systemIndigo, .systemGray
    ]

    private let backgroundColor = NSColor(calibratedRed: 0.055, green: 0.067, blue: 0.10, alpha: 1)
    private let gridColor = NSColor(calibratedRed: 1, green: 1, blue: 1, alpha: 0.07)
    private let axisTextColor = NSColor(calibratedRed: 1, green: 1, blue: 1, alpha: 0.45)

    override func draw(_ dirtyRect: NSRect) {
        guard let ctx = NSGraphicsContext.current?.cgContext else { return }

        let bounds = self.bounds

        // Dark rounded canvas.
        let canvas = NSBezierPath(roundedRect: bounds, xRadius: 14, yRadius: 14)
        backgroundColor.setFill()
        canvas.fill()

        guard !rows.isEmpty else { return }

        let leftPad: CGFloat = 64
        let topPad: CGFloat = 48
        let bottomPad: CGFloat = 32
        let labelGutter: CGFloat = 180
        let rightPad: CGFloat = 16
        let graphRect = NSRect(
            x: leftPad,
            y: bottomPad,
            width: bounds.width - leftPad - labelGutter - rightPad,
            height: bounds.height - topPad - bottomPad
        )
        guard graphRect.width > 40, graphRect.height > 40 else { return }

        drawTitle("LATENCY OVER TIME", at: CGPoint(x: leftPad, y: bounds.maxY - 32))

        let span = ProbeGraphView.visibleWindow
        let headTime = now - ProbeGraphView.displayDelay

        // Range over every stored sample, not just the visible ones: samples
        // newer than headTime are known ~displayDelay before the line reaches
        // them, so the eased range finishes expanding before a peak scrolls
        // in; and pruning keeps only ~one sample past the left edge, whose
        // curve is still partly on screen. Either way, no overshoot.
        let allLatencies = rows.flatMap { row in row.samples.compactMap { $0.latency } }
        let rawMax = allLatencies.max() ?? 100
        let rawMin = allLatencies.min() ?? 0
        let (minLatency, maxLatency) = yRange.update(
            min: max(0, CGFloat(rawMin) - CGFloat(max(rawMax - rawMin, 10)) * 0.05),
            max: CGFloat(rawMax) + CGFloat(max(rawMax - rawMin, 10)) * 0.12,
            at: now
        )
        let latencyRange = max(maxLatency - minLatency, 1)

        func point(_ time: TimeInterval, _ value: Int) -> CGPoint {
            let x = graphRect.maxX - CGFloat((headTime - time) / span) * graphRect.width
            let y = graphRect.minY + (CGFloat(value) - minLatency) / latencyRange * graphRect.height
            return CGPoint(x: x, y: y)
        }

        drawGrid(ctx, in: graphRect, minLatency: minLatency, latencyRange: latencyRange)

        let colorSpace = CGColorSpaceCreateDeviceRGB()

        var labels: [FloatingLabel] = []

        // Lines extend past both edges of the plot (older samples on the left,
        // samples newer than headTime on the right); clip them horizontally.
        ctx.saveGState()
        ctx.clip(to: NSRect(x: graphRect.minX, y: bounds.minY, width: graphRect.width, height: bounds.height))

        for (rowIndex, row) in rows.enumerated() {
            let color = Self.colors[rowIndex % Self.colors.count]
            // Split into contiguous segments so failed probes break the line
            // instead of plunging it to the floor.
            var segments: [[CGPoint]] = []
            var current: [CGPoint] = []
            for sample in row.samples {
                if let latency = sample.latency {
                    current.append(point(sample.time, latency))
                } else if !current.isEmpty {
                    segments.append(current)
                    current = []
                }
            }
            // A late probe holds its last value flat up to the right edge.
            if let last = row.samples.last, let latency = last.latency, last.time < headTime {
                current.append(point(headTime, latency))
            }
            if !current.isEmpty { segments.append(current) }
            guard !segments.isEmpty else { continue }

            for pts in segments {
                drawAreaFill(ctx, points: pts, baseline: graphRect.minY,
                             top: graphRect.maxY, color: color, colorSpace: colorSpace)
                drawGlowLine(ctx, points: pts, color: color)
            }

            // The line's visible end: where it crosses the right edge, or where
            // its last segment stops if the probe has been failing since.
            guard let segment = segments.last(where: { $0[0].x <= graphRect.maxX }),
                  let end = curvePoint(on: segment, atX: graphRect.maxX) ?? segment.last(where: { $0.x <= graphRect.maxX }),
                  end.x >= graphRect.minX else { continue }
            labels.append(FloatingLabel(text: labelText(for: row), color: color,
                                        anchor: end, active: row.status == .ok))
        }

        ctx.restoreGState()

        for label in labels {
            drawEndDot(ctx, at: label.anchor, color: label.color)
        }

        drawFloatingLabels(ctx, labels, graphRect: graphRect)
    }

    private struct FloatingLabel {
        let text: String
        let color: NSColor
        let anchor: CGPoint
        let active: Bool
    }

    private func labelText(for row: ProbeRow) -> String {
        let arrow: String
        switch row.trend {
        case "up": arrow = " ↑"
        case "down": arrow = " ↓"
        case "flat": arrow = " ↔"
        default: arrow = ""
        }
        if let latency = row.latencyMs {
            return "\(row.target.name)  \(latency) ms\(arrow)"
        }
        return row.target.name
    }

    /// Draws each probe's label floating next to the end of its line. Labels
    /// are nudged apart vertically so they stay readable when lines cluster,
    /// with a faint connector back to the line's last point.
    private func drawFloatingLabels(_ ctx: CGContext, _ labels: [FloatingLabel], graphRect: NSRect) {
        guard !labels.isEmpty else { return }
        let font = NSFont.systemFont(ofSize: 11, weight: .medium)
        let lineHeight = font.ascender - font.descender
        let minGap = lineHeight + 4
        let labelX = graphRect.maxX + 14

        // Resolve vertical collisions from the top down.
        let placed = labels.sorted { $0.anchor.y > $1.anchor.y }
        var ys = placed.map { $0.anchor.y }
        for i in 1..<ys.count where ys[i - 1] - ys[i] < minGap {
            ys[i] = ys[i - 1] - minGap
        }
        // Keep the stack inside the canvas.
        let overflow = graphRect.minY - (ys.last ?? graphRect.minY)
        if overflow > 0 { for i in ys.indices { ys[i] += overflow } }

        for (i, label) in placed.enumerated() {
            let y = ys[i]
            let dim: CGFloat = label.active ? 1.0 : 0.4

            // Connector from the line's end point to the label.
            ctx.saveGState()
            ctx.setStrokeColor(label.color.withAlphaComponent(0.35 * dim).cgColor)
            ctx.setLineWidth(1)
            ctx.move(to: label.anchor)
            ctx.addLine(to: CGPoint(x: labelX - 4, y: y))
            ctx.strokePath()
            ctx.restoreGState()

            NSAttributedString(string: label.text, attributes: [
                .font: font,
                .foregroundColor: label.color.withAlphaComponent(dim)
            ]).draw(at: CGPoint(x: labelX, y: y - lineHeight / 2))
        }
    }

    private func drawTitle(_ text: String, at origin: CGPoint) {
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 13, weight: .semibold),
            .foregroundColor: NSColor(calibratedRed: 1, green: 1, blue: 1, alpha: 0.75),
            .kern: 2.0
        ]
        NSAttributedString(string: text, attributes: attrs)
            .draw(at: origin)
    }

    private func drawGrid(_ ctx: CGContext, in rect: NSRect, minLatency: CGFloat, latencyRange: CGFloat) {
        ctx.setLineWidth(1)
        for i in 0...5 {
            let y = rect.minY + CGFloat(i) * rect.height / 5
            ctx.setStrokeColor(gridColor.cgColor)
            ctx.move(to: CGPoint(x: rect.minX, y: y))
            ctx.addLine(to: CGPoint(x: rect.maxX, y: y))
            ctx.strokePath()

            let value = Int((minLatency + latencyRange * CGFloat(i) / 5).rounded())
            let label = NSAttributedString(string: "\(value) ms", attributes: [
                .font: NSFont.monospacedDigitSystemFont(ofSize: 10, weight: .regular),
                .foregroundColor: axisTextColor
            ])
            let size = label.size()
            label.draw(at: CGPoint(x: rect.minX - size.width - 8, y: y - size.height / 2))
        }
    }

    private func drawAreaFill(_ ctx: CGContext, points: [CGPoint], baseline: CGFloat,
                              top: CGFloat, color: NSColor, colorSpace: CGColorSpace) {
        guard points.count >= 2 else { return }
        ctx.saveGState()
        let fill = CGMutablePath()
        fill.move(to: CGPoint(x: points[0].x, y: baseline))
        fill.addLine(to: points[0])
        Self.addSmoothCurve(to: fill, through: points)
        fill.addLine(to: CGPoint(x: points.last!.x, y: baseline))
        fill.closeSubpath()
        ctx.addPath(fill)
        ctx.clip()

        let gradient = CGGradient(colorsSpace: colorSpace,
                                  colors: [color.withAlphaComponent(0.40).cgColor,
                                           color.withAlphaComponent(0.0).cgColor] as CFArray,
                                  locations: [0, 1])!
        ctx.drawLinearGradient(gradient,
                               start: CGPoint(x: 0, y: top),
                               end: CGPoint(x: 0, y: baseline),
                               options: [])
        ctx.restoreGState()
    }

    private func drawGlowLine(_ ctx: CGContext, points: [CGPoint], color: NSColor) {
        guard !points.isEmpty else { return }
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: 9, color: color.withAlphaComponent(0.9).cgColor)
        ctx.setStrokeColor(color.cgColor)
        ctx.setLineWidth(2.5)
        ctx.setLineJoin(.round)
        ctx.setLineCap(.round)
        let line = CGMutablePath()
        line.move(to: points[0])
        Self.addSmoothCurve(to: line, through: points)
        ctx.addPath(line)
        ctx.strokePath()
        ctx.restoreGState()

        if points.count == 1 {
            drawEndDot(ctx, at: points[0], color: color)
        }
    }

    /// Appends a Catmull-Rom spline through `points` to `path`, which must
    /// already be positioned at `points[0]`. Produces smooth curved lines.
    static func addSmoothCurve(to path: CGMutablePath, through points: [CGPoint]) {
        guard points.count > 1 else { return }
        guard points.count > 2 else {
            path.addLine(to: points[1])
            return
        }
        for i in 0..<(points.count - 1) {
            let (c1, c2) = Self.controlPoints(points, segment: i)
            path.addCurve(to: points[i + 1], control1: c1, control2: c2)
        }
    }

    /// Bezier control points of the Catmull-Rom segment from points[i] to points[i + 1].
    private static func controlPoints(_ points: [CGPoint], segment i: Int) -> (CGPoint, CGPoint) {
        let p0 = points[max(i - 1, 0)]
        let p1 = points[i]
        let p2 = points[i + 1]
        let p3 = points[min(i + 2, points.count - 1)]
        let c1 = CGPoint(x: p1.x + (p2.x - p0.x) / 6.0, y: p1.y + (p2.y - p0.y) / 6.0)
        let c2 = CGPoint(x: p2.x - (p3.x - p1.x) / 6.0, y: p2.y - (p3.y - p1.y) / 6.0)
        return (c1, c2)
    }

    /// The point where the smooth curve through `points` crosses `x`, so the
    /// end dot sits exactly on the drawn line. Nil if the curve doesn't span `x`.
    private func curvePoint(on points: [CGPoint], atX x: CGFloat) -> CGPoint? {
        guard points.count >= 2,
              let i = points.indices.dropLast().first(where: { points[$0].x <= x && x <= points[$0 + 1].x })
        else { return nil }
        let p1 = points[i]
        let p2 = points[i + 1]
        guard points.count > 2 else {
            let t = p2.x > p1.x ? (x - p1.x) / (p2.x - p1.x) : 1
            return CGPoint(x: x, y: p1.y + (p2.y - p1.y) * t)
        }
        let (c1, c2) = Self.controlPoints(points, segment: i)
        // x(t) is close to linear for evenly spaced samples, so use the x
        // fraction as the curve parameter.
        let t = p2.x > p1.x ? (x - p1.x) / (p2.x - p1.x) : 1
        let u = 1 - t
        let y = u * u * u * p1.y + 3 * u * u * t * c1.y + 3 * u * t * t * c2.y + t * t * t * p2.y
        return CGPoint(x: x, y: y)
    }

    private func drawEndDot(_ ctx: CGContext, at point: CGPoint, color: NSColor) {
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: 12, color: color.cgColor)
        ctx.setFillColor(color.cgColor)
        let r: CGFloat = 4
        ctx.fillEllipse(in: CGRect(x: point.x - r, y: point.y - r, width: r * 2, height: r * 2))
        ctx.restoreGState()

        ctx.setFillColor(NSColor.white.withAlphaComponent(0.9).cgColor)
        ctx.fillEllipse(in: CGRect(x: point.x - 1.5, y: point.y - 1.5, width: 3, height: 3))
    }

}

/// A miniature, single-row version of `ProbeGraphView` for the menu bar
/// popover. Shares its time axis (window and display delay) and line color,
/// but scales y to its own row so small latencies stay readable.
final class SparklineView: NSView {
    var samples: [(time: TimeInterval, latency: Int?)] = []
    var now: TimeInterval = ProcessInfo.processInfo.systemUptime
    var color: NSColor = .systemBlue
    private var yRange = EasedRange()

    override var intrinsicContentSize: NSSize { NSSize(width: 120, height: 22) }

    override func draw(_ dirtyRect: NSRect) {
        guard let ctx = NSGraphicsContext.current?.cgContext else { return }
        let rect = bounds.insetBy(dx: 0, dy: 3)
        let span = ProbeGraphView.visibleWindow
        let headTime = now - ProbeGraphView.displayDelay

        // Range over every stored sample, as in ProbeGraphView, so peaks never
        // overshoot the view at either edge.
        let latencies = samples.compactMap { $0.latency }
        guard let rawMin = latencies.min(), let rawMax = latencies.max() else { return }
        let (minLatency, maxLatency) = yRange.update(
            min: CGFloat(rawMin),
            max: CGFloat(rawMin + max(rawMax - rawMin, 4)),
            at: now
        )
        let range = max(maxLatency - minLatency, 1)

        func point(_ time: TimeInterval, _ value: Int) -> CGPoint {
            CGPoint(x: rect.maxX - CGFloat((headTime - time) / span) * rect.width,
                    y: rect.minY + (CGFloat(value) - minLatency) / range * rect.height)
        }

        // Same segmenting as the main graph: failures break the line, and a
        // late probe holds its last value flat to the right edge.
        var segments: [[CGPoint]] = []
        var current: [CGPoint] = []
        for sample in samples {
            if let latency = sample.latency {
                current.append(point(sample.time, latency))
            } else if !current.isEmpty {
                segments.append(current)
                current = []
            }
        }
        if let last = samples.last, let latency = last.latency, last.time < headTime {
            current.append(point(headTime, latency))
        }
        if !current.isEmpty { segments.append(current) }

        ctx.clip(to: bounds)
        ctx.setStrokeColor(color.cgColor)
        ctx.setLineWidth(1.5)
        ctx.setLineJoin(.round)
        ctx.setLineCap(.round)
        for pts in segments where pts.count >= 2 {
            let line = CGMutablePath()
            line.move(to: pts[0])
            ProbeGraphView.addSmoothCurve(to: line, through: pts)
            ctx.addPath(line)
        }
        ctx.strokePath()
    }
}

@MainActor
final class DashboardController: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private var window: NSWindow!
    private var graphView: ProbeGraphView!
    private var footerLabel: NSTextField!
    private var refreshButton: NSButton!
    private var versionLabel: NSTextField!
    private var rows: [ProbeRow] = TargetStore.load().map { ProbeRow(target: $0) }
    private let engine = ProbeEngine(timeout: 3)
    // Each probe runs its own independent loop, so a slow target never blocks
    // the others. `inFlight`/`scheduled` keep a single loop alive per probe.
    private var inFlight: [Bool] = []
    private var scheduled: [DispatchWorkItem?] = []
    // Bumped whenever the target list is replaced. All per-probe state is
    // indexed by position, so results from probes started under an older list
    // are discarded instead of landing on the wrong (or a missing) row.
    private var generation = 0
    private lazy var targetEditor = TargetEditorController(engine: engine, probeQueue: probeQueue)
    private let probeQueue = DispatchQueue(label: "probes", qos: .utility, attributes: .concurrent)
    // Redraws the graph every frame so it scrolls continuously; samples are
    // only recorded when a probe completes.
    private var frameTimer: Timer?
    // Menu bar presence: the app has no Dock icon and lives here instead.
    private var statusItem: NSStatusItem!
    private let popover = NSPopover()
    private var popoverDots: [NSTextField] = []
    private var popoverLatencies: [NSTextField] = []
    private var popoverSparklines: [SparklineView] = []
    private var popoverSummary: NSTextField!
    private var outsideClickMonitor: Any?

    private var buildNumber: Int {
        // Inside a .app bundle (built by bundle.sh) the working directory isn't
        // the repo, so the git count is baked into Info.plist at bundle time.
        if let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
           let intValue = Int(version) {
            return intValue
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["rev-list", "--count", "HEAD"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            if let count = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
               let intValue = Int(count) {
                return intValue
            }
        } catch {
            return 0
        }
        return 0
    }
    
    private var versionString: String {
        "v1.0.\(buildNumber)"
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildWindow()
        buildStatusItem()
        startProbing()
        // .common mode keeps frames coming during live resize; assumeIsolated
        // (not a Task per frame) avoids scheduling jitter.
        let timer = Timer(timeInterval: 1.0 / 60.0, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.renderFrame() }
        }
        RunLoop.main.add(timer, forMode: .common)
        frameTimer = timer
    }

    // Closing the window just hides it; the app keeps probing in the menu bar.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    private func buildWindow() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1120, height: 620),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Operator Peering Quality Dashboard"
        window.isReleasedWhenClosed = false
        window.center()

        let root = NSStackView()
        root.orientation = .vertical
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        root.translatesAutoresizingMaskIntoConstraints = false

        let title = NSTextField(labelWithString: "Operator Peering Quality")
        title.font = .systemFont(ofSize: 24, weight: .semibold)

        let version = NSTextField(labelWithString: "")
        version.font = .systemFont(ofSize: 11)
        version.textColor = .secondaryLabelColor

        let subtitle = NSTextField(labelWithString: "Native macOS probe dashboard for ICMP, DNS, and HTTPS path quality.")
        subtitle.textColor = .secondaryLabelColor

        let subtitleLine = NSStackView(views: [version, subtitle])
        subtitleLine.orientation = .horizontal
        subtitleLine.spacing = 8
        subtitleLine.alignment = .centerY

        let header = NSStackView(views: [title, subtitleLine])
        header.orientation = .vertical
        header.spacing = 4
        
        self.versionLabel = version
        updateVersionLabel()

        refreshButton = NSButton(title: "Refresh Now", target: self, action: #selector(refreshNow))
        refreshButton.bezelStyle = .rounded

        footerLabel = NSTextField(labelWithString: "Starting...")
        footerLabel.textColor = .secondaryLabelColor

        let controls = NSStackView(views: [footerLabel, NSView(), refreshButton])
        controls.orientation = .horizontal
        controls.alignment = .centerY
        controls.spacing = 12

        graphView = ProbeGraphView()
        graphView.wantsLayer = true
        graphView.rows = rows
        graphView.translatesAutoresizingMaskIntoConstraints = false

        let scrollView = NSScrollView()
        scrollView.documentView = graphView
        scrollView.hasVerticalScroller = false
        scrollView.hasHorizontalScroller = false
        scrollView.borderType = .bezelBorder

        // Pin the graph to fill the visible area so the dark canvas always
        // covers the bezel and the chart scales to the window.
        NSLayoutConstraint.activate([
            graphView.leadingAnchor.constraint(equalTo: scrollView.contentView.leadingAnchor),
            graphView.trailingAnchor.constraint(equalTo: scrollView.contentView.trailingAnchor),
            graphView.topAnchor.constraint(equalTo: scrollView.contentView.topAnchor),
            graphView.bottomAnchor.constraint(equalTo: scrollView.contentView.bottomAnchor)
        ])

        root.addArrangedSubview(header)
        root.addArrangedSubview(scrollView)
        root.addArrangedSubview(controls)

        window.contentView = root
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor),
            root.topAnchor.constraint(equalTo: window.contentView!.topAnchor),
            root.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor),
            scrollView.heightAnchor.constraint(greaterThanOrEqualToConstant: 420)
        ])
        // Not shown at launch: the app starts as a menu bar icon only, and the
        // window appears via "Open Dashboard".
    }

    /// (Re)starts every probe's loop for the current `rows`.
    private func startProbing() {
        validateRows()
        inFlight = Array(repeating: false, count: rows.count)
        scheduled = Array(repeating: nil, count: rows.count)
        for index in rows.indices where rows[index].status != .configBad {
            probeOnce(index)
        }
    }

    /// Swaps in an edited target list at runtime. Targets whose host and probe
    /// type are unchanged keep their graph history.
    private func applyTargets(_ targets: [ProbeTarget]) {
        generation += 1
        scheduled.forEach { $0?.cancel() }
        let old = rows
        rows = targets.map { target in
            var row = ProbeRow(target: target)
            if let previous = old.first(where: { $0.target.host == target.host && $0.target.probe == target.probe }) {
                row.samples = previous.samples
            }
            return row
        }
        rebuildPopover()
        startProbing()
        graphView.rows = rows
        updateFooter()
    }

    private func validateRows() {
        for index in rows.indices {
            if let error = engine.validate(rows[index].target) {
                rows[index].status = ProbeStatus.configBad
                rows[index].lastError = error
            }
        }
        graphView.needsDisplay = true
        updateStatusItem()
    }
    
    private func updateVersionLabel() {
        versionLabel.stringValue = versionString
    }

    @objc private func refreshNow() {
        for index in rows.indices where rows[index].status != .configBad {
            scheduled[index]?.cancel()
            scheduled[index] = nil
            probeOnce(index)
        }
    }

    /// Runs a single probe for one target off the main thread, then applies
    /// the result and schedules this probe's next run — independently of every
    /// other probe. `inFlight` guards against overlapping runs of the same one.
    private func probeOnce(_ index: Int) {
        guard !inFlight[index] else { return }
        inFlight[index] = true

        let target = rows[index].target
        let engine = self.engine
        let generation = self.generation
        probeQueue.async {
            let outcome = engine.run(target)
            Task { @MainActor in
                guard generation == self.generation else { return }
                self.inFlight[index] = false
                self.apply(outcome, at: index)
                self.scheduleNext(index)
            }
        }
    }

    private func scheduleNext(_ index: Int) {
        scheduled[index]?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.probeOnce(index) }
        scheduled[index] = work
        let interval = rows[index].target.probe.refreshInterval
        DispatchQueue.main.asyncAfter(deadline: .now() + interval, execute: work)
    }

    /// Advances the graph's clock and redraws it — only while the window is
    /// actually on screen, so the menu-bar-only state stays near idle.
    private func renderFrame() {
        let now = ProcessInfo.processInfo.systemUptime
        if popover.isShown {
            for sparkline in popoverSparklines {
                sparkline.now = now
                sparkline.needsDisplay = true
            }
        }
        guard window.isVisible, window.occlusionState.contains(.visible) else { return }
        graphView.now = now
        graphView.needsDisplay = true
    }

    private func apply(_ outcome: ProbeOutcome, at index: Int) {
        rows[index].totalCount += 1
        rows[index].status = outcome.status
        rows[index].lastError = outcome.error

        if outcome.status == .ok {
            rows[index].successCount += 1
            rows[index].previousLatencyMs = rows[index].latencyMs
            rows[index].latencyMs = outcome.latencyMs
        } else {
            rows[index].latencyMs = nil
        }
        let now = ProcessInfo.processInfo.systemUptime
        rows[index].addSample(rows[index].latencyMs, at: now)
        rows[index].pruneSamples(before: now - ProbeGraphView.displayDelay - ProbeGraphView.visibleWindow)

        graphView.rows = rows
        updateFooter()
        updateStatusItem()
    }

    private func buildStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.button?.target = self
        statusItem.button?.action = #selector(togglePopover)
        popover.behavior = .transient
        popover.delegate = self
        rebuildPopover()
    }

    /// Builds the popover content for the current `rows`; called again
    /// whenever the target list is edited.
    private func rebuildPopover() {
        popoverDots = []
        popoverSparklines = []
        popoverLatencies = []

        let title = NSTextField(labelWithString: "Operator Peering Quality")
        title.font = .systemFont(ofSize: 13, weight: .semibold)

        popoverSummary = NSTextField(labelWithString: "Starting...")
        popoverSummary.font = .systemFont(ofSize: 11)
        popoverSummary.textColor = .secondaryLabelColor

        let grid = NSGridView()
        grid.rowSpacing = 4
        grid.columnSpacing = 8
        for (index, row) in rows.enumerated() {
            let dot = NSTextField(labelWithString: "●")
            let name = NSTextField(labelWithString: row.target.name)
            let sparkline = SparklineView()
            sparkline.color = ProbeGraphView.colors[index % ProbeGraphView.colors.count]
            let latency = NSTextField(labelWithString: "-")
            latency.font = .monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
            latency.alignment = .right
            grid.addRow(with: [dot, name, sparkline, latency])
            popoverDots.append(dot)
            popoverSparklines.append(sparkline)
            popoverLatencies.append(latency)
        }
        grid.rowAlignment = .none
        for index in 0..<grid.numberOfRows { grid.row(at: index).yPlacement = .center }
        if grid.numberOfColumns > 3 {
            grid.column(at: 3).xPlacement = .trailing
        }

        let openButton = NSButton(title: "Open Dashboard", target: self, action: #selector(openDashboard))
        openButton.bezelStyle = .rounded
        openButton.keyEquivalent = "\r"
        let editButton = NSButton(title: "Edit Targets…", target: self, action: #selector(editTargets))
        editButton.bezelStyle = .rounded
        let quitButton = NSButton(title: "Quit", target: self, action: #selector(quit))
        quitButton.bezelStyle = .rounded
        let buttons = NSStackView(views: [quitButton, NSView(), editButton, openButton])
        buttons.orientation = .horizontal

        let stack = NSStackView(views: [title, popoverSummary, grid, buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 14)
        buttons.widthAnchor.constraint(greaterThanOrEqualTo: grid.widthAnchor).isActive = true

        let content = NSViewController()
        content.view = stack
        popover.contentViewController = content

        updateStatusItem()
    }

    /// Recolors the menu bar icon by overall health and refreshes the popover:
    /// green = all probes OK, orange = some failing, red = all failing,
    /// gray = no results yet.
    private func updateStatusItem() {
        guard statusItem != nil else { return }
        let active = rows.filter { $0.status != .configBad }
        let ok = active.filter { $0.status == .ok }.count
        let failed = active.filter { $0.status == .failed }.count
        let health: NSColor
        if ok + failed == 0 {
            health = .systemGray
        } else if failed == 0 {
            health = .systemGreen
        } else if ok == 0 {
            health = .systemRed
        } else {
            health = .systemOrange
        }
        let config = NSImage.SymbolConfiguration(pointSize: 14, weight: .medium)
            .applying(NSImage.SymbolConfiguration(paletteColors: [health]))
        statusItem.button?.image = NSImage(systemSymbolName: "antenna.radiowaves.left.and.right",
                                           accessibilityDescription: "Reachability")?
            .withSymbolConfiguration(config)

        popoverSummary.stringValue = footerLabel.stringValue
        for (index, row) in rows.enumerated() where index < popoverDots.count {
            popoverDots[index].textColor = switch row.status {
            case .ok: .systemGreen
            case .failed: .systemRed
            case .configBad: .systemGray
            case .pending, .checking: .tertiaryLabelColor
            }
            popoverLatencies[index].stringValue = row.status == .configBad ? "config bad" : row.latencyText
            popoverSparklines[index].samples = row.samples
        }
    }

    @objc private func togglePopover() {
        if popover.isShown {
            popover.performClose(nil)
        } else if let button = statusItem.button {
            // Deliberately not activating the app: that would raise the
            // dashboard and editor windows along with the popover. Without
            // activation, transient popovers don't see clicks in other apps,
            // so close on those via a global monitor (mouse monitors need no
            // accessibility permission).
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            outsideClickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
                MainActor.assumeIsolated { self?.popover.performClose(nil) }
            }
        }
    }

    func popoverDidClose(_ notification: Notification) {
        if let monitor = outsideClickMonitor {
            NSEvent.removeMonitor(monitor)
            outsideClickMonitor = nil
        }
    }

    @objc private func openDashboard() {
        popover.performClose(nil)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    @objc private func editTargets() {
        popover.performClose(nil)
        targetEditor.onSave = { [weak self] targets in self?.applyTargets(targets) }
        targetEditor.show(rows.map(\.target))
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }

    private func updateFooter() {
        let ok = rows.filter { $0.status == .ok }.count
        let bad = rows.filter { $0.status == .configBad }.count
        let latencies = rows.compactMap { $0.latencyMs }
        let avg = latencies.isEmpty ? "no latency samples" : "\(latencies.reduce(0, +) / latencies.count) ms avg"
        footerLabel.stringValue = "\(ok)/\(rows.count) probes OK, \(bad) config bad, \(avg)."
    }
}

/// Window for editing the target list. Edits a working copy; nothing changes
/// until Save, which persists to `TargetStore` and hands the list to `onSave`.
@MainActor
final class TargetEditorController: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSTextFieldDelegate {
    var onSave: (([ProbeTarget]) -> Void)?

    private let engine: ProbeEngine
    private let probeQueue: DispatchQueue
    private var targets: [ProbeTarget] = []
    private var window: NSWindow!
    private let table = NSTableView()
    private let nameField = NSTextField()
    private let hostField = NSTextField()
    private let networkField = NSTextField()
    private let scopeField = NSTextField()
    private let probePopup = NSPopUpButton()
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private var testButton: NSButton!
    private var removeButton: NSButton!

    init(engine: ProbeEngine, probeQueue: DispatchQueue) {
        self.engine = engine
        self.probeQueue = probeQueue
        super.init()
        buildWindow()
    }

    func show(_ current: [ProbeTarget]) {
        targets = current
        table.reloadData()
        select(targets.isEmpty ? nil : 0)
        setStatus("", color: .secondaryLabelColor)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    private func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 700, height: 420),
                          styleMask: [.titled, .closable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Edit Targets"
        window.isReleasedWhenClosed = false
        window.center()

        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("target"))
        table.addTableColumn(column)
        table.headerView = nil
        table.dataSource = self
        table.delegate = self
        let tableScroll = NSScrollView()
        tableScroll.documentView = table
        tableScroll.hasVerticalScroller = true
        tableScroll.borderType = .bezelBorder
        tableScroll.widthAnchor.constraint(equalToConstant: 280).isActive = true

        for field in [nameField, hostField, networkField, scopeField] {
            field.delegate = self
        }
        hostField.placeholderString = "IPv4 address or hostname"
        probePopup.addItems(withTitles: ProbeType.allCases.map(\.rawValue))
        probePopup.target = self
        probePopup.action = #selector(formChanged)

        let form = NSGridView(views: [
            [NSTextField(labelWithString: "Name:"), nameField],
            [NSTextField(labelWithString: "Host:"), hostField],
            [NSTextField(labelWithString: "Probe:"), probePopup],
            [NSTextField(labelWithString: "Network:"), networkField],
            [NSTextField(labelWithString: "Scope:"), scopeField]
        ])
        form.rowSpacing = 8
        form.column(at: 0).xPlacement = .trailing
        form.column(at: 1).width = 300
        let hint = NSTextField(wrappingLabelWithString: "DNS probes need an IPv4 host. Test runs one probe against the entered values without saving.")
        hint.font = .systemFont(ofSize: 11)
        hint.textColor = .secondaryLabelColor
        testButton = NSButton(title: "Test", target: self, action: #selector(test))
        testButton.bezelStyle = .rounded
        statusLabel.font = .systemFont(ofSize: 12)

        let detail = NSStackView(views: [form, hint, testButton, statusLabel])
        detail.orientation = .vertical
        detail.alignment = .leading
        detail.spacing = 12

        let addButton = NSButton(title: "Add", target: self, action: #selector(add))
        removeButton = NSButton(title: "Remove", target: self, action: #selector(remove))
        let resetButton = NSButton(title: "Reset to Defaults", target: self, action: #selector(resetToDefaults))
        let cancelButton = NSButton(title: "Cancel", target: self, action: #selector(cancel))
        cancelButton.keyEquivalent = "\u{1b}"
        let saveButton = NSButton(title: "Save", target: self, action: #selector(save))
        saveButton.keyEquivalent = "\r"
        for button in [addButton, removeButton!, resetButton, cancelButton, saveButton] {
            button.bezelStyle = .rounded
        }

        let body = NSStackView(views: [tableScroll, detail])
        body.orientation = .horizontal
        body.alignment = .top
        body.spacing = 16
        let footer = NSStackView(views: [addButton, removeButton, resetButton, NSView(), cancelButton, saveButton])
        footer.orientation = .horizontal
        let root = NSStackView(views: [body, footer])
        root.orientation = .vertical
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        window.contentView = root
    }

    // MARK: Table

    func numberOfRows(in tableView: NSTableView) -> Int {
        targets.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let target = targets[row]
        let label = NSTextField(labelWithString: "\(target.name) — \(target.host) (\(target.probe.label))")
        label.lineBreakMode = .byTruncatingTail
        return label
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        loadForm()
    }

    private var selectedIndex: Int? {
        targets.indices.contains(table.selectedRow) ? table.selectedRow : nil
    }

    private func select(_ index: Int?) {
        if let index {
            table.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
            table.scrollRowToVisible(index)
        } else {
            table.deselectAll(nil)
        }
        loadForm()
    }

    // MARK: Form

    private func loadForm() {
        let target = selectedIndex.map { targets[$0] }
        for field in [nameField, hostField, networkField, scopeField] {
            field.isEnabled = target != nil
        }
        probePopup.isEnabled = target != nil
        testButton.isEnabled = target != nil
        removeButton.isEnabled = target != nil
        nameField.stringValue = target?.name ?? ""
        hostField.stringValue = target?.host ?? ""
        networkField.stringValue = target?.network ?? ""
        scopeField.stringValue = target?.scope ?? ""
        probePopup.selectItem(withTitle: (target?.probe ?? .icmpEcho).rawValue)
    }

    func controlTextDidChange(_ obj: Notification) {
        formChanged()
    }

    @objc private func formChanged() {
        guard let index = selectedIndex else { return }
        targets[index] = ProbeTarget(
            name: nameField.stringValue.trimmingCharacters(in: .whitespaces),
            host: hostField.stringValue.trimmingCharacters(in: .whitespaces),
            network: networkField.stringValue.trimmingCharacters(in: .whitespaces),
            scope: scopeField.stringValue.trimmingCharacters(in: .whitespaces),
            probe: ProbeType.allCases[max(probePopup.indexOfSelectedItem, 0)]
        )
        table.reloadData(forRowIndexes: IndexSet(integer: index), columnIndexes: IndexSet(integer: 0))
    }

    /// Why a target can't be probed or saved, or nil if it's fine. Host
    /// validation also keeps user input from being read as a command-line
    /// option by ping/dig/curl.
    private func problem(with target: ProbeTarget) -> String? {
        if target.name.isEmpty { return "name is empty" }
        return engine.validate(target)
    }

    private func setStatus(_ text: String, color: NSColor) {
        statusLabel.stringValue = text
        statusLabel.textColor = color
    }

    // MARK: Actions

    @objc private func test() {
        guard let index = selectedIndex else { return }
        let target = targets[index]
        if let problem = problem(with: target) {
            setStatus("Can't test: \(problem)", color: .systemRed)
            return
        }
        testButton.isEnabled = false
        setStatus("Testing \(target.host)…", color: .secondaryLabelColor)
        let engine = self.engine
        // engine.run blocks for up to the probe timeout; keep it off main.
        probeQueue.async {
            let outcome = engine.run(target)
            Task { @MainActor in
                self.testButton.isEnabled = self.selectedIndex != nil
                if outcome.status == .ok, let latency = outcome.latencyMs {
                    self.setStatus("\(target.name): OK — \(latency) ms", color: .systemGreen)
                } else {
                    self.setStatus("\(target.name): \(outcome.status.rawValue) — \(outcome.error ?? "no response")", color: .systemRed)
                }
            }
        }
    }

    @objc private func add() {
        targets.append(ProbeTarget(name: "New target", host: "", network: "", scope: "", probe: .icmpEcho))
        table.reloadData()
        select(targets.count - 1)
        window.makeFirstResponder(hostField)
    }

    @objc private func remove() {
        guard let index = selectedIndex else { return }
        targets.remove(at: index)
        table.reloadData()
        select(targets.isEmpty ? nil : min(index, targets.count - 1))
    }

    @objc private func resetToDefaults() {
        targets = defaultTargets
        table.reloadData()
        select(0)
        setStatus("Restored the default targets — Save to apply.", color: .secondaryLabelColor)
    }

    @objc private func cancel() {
        window.close()
    }

    @objc private func save() {
        guard !targets.isEmpty else {
            setStatus("Add at least one target.", color: .systemRed)
            return
        }
        if let index = targets.indices.first(where: { problem(with: targets[$0]) != nil }) {
            select(index)
            setStatus("Fix \"\(targets[index].name)\": \(problem(with: targets[index]) ?? "")", color: .systemRed)
            return
        }
        do {
            try TargetStore.save(targets)
        } catch {
            setStatus("Couldn't save: \(error.localizedDescription)", color: .systemRed)
            return
        }
        onSave?(targets)
        window.close()
    }
}

/// Accessory apps show no menu bar, but the main menu's key equivalents still
/// work while the app is active — needed for copy/paste in the target editor.
@MainActor
func buildMainMenu() -> NSMenu {
    let mainMenu = NSMenu()

    let appMenu = NSMenu()
    appMenu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    mainMenu.addItem(withTitle: "", action: nil, keyEquivalent: "").submenu = appMenu

    let editMenu = NSMenu(title: "Edit")
    editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
    editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
    editMenu.addItem(.separator())
    editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
    editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
    editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
    editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
    mainMenu.addItem(withTitle: "Edit", action: nil, keyEquivalent: "").submenu = editMenu

    let windowMenu = NSMenu(title: "Window")
    windowMenu.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
    mainMenu.addItem(withTitle: "Window", action: nil, keyEquivalent: "").submenu = windowMenu

    return mainMenu
}

let app = NSApplication.shared
app.mainMenu = buildMainMenu()
let delegate = DashboardController()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()