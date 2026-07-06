import AppKit
import Foundation

enum ProbeType: String {
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

struct ProbeTarget {
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
    var latencyHistory: [Int?] = []
    
    static let maxHistoryPoints = 50

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
    
    mutating func addLatency(_ latency: Int?) {
        latencyHistory.append(latency)
        if latencyHistory.count > ProbeRow.maxHistoryPoints {
            latencyHistory.removeFirst()
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

let configuredTargets: [ProbeTarget] = [
    .init(name: "Cloudflare DNS", host: "1.1.1.1", network: "AS13335 / anycast", scope: "global", probe: .dnsRecursor),
    .init(name: "Quad9 DNS", host: "9.9.9.9", network: "AS19281 / anycast", scope: "global", probe: .dnsRecursor),
    .init(name: "Google DNS", host: "8.8.8.8", network: "AS15169 / anycast", scope: "global", probe: .dnsRecursor),
    .init(name: "114DNS China", host: "114.114.114.114", network: "AS38283 / CN", scope: "regional", probe: .dnsRecursor),
    .init(name: "K-root RIPE NCC", host: "193.0.14.129", network: "AS25152 / root", scope: "anycast-root", probe: .dnsAuth),
    .init(name: "M-root WIDE", host: "202.12.27.33", network: "WIDE / root", scope: "anycast-root", probe: .dnsAuth),
    .init(name: "Cloudflare HTTPS", host: "www.cloudflare.com", network: "AS13335 / CDN", scope: "global", probe: .httpsConnect),
    .init(name: "Wikipedia HTTPS", host: "www.wikipedia.org", network: "AS14907 / CDN", scope: "global", probe: .httpsGet),
    .init(name: "Deutsche Telekom", host: "194.25.0.60", network: "AS3320 / DE", scope: "operator", probe: .icmpEcho),
    .init(name: "Hurricane Electric", host: "184.105.213.138", network: "AS6939 / US", scope: "operator", probe: .icmpEcho),
    .init(name: "Telstra", host: "139.130.4.5", network: "AS1221 / AU", scope: "operator", probe: .icmpEcho),
    .init(name: "LACNIC", host: "200.3.14.1", network: "AS28001 / UY", scope: "operator", probe: .icmpEcho)
]

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

final class ProbeGraphView: NSView {
    var rows: [ProbeRow] = []

    private let colors: [NSColor] = [
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

        let allLatencies = rows.flatMap { $0.latencyHistory.compactMap { $0 } }
        let rawMax = allLatencies.max() ?? 100
        let rawMin = allLatencies.min() ?? 0
        let maxLatency = CGFloat(rawMax) + CGFloat(max(rawMax - rawMin, 10)) * 0.12
        let minLatency = max(0, CGFloat(rawMin) - CGFloat(max(rawMax - rawMin, 10)) * 0.05)
        let latencyRange = max(maxLatency - minLatency, 1)

        let pointCount = rows.map { $0.latencyHistory.count }.max() ?? 0
        let xDenom = CGFloat(max(pointCount - 1, 1))
        let xScale = graphRect.width / xDenom

        func point(_ index: Int, _ value: Int) -> CGPoint {
            let x = graphRect.minX + CGFloat(index) * xScale
            let y = graphRect.minY + (CGFloat(value) - minLatency) / latencyRange * graphRect.height
            return CGPoint(x: x, y: y)
        }

        drawGrid(ctx, in: graphRect, minLatency: minLatency, latencyRange: latencyRange)

        let colorSpace = CGColorSpaceCreateDeviceRGB()

        var labels: [FloatingLabel] = []

        for (rowIndex, row) in rows.enumerated() {
            let color = colors[rowIndex % colors.count]
            // Split into contiguous segments so failed probes break the line
            // instead of plunging it to the floor.
            var segments: [[CGPoint]] = []
            var current: [CGPoint] = []
            for (i, latency) in row.latencyHistory.enumerated() {
                if let latency {
                    current.append(point(i, latency))
                } else if !current.isEmpty {
                    segments.append(current)
                    current = []
                }
            }
            if !current.isEmpty { segments.append(current) }
            guard !segments.isEmpty else { continue }

            for pts in segments {
                drawAreaFill(ctx, points: pts, baseline: graphRect.minY,
                             top: graphRect.maxY, color: color, colorSpace: colorSpace)
                drawGlowLine(ctx, points: pts, color: color)
            }

            if let end = segments.last?.last {
                drawEndDot(ctx, at: end, color: color)
                labels.append(FloatingLabel(text: labelText(for: row), color: color,
                                            anchor: end, active: row.status == .ok))
            }
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
        addSmoothCurve(to: fill, through: points)
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
        addSmoothCurve(to: line, through: points)
        ctx.addPath(line)
        ctx.strokePath()
        ctx.restoreGState()

        if points.count == 1 {
            drawEndDot(ctx, at: points[0], color: color)
        }
    }

    /// Appends a Catmull-Rom spline through `points` to `path`, which must
    /// already be positioned at `points[0]`. Produces smooth curved lines.
    private func addSmoothCurve(to path: CGMutablePath, through points: [CGPoint]) {
        guard points.count > 1 else { return }
        guard points.count > 2 else {
            path.addLine(to: points[1])
            return
        }
        for i in 0..<(points.count - 1) {
            let p0 = points[max(i - 1, 0)]
            let p1 = points[i]
            let p2 = points[i + 1]
            let p3 = points[min(i + 2, points.count - 1)]
            let c1 = CGPoint(x: p1.x + (p2.x - p0.x) / 6.0, y: p1.y + (p2.y - p0.y) / 6.0)
            let c2 = CGPoint(x: p2.x - (p3.x - p1.x) / 6.0, y: p2.y - (p3.y - p1.y) / 6.0)
            path.addCurve(to: p2, control1: c1, control2: c2)
        }
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

@MainActor
final class DashboardController: NSObject, NSApplicationDelegate {
    private var window: NSWindow!
    private var graphView: ProbeGraphView!
    private var footerLabel: NSTextField!
    private var refreshButton: NSButton!
    private var versionLabel: NSTextField!
    private var rows: [ProbeRow] = configuredTargets.map { ProbeRow(target: $0) }
    private let engine = ProbeEngine(timeout: 3)
    // Each probe runs its own independent loop, so a slow target never blocks
    // the others. `inFlight`/`scheduled` keep a single loop alive per probe.
    private var inFlight: [Bool] = []
    private var scheduled: [DispatchWorkItem?] = []
    private let probeQueue = DispatchQueue(label: "probes", qos: .utility, attributes: .concurrent)
    
    private var buildNumber: Int {
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
        validateRows()
        inFlight = Array(repeating: false, count: rows.count)
        scheduled = Array(repeating: nil, count: rows.count)
        for index in rows.indices where rows[index].status != .configBad {
            probeOnce(index)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    private func buildWindow() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1120, height: 620),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Operator Peering Quality Dashboard"
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

        window.makeKeyAndOrderFront(nil)
    }

    private func validateRows() {
        for index in rows.indices {
            if let error = engine.validate(rows[index].target) {
                rows[index].status = ProbeStatus.configBad
                rows[index].lastError = error
            }
        }
        graphView.needsDisplay = true
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
        probeQueue.async {
            let outcome = engine.run(target)
            Task { @MainActor in
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

    private func apply(_ outcome: ProbeOutcome, at index: Int) {
        rows[index].totalCount += 1
        rows[index].status = outcome.status
        rows[index].lastError = outcome.error
        rows[index].addLatency(outcome.latencyMs)

        if outcome.status == .ok {
            rows[index].successCount += 1
            rows[index].previousLatencyMs = rows[index].latencyMs
            rows[index].latencyMs = outcome.latencyMs
        } else {
            rows[index].latencyMs = nil
        }

        graphView.rows = rows
        graphView.needsDisplay = true
        updateFooter()
    }

    private func updateFooter() {
        let ok = rows.filter { $0.status == .ok }.count
        let bad = rows.filter { $0.status == .configBad }.count
        let latencies = rows.compactMap { $0.latencyMs }
        let avg = latencies.isEmpty ? "no latency samples" : "\(latencies.reduce(0, +) / latencies.count) ms avg"
        footerLabel.stringValue = "\(ok)/\(rows.count) probes OK, \(bad) config bad, \(avg)."
    }
}

let app = NSApplication.shared
let delegate = DashboardController()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.activate(ignoringOtherApps: true)
app.run()