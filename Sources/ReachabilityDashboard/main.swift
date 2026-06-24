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

final class OutcomeStore: @unchecked Sendable {
    private let lock = NSLock()
    private var outcomes: [ProbeOutcome?]

    init(count: Int) {
        outcomes = Array(repeating: nil, count: count)
    }

    func set(_ outcome: ProbeOutcome, at index: Int) {
        lock.lock()
        outcomes[index] = outcome
        lock.unlock()
    }

    func values() -> [ProbeOutcome?] {
        lock.lock()
        let copy = outcomes
        lock.unlock()
        return copy
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

    private enum CurlMetric {
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

    private func isIPv4(_ value: String) -> Bool {
        let parts = value.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            guard let octet = Int(part) else { return false }
            return octet >= 0 && octet <= 255
        }
    }

    private func isHostname(_ value: String) -> Bool {
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

@MainActor
final class DashboardController: NSObject, NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate {
    private var window: NSWindow!
    private var tableView: NSTableView!
    private var footerLabel: NSTextField!
    private var refreshButton: NSButton!
    private var rows = configuredTargets.map { ProbeRow(target: $0) }
    private let engine = ProbeEngine(timeout: 3)
    private var timer: Timer?
    private var cycle = 0
    private var isRunning = false
    private let refreshInterval: TimeInterval = 5

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildWindow()
        validateRows()
        runCycle()
        timer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.runCycle()
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        rows.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let identifier = tableColumn?.identifier.rawValue ?? ""
        let cell = tableView.makeView(withIdentifier: NSUserInterfaceItemIdentifier(identifier), owner: self) as? NSTextField
            ?? NSTextField(labelWithString: "")
        cell.identifier = NSUserInterfaceItemIdentifier(identifier)
        cell.lineBreakMode = .byTruncatingTail
        cell.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        cell.textColor = color(for: rows[row], column: identifier)
        cell.stringValue = value(for: rows[row], column: identifier)
        return cell
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

        let subtitle = NSTextField(labelWithString: "Native macOS probe dashboard for ICMP, DNS, and HTTPS path quality.")
        subtitle.textColor = .secondaryLabelColor

        let header = NSStackView(views: [title, subtitle])
        header.orientation = .vertical
        header.spacing = 4

        refreshButton = NSButton(title: "Refresh Now", target: self, action: #selector(refreshNow))
        refreshButton.bezelStyle = .rounded

        footerLabel = NSTextField(labelWithString: "Starting...")
        footerLabel.textColor = .secondaryLabelColor

        let controls = NSStackView(views: [footerLabel, NSView(), refreshButton])
        controls.orientation = .horizontal
        controls.alignment = .centerY
        controls.spacing = 12

        tableView = NSTableView()
        tableView.delegate = self
        tableView.dataSource = self
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.rowHeight = 28
        tableView.headerView = NSTableHeaderView()

        addColumn("name", "Target", 170)
        addColumn("network", "Network", 160)
        addColumn("scope", "Scope", 120)
        addColumn("probe", "Probe", 90)
        addColumn("status", "Status", 110)
        addColumn("latency", "RTT/Time", 90)
        addColumn("trend", "Trend", 70)
        addColumn("success", "Success", 80)
        addColumn("error", "Last Error", 230)

        let scrollView = NSScrollView()
        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .bezelBorder

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

    private func addColumn(_ identifier: String, _ title: String, _ width: CGFloat) {
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
        column.title = title
        column.width = width
        tableView.addTableColumn(column)
    }

    private func validateRows() {
        for index in rows.indices {
            if let error = engine.validate(rows[index].target) {
                rows[index].status = ProbeStatus.configBad
                rows[index].lastError = error
            }
        }
        tableView.reloadData()
    }

    @objc private func refreshNow() {
        runCycle()
    }

    private func runCycle() {
        guard !isRunning else { return }
        isRunning = true
        cycle += 1
        refreshButton.isEnabled = false
        footerLabel.stringValue = "Cycle \(cycle) running..."

        for index in rows.indices where rows[index].status != ProbeStatus.configBad {
            rows[index].status = ProbeStatus.checking
            rows[index].lastError = nil
        }
        tableView.reloadData()

        let snapshot = rows.map { $0.target }
        let engine = self.engine
        DispatchQueue.global(qos: .utility).async {
            let group = DispatchGroup()
            let store = OutcomeStore(count: snapshot.count)

            for (index, target) in snapshot.enumerated() {
                group.enter()
                DispatchQueue.global(qos: .utility).async {
                    let outcome = engine.run(target)
                    store.set(outcome, at: index)
                    group.leave()
                }
            }

            group.wait()
            let outcomes = store.values()
            Task { @MainActor in
                self.apply(outcomes: outcomes)
            }
        }
    }

    private func apply(outcomes: [ProbeOutcome?]) {
        var okCount = 0
        var badConfigCount = 0
        var latencyTotal = 0
        var latencyCount = 0

        for index in rows.indices {
            guard let outcome = outcomes[index] else { continue }

            rows[index].totalCount += 1
            rows[index].status = outcome.status
            rows[index].lastError = outcome.error

            if outcome.status == ProbeStatus.ok {
                rows[index].successCount += 1
                rows[index].previousLatencyMs = rows[index].latencyMs
                rows[index].latencyMs = outcome.latencyMs
                okCount += 1

                if let latency = outcome.latencyMs {
                    latencyTotal += latency
                    latencyCount += 1
                }
            } else {
                if outcome.status == ProbeStatus.configBad {
                    badConfigCount += 1
                }
                rows[index].latencyMs = nil
            }
        }

        let avg = latencyCount > 0 ? "\(latencyTotal / latencyCount) ms avg" : "no latency samples"
        footerLabel.stringValue = "Cycle \(cycle): \(okCount)/\(rows.count) probes OK, \(badConfigCount) config bad, \(avg). Next refresh in \(Int(refreshInterval))s."
        refreshButton.isEnabled = true
        isRunning = false
        tableView.reloadData()
    }

    private func value(for row: ProbeRow, column: String) -> String {
        switch column {
        case "name": row.target.name
        case "network": row.target.network
        case "scope": row.target.scope
        case "probe": row.target.probe.label
        case "status": row.status.rawValue
        case "latency": row.latencyText
        case "trend": row.trend
        case "success": row.successRate
        case "error": row.lastError ?? ""
        default: ""
        }
    }

    private func color(for row: ProbeRow, column: String) -> NSColor {
        if column == "status" {
            switch row.status {
            case .ok: return .systemGreen
            case .checking: return .systemBlue
            case .configBad: return .systemOrange
            case .failed: return .systemRed
            case .pending: return .secondaryLabelColor
            }
        }

        if column == "latency", let latency = row.latencyMs {
            if latency < 50 { return .systemGreen }
            if latency < 150 { return .systemOrange }
            return .systemRed
        }

        return .labelColor
    }
}

let app = NSApplication.shared
let delegate = DashboardController()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.activate(ignoringOtherApps: true)
app.run()