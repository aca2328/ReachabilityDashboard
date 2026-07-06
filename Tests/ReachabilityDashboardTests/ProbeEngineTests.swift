import Testing
@testable import ReachabilityDashboard

struct ProbeEngineTests {
    let engine = ProbeEngine(timeout: 3)

    // MARK: - isIPv4 / isHostname

    @Test func isIPv4Valid() {
        #expect(engine.isIPv4("1.1.1.1"))
        #expect(engine.isIPv4("255.255.255.255"))
    }

    @Test func isIPv4Invalid() {
        #expect(!engine.isIPv4("256.1.1.1"))
        #expect(!engine.isIPv4("1.1.1"))
        #expect(!engine.isIPv4("example.com"))
    }

    @Test func isHostnameValid() {
        #expect(engine.isHostname("www.wikipedia.org"))
        #expect(engine.isHostname("www.cloudflare.com"))
    }

    @Test func isHostnameInvalid() {
        #expect(!engine.isHostname("no-dots"))
        #expect(!engine.isHostname("-bad.example.com"))
        #expect(!engine.isHostname(""))
    }

    // MARK: - ping parsing

    @Test func parsePingOutputExtractsLatency() {
        let output = """
        PING 1.1.1.1 (1.1.1.1): 56 data bytes
        64 bytes from 1.1.1.1: icmp_seq=0 ttl=59 time=11.234 ms

        --- 1.1.1.1 ping statistics ---
        1 packets transmitted, 1 packets received, 0.0% packet loss
        """
        let outcome = engine.parsePingOutput(output)
        #expect(outcome.status == .ok)
        #expect(outcome.latencyMs == 11)
    }

    @Test func parsePingOutputMissingRTTFails() {
        let outcome = engine.parsePingOutput("Request timeout for icmp_seq 0")
        #expect(outcome.status == .failed)
        #expect(outcome.latencyMs == nil)
    }

    // MARK: - dig parsing

    @Test func parseDigOutputRecursorSuccess() {
        let output = """
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
        ;; Query time: 23 msec
        """
        let outcome = engine.parseDigOutput(output, requireNoError: true)
        #expect(outcome.status == .ok)
        #expect(outcome.latencyMs == 23)
    }

    @Test func parseDigOutputRecursorNonNoErrorFails() {
        let output = """
        ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1
        ;; Query time: 23 msec
        """
        let outcome = engine.parseDigOutput(output, requireNoError: true)
        #expect(outcome.status == .failed)
    }

    @Test func parseDigOutputAuthAllowsRefused() {
        let output = """
        ;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 1
        ;; Query time: 5 msec
        """
        let outcome = engine.parseDigOutput(output, requireNoError: false)
        #expect(outcome.status == .ok)
        #expect(outcome.latencyMs == 5)
    }

    @Test func parseDigOutputAuthRejectsOtherStatus() {
        let output = """
        ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1
        ;; Query time: 5 msec
        """
        let outcome = engine.parseDigOutput(output, requireNoError: false)
        #expect(outcome.status == .failed)
    }

    // MARK: - curl parsing

    @Test func parseCurlOutputConnectMetric() {
        let outcome = engine.parseCurlOutput("0.050 0.120 0.300 200", metric: .connect)
        #expect(outcome.status == .ok)
        #expect(outcome.latencyMs == 120)
    }

    @Test func parseCurlOutputConnectFallsBackToTimeConnect() {
        let outcome = engine.parseCurlOutput("0.050 0.000 0.300 200", metric: .connect)
        #expect(outcome.status == .ok)
        #expect(outcome.latencyMs == 50)
    }

    @Test func parseCurlOutputTotalMetric() {
        let outcome = engine.parseCurlOutput("0.050 0.120 0.300 200", metric: .total)
        #expect(outcome.status == .ok)
        #expect(outcome.latencyMs == 300)
    }

    @Test func parseCurlOutputBadStatusFails() {
        let outcome = engine.parseCurlOutput("0.050 0.120 0.300 503", metric: .total)
        #expect(outcome.status == .failed)
    }

    @Test func parseCurlOutputMalformedFails() {
        let outcome = engine.parseCurlOutput("not enough parts", metric: .total)
        #expect(outcome.status == .failed)
    }
}
