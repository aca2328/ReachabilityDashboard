// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "ReachabilityDashboard",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "ReachabilityDashboard", targets: ["ReachabilityDashboard"])
    ],
    targets: [
        .executableTarget(
            name: "ReachabilityDashboard",
            path: "Sources/ReachabilityDashboard"
        )
    ]
)
