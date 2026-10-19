// Renders the app icon in the dashboard's neon-graph style into an .iconset
// directory, for bundle.sh to turn into AppIcon.icns with iconutil.
// Usage: swift make-icon.swift <output.iconset>

import AppKit

guard CommandLine.arguments.count == 2 else {
    print("Usage: swift make-icon.swift <output.iconset>")
    exit(1)
}
let outputDir = URL(fileURLWithPath: CommandLine.arguments[1])
try FileManager.default.createDirectory(at: outputDir, withIntermediateDirectories: true)

/// Draws the icon on a 1024-point design canvas, scaled to `pixels`.
func render(pixels: Int) -> Data {
    let ctx = CGContext(data: nil, width: pixels, height: pixels, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    // Shadows ignore the CTM, so blur and offset are scaled by `unit` by hand.
    let unit = CGFloat(pixels) / 1024
    ctx.scaleBy(x: unit, y: unit)

    // macOS icon grid: 824pt rounded square centered on the 1024 canvas.
    let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
    let tilePath = CGPath(roundedRect: tile, cornerWidth: 185, cornerHeight: 185, transform: nil)

    // Drop shadow under the tile.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -12 * unit), blur: 28 * unit, color: NSColor.black.withAlphaComponent(0.45).cgColor)
    ctx.addPath(tilePath)
    ctx.setFillColor(NSColor.black.cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    // Dark navy background, matching the graph canvas.
    ctx.saveGState()
    ctx.addPath(tilePath)
    ctx.clip()
    let background = CGGradient(colorsSpace: nil, colors: [
        NSColor(calibratedRed: 0.10, green: 0.12, blue: 0.19, alpha: 1).cgColor,
        NSColor(calibratedRed: 0.035, green: 0.045, blue: 0.075, alpha: 1).cgColor
    ] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(background, start: CGPoint(x: 0, y: tile.maxY), end: CGPoint(x: 0, y: tile.minY), options: [])

    // Faint grid.
    ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.07).cgColor)
    ctx.setLineWidth(4)
    for i in 1...4 {
        let y = tile.minY + CGFloat(i) * tile.height / 5
        ctx.move(to: CGPoint(x: tile.minX, y: y))
        ctx.addLine(to: CGPoint(x: tile.maxX, y: y))
    }
    ctx.strokePath()

    // Three smooth latency lines with glow and end dots. Fixed sRGB values
    // (the dark-mode system pink/cyan/green) so output doesn't depend on the
    // build machine's appearance settings.
    let lines: [(NSColor, [CGFloat])] = [
        (NSColor(srgbRed: 1.00, green: 0.22, blue: 0.37, alpha: 1), [0.30, 0.34, 0.28, 0.45, 0.40, 0.62, 0.50, 0.50]),
        (NSColor(srgbRed: 0.39, green: 0.82, blue: 1.00, alpha: 1), [0.52, 0.48, 0.58, 0.50, 0.66, 0.60, 0.74, 0.68]),
        (NSColor(srgbRed: 0.19, green: 0.82, blue: 0.35, alpha: 1), [0.18, 0.22, 0.20, 0.26, 0.24, 0.30, 0.27, 0.34])
    ]
    let plot = tile.insetBy(dx: 90, dy: 150)
    for (color, values) in lines {
        let points = values.enumerated().map { i, v in
            CGPoint(x: plot.minX + CGFloat(i) / CGFloat(values.count - 1) * plot.width,
                    y: plot.minY + v * plot.height)
        }
        let path = CGMutablePath()
        path.move(to: points[0])
        for i in 0..<(points.count - 1) {
            let p0 = points[max(i - 1, 0)], p1 = points[i], p2 = points[i + 1], p3 = points[min(i + 2, points.count - 1)]
            path.addCurve(to: p2,
                          control1: CGPoint(x: p1.x + (p2.x - p0.x) / 6, y: p1.y + (p2.y - p0.y) / 6),
                          control2: CGPoint(x: p2.x - (p3.x - p1.x) / 6, y: p2.y - (p3.y - p1.y) / 6))
        }
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: 30 * unit, color: color.cgColor)
        ctx.setStrokeColor(color.cgColor)
        ctx.setLineWidth(22)
        ctx.setLineCap(.round)
        ctx.setLineJoin(.round)
        ctx.addPath(path)
        ctx.strokePath()
        ctx.restoreGState()

        let end = points.last!
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: 36 * unit, color: color.cgColor)
        ctx.setFillColor(color.cgColor)
        ctx.fillEllipse(in: CGRect(x: end.x - 30, y: end.y - 30, width: 60, height: 60))
        ctx.restoreGState()
        ctx.setFillColor(NSColor.white.withAlphaComponent(0.95).cgColor)
        ctx.fillEllipse(in: CGRect(x: end.x - 13, y: end.y - 13, width: 26, height: 26))
    }
    ctx.restoreGState()

    return NSBitmapImageRep(cgImage: ctx.makeImage()!).representation(using: .png, properties: [:])!
}

for size in [16, 32, 128, 256, 512] {
    try render(pixels: size).write(to: outputDir.appendingPathComponent("icon_\(size)x\(size).png"))
    try render(pixels: size * 2).write(to: outputDir.appendingPathComponent("icon_\(size)x\(size)@2x.png"))
}
