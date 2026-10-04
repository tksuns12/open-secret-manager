// Draws the desktop icon's shield (apps/desktop/src-tauri/icons/icon.svg)
// full-bleed at 1024 px, the app icon in App/Assets.xcassets: iOS rounds
// the corners itself.
//
//   swift Config/icon.swift App/Assets.xcassets/AppIcon.appiconset/icon-1024.png
import CoreGraphics
import Foundation
import ImageIO
let size = 1024.0, scale = size / 64.0
let context = CGContext(data: nil, width: 1024, height: 1024, bitsPerComponent: 8, bytesPerRow: 0, space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
context.translateBy(x: 0, y: size); context.scaleBy(x: scale, y: -scale)
func color(_ hex: Int) -> CGColor { CGColor(red: CGFloat(hex >> 16 & 255) / 255, green: CGFloat(hex >> 8 & 255) / 255, blue: CGFloat(hex & 255) / 255, alpha: 1) }
context.setFillColor(color(0xdda45b)); context.fill(CGRect(x: 0, y: 0, width: 64, height: 64))
func shield(_ top: CGFloat, _ side: CGFloat, _ width: CGFloat, _ straight: CGFloat, _ bottom: CGFloat, _ curve: CGFloat) -> CGPath {
    let path = CGMutablePath()
    path.move(to: CGPoint(x: 32, y: top))
    path.addLine(to: CGPoint(x: 32 + width, y: top + side))
    path.addLine(to: CGPoint(x: 32 + width, y: top + side + straight))
    path.addCurve(to: CGPoint(x: 32, y: bottom), control1: CGPoint(x: 32 + width, y: top + side + straight + curve), control2: CGPoint(x: 32 + width * 0.425, y: bottom - (bottom - top - side - straight) * 0.167))
    path.addCurve(to: CGPoint(x: 32 - width, y: top + side + straight), control1: CGPoint(x: 32 - width * 0.425, y: bottom - (bottom - top - side - straight) * 0.167), control2: CGPoint(x: 32 - width, y: top + side + straight + curve))
    path.addLine(to: CGPoint(x: 32 - width, y: top + side))
    path.closeSubpath()
    return path
}
// M32 12 48 20v12c0 10-6.8 17.5-16 21-9.2-3.5-16-11-16-21V20l16-8Z
context.addPath(shield(12, 8, 16, 12, 53, 10)); context.setFillColor(color(0x17130e)); context.fillPath()
// m32 22 8 4v7c0 5-3.2 8.5-8 10-4.8-1.5-8-5-8-10v-7l8-4Z
context.addPath(shield(22, 4, 8, 7, 43, 5)); context.setFillColor(color(0xdda45b)); context.fillPath()
let destination = CGImageDestinationCreateWithURL(URL(fileURLWithPath: CommandLine.arguments[1]) as CFURL, "public.png" as CFString, 1, nil)!
CGImageDestinationAddImage(destination, context.makeImage()!, nil)
precondition(CGImageDestinationFinalize(destination))
