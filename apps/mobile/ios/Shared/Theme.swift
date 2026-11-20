import SwiftUI
import UIKit

// The desktop app's look, made for a phone: a warm near-black (or warm paper,
// in the light appearance) with an amber accent. Colours are made here, in
// code, and follow the system's appearance; nothing is downloaded or bundled
// for it, and the system's own font is used throughout.

extension Color {
    /// A colour that is `light` in the light appearance and `dark` in the dark one.
    init(light: UInt32, dark: UInt32) {
        self.init(uiColor: UIColor { traits in
            UIColor(rgb: traits.userInterfaceStyle == .dark ? dark : light)
        })
    }
}

private extension UIColor {
    convenience init(rgb: UInt32) {
        self.init(
            red: CGFloat((rgb >> 16) & 0xFF) / 255,
            green: CGFloat((rgb >> 8) & 0xFF) / 255,
            blue: CGFloat(rgb & 0xFF) / 255,
            alpha: 1
        )
    }
}

enum OSM {
    static let accent = Color(light: 0x8D5A1E, dark: 0xDDA45B)
    static let background = Color(light: 0xFAF7F0, dark: 0x11100E)
    /// What a row or a card sits on.
    static let card = Color(light: 0xF1EBDD, dark: 0x1B1916)
    static let hairline = Color(light: 0xDDD5C4, dark: 0x2D2A25)
    static let good = Color(light: 0x4F7D35, dark: 0x86B768)

    /// The tint behind an item's mark, and the colour of the mark, by kind.
    static func kind(_ kind: ItemKind) -> (tint: Color, ink: Color) {
        switch kind {
        case .login: (Color(light: 0xF7E3C4, dark: 0x342A1E), Color(light: 0x8D5A1E, dark: 0xDCA964))
        case .secureNote: (Color(light: 0xDDEBE5, dark: 0x252A2A), Color(light: 0x3F6B5E, dark: 0x91AAA2))
        case .card: (Color(light: 0xDCEAF5, dark: 0x1F2A33), Color(light: 0x2F5F85, dark: 0x8FB3CF))
        case .identity: (Color(light: 0xE7E0F4, dark: 0x29243A), Color(light: 0x5B4A8A, dark: 0xA899C5))
        }
    }
}

/// The shield with a keyhole, as the app's icon draws it.
struct BrandMark: View {
    var size: CGFloat = 44

    var body: some View {
        Canvas { context, canvas in
            let w = canvas.width
            let h = canvas.height
            var shield = Path()
            shield.move(to: CGPoint(x: w * 0.5, y: h * 0.06))
            shield.addLine(to: CGPoint(x: w * 0.86, y: h * 0.2))
            shield.addLine(to: CGPoint(x: w * 0.86, y: h * 0.52))
            shield.addCurve(to: CGPoint(x: w * 0.5, y: h * 0.96), control1: CGPoint(x: w * 0.86, y: h * 0.74), control2: CGPoint(x: w * 0.68, y: h * 0.88))
            shield.addCurve(to: CGPoint(x: w * 0.14, y: h * 0.52), control1: CGPoint(x: w * 0.32, y: h * 0.88), control2: CGPoint(x: w * 0.14, y: h * 0.74))
            shield.addLine(to: CGPoint(x: w * 0.14, y: h * 0.2))
            shield.closeSubpath()
            context.stroke(shield, with: .foreground, style: StrokeStyle(lineWidth: w * 0.07, lineJoin: .round))
            context.fill(
                Path(ellipseIn: CGRect(x: w * 0.415, y: h * 0.335, width: w * 0.17, height: w * 0.17)),
                with: .foreground
            )
            context.fill(Path(CGRect(x: w * 0.465, y: h * 0.45, width: w * 0.07, height: h * 0.2)), with: .foreground)
        }
        .frame(width: size, height: size)
        .foregroundStyle(OSM.accent)
        .accessibilityHidden(true)
    }
}

/// An item's mark in a list: its first letter, on the colour of its kind. It
/// says nothing to a screen reader: the row's text already does.
struct ItemAvatar: View {
    let title: String
    let kind: ItemKind
    var size: CGFloat = 40

    var body: some View {
        let colours = OSM.kind(kind)
        Text(mark)
            .font(.system(size: size * 0.42, weight: .heavy))
            .foregroundStyle(colours.ink)
            .frame(width: size, height: size)
            .background(colours.tint, in: RoundedRectangle(cornerRadius: size * 0.3, style: .continuous))
            .accessibilityHidden(true)
    }

    private var mark: String {
        switch kind {
        case .card: "▭"
        case .secureNote: "≡"
        default: title.trimmingCharacters(in: .whitespaces).first.map { String($0).uppercased() } ?? "•"
        }
    }
}

extension View {
    /// A list or form on the app's own ground, its rows on cards.
    func osmList() -> some View {
        scrollContentBackground(.hidden)
            .background(OSM.background)
            .listRowBackground(OSM.card)
    }

    /// A text field on a rounded card, for screens that are not a list.
    func osmField() -> some View {
        padding(14)
            .background(OSM.card, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(OSM.hairline, lineWidth: 1))
    }

    /// A screen of free-standing content on the app's ground.
    func osmScreen() -> some View {
        background(OSM.background)
    }
}

/// A full-width button for the main action of a screen.
struct WideButtonStyle: ButtonStyle {
    var prominent = true
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .frame(maxWidth: .infinity, minHeight: 48)
            .foregroundStyle(prominent ? Color(light: 0xFFFBF5, dark: 0x1D160E) : OSM.accent)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(prominent ? OSM.accent : Color.clear)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(prominent ? Color.clear : OSM.hairline, lineWidth: 1)
            )
            .opacity(isEnabled ? (configuration.isPressed ? 0.8 : 1) : 0.4)
            .contentShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

extension ButtonStyle where Self == WideButtonStyle {
    static var wide: WideButtonStyle { WideButtonStyle() }
    static var wideQuiet: WideButtonStyle { WideButtonStyle(prominent: false) }
}
