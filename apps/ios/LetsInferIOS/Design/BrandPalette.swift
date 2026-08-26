import SwiftUI

enum BrandPalette {
    static let dark = Color(hex: 0x1E1E1E)
    static let light = Color(hex: 0xF7F7F7)
    static let blue = Color(hex: 0x009CDF)
    static let purple = Color(hex: 0x973999)
    static let green = Color(hex: 0x61BB46)
    static let yellow = Color(hex: 0xFFB900)
    static let orange = Color(hex: 0xF78200)
    static let red = Color(hex: 0xE23838)

    static let canvas = Color(
        uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark
                ? UIColor.black
                : UIColor(red: 247 / 255, green: 247 / 255, blue: 245 / 255, alpha: 1)
        }
    )

    static let surface = Color(
        uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark
                ? UIColor(red: 41 / 255, green: 41 / 255, blue: 41 / 255, alpha: 1)
                : UIColor(red: 233 / 255, green: 233 / 255, blue: 230 / 255, alpha: 1)
        }
    )

    static let secondarySurface = Color(
        uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark
                ? UIColor(red: 30 / 255, green: 30 / 255, blue: 30 / 255, alpha: 1)
                : UIColor.white
        }
    )
}

extension Color {
    init(hex: UInt32, alpha: Double = 1) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: alpha
        )
    }
}

struct BoltMark: View {
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        ZStack {
            layer(BrandPalette.red, x: 8)
            layer(BrandPalette.orange, x: 6)
            layer(BrandPalette.yellow, x: 4)
            layer(BrandPalette.blue, x: 2)
            layer(colorScheme == .dark ? BrandPalette.light : BrandPalette.dark, x: 0)
        }
        .frame(width: 22, height: 45)
        .accessibilityHidden(true)
    }

    private func layer(_ color: Color, x: CGFloat) -> some View {
        Image("Bolt")
            .resizable()
            .renderingMode(.template)
            .foregroundStyle(color)
            .offset(x: x)
    }
}

struct ActivityCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(BrandPalette.secondarySurface)
            .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
    }
}
