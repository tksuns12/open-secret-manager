import AuthenticationServices
import Foundation

/// Who asks for a login, as the system tells the AutoFill extension. The
/// system names a web page by its address, and an app by the web domains
/// Apple verified the app is associated with or, from iOS 26.2, by its App
/// ID; before that an app with no associated domain is named by nothing.
enum FillRequester: Equatable {
    /// A page, or an app, of these origins (`https://host[:port]`).
    case origins([String])
    /// An app the system names by its App ID.
    case app(id: String, name: String)
    /// Only an address that is not https: nothing is filled.
    case notHTTPS(String)
    /// Nothing named: the owner chooses a login, warned.
    case unnamed

    init(_ identifiers: [ASCredentialServiceIdentifier]) {
        var origins: [String] = []
        var app: (id: String, name: String)?
        var refused: String?
        for identifier in identifiers {
            switch identifier.type {
            case .domain:
                let host = identifier.identifier.lowercased()
                if !host.isEmpty, !host.contains("/") { origins.append("https://\(host)") }
            case .URL:
                guard let url = URL(string: identifier.identifier), let host = url.host?.lowercased(), !host.isEmpty else { continue }
                guard url.scheme?.lowercased() == "https" else {
                    refused = refused ?? identifier.identifier
                    continue
                }
                if let port = url.port, port != 443 {
                    origins.append("https://\(host):\(port)")
                } else {
                    origins.append("https://\(host)")
                }
            default:
                if #available(iOS 26.2, *), identifier.type == .app {
                    // A save request names the app `app://<App ID>`: one key
                    // for the app, whichever request names it.
                    var id = identifier.identifier
                    if id.hasPrefix("app://") { id.removeFirst("app://".count) }
                    app = (id, identifier.displayName ?? id)
                }
            }
        }
        var seen = Set<String>()
        origins = origins.filter { seen.insert($0).inserted }
        if !origins.isEmpty {
            self = .origins(origins)
        } else if let app {
            self = .app(id: app.id, name: app.name)
        } else if let refused {
            self = .notHTTPS(refused)
        } else {
            self = .unnamed
        }
    }
}

extension FillRequester {
    /// Who asks, as the vault decides what it is offered, filled, and saved
    /// into: an app by its App ID, which the vault keeps the logins the
    /// owner chose for it by. None for an address that is not https, which
    /// is filled nothing.
    var asked: Requester? {
        switch self {
        case let .origins(origins): return .page(origins: origins)
        case let .app(id, _): return .app(key: id, linkedDomains: [])
        case .unnamed: return .unnamed
        case .notHTTPS: return nil
        }
    }
}

/// Where builds before the vault kept them, the extension held the logins
/// the owner chose for each app: in the shared user defaults, by App ID,
/// the key the vault keeps them by now. They move into the device once, as
/// the app or the extension opens it, and are then gone from there.
enum EarlierAppLogins {
    private static let key = "app-logins"

    static func move(into device: Device) {
        guard let defaults = UserDefaults(suiteName: DeviceFolder.appGroup),
              let earlier = defaults.dictionary(forKey: key) else { return }
        let chosen = earlier.compactMapValues { $0 as? [String] }
        // Only once the device has them: a failure leaves them for the next open.
        if !chosen.isEmpty, (try? device.importAppChoices(chosen: chosen)) == nil { return }
        defaults.removeObject(forKey: key)
    }
}
