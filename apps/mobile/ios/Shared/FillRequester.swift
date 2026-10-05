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

/// Which logins the owner chose for which app, on this phone only, by the
/// App ID the system gives: an app has no origin to match a login's address
/// against.
struct AppLogins {
    private let defaults = UserDefaults(suiteName: DeviceFolder.appGroup)
    private let key = "app-logins"

    func chosen(_ app: String) -> Set<String> {
        Set((defaults?.dictionary(forKey: key)?[app] as? [String]) ?? [])
    }

    func remember(_ app: String, _ itemId: String) {
        var all = defaults?.dictionary(forKey: key) ?? [:]
        all[app] = Array(chosen(app).union([itemId])).sorted()
        defaults?.set(all, forKey: key)
    }
}
