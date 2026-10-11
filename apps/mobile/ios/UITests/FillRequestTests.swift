import AuthenticationServices
import XCTest

/// How the AutoFill extension reads who asks (Shared/FillRequester.swift),
/// and what the vault offers each origin, on a copy of the frozen vault: the
/// cases the simulator's own requests do not reach, such as Safari's pages.
final class FillRequestTests: XCTestCase {
    private func requester(_ identifiers: (String, ASCredentialServiceIdentifier.IdentifierType)...) -> FillRequester {
        FillRequester(identifiers.map { ASCredentialServiceIdentifier(identifier: $0.0, type: $0.1) })
    }

    func testTheSystemsNamesBecomeOrigins() {
        XCTAssertEqual(requester(("https://mail.example.test/login?next=%2F", .URL)), .origins(["https://mail.example.test"]))
        XCTAssertEqual(requester(("https://Bank.Example.test:8443/", .URL)), .origins(["https://bank.example.test:8443"]))
        XCTAssertEqual(requester(("https://bank.example.test:443/", .URL)), .origins(["https://bank.example.test"]))
        XCTAssertEqual(requester(("mail.example.test", .domain)), .origins(["https://mail.example.test"]))
        XCTAssertEqual(
            requester(("mail.example.test", .domain), ("https://mail.example.test/", .URL), ("bank.example.test", .domain)),
            .origins(["https://mail.example.test", "https://bank.example.test"])
        )
        XCTAssertEqual(requester(("http://mail.example.test/", .URL)), .notHTTPS("http://mail.example.test/"))
        XCTAssertEqual(requester(("http://mail.example.test/", .URL), ("mail.example.test", .domain)), .origins(["https://mail.example.test"]))
        XCTAssertEqual(requester(), .unnamed)
        XCTAssertEqual(requester(("not a url", .URL)), .unnamed)
        if #available(iOS 26.2, *) {
            let app = ASCredentialServiceIdentifier(identifier: "ABCDE12345.org.example.app", type: .app, displayName: "Example")
            XCTAssertEqual(FillRequester([app]), .app(id: "ABCDE12345.org.example.app", name: "Example"))
            // As a save request names it.
            let saving = ASCredentialServiceIdentifier(identifier: "app://ABCDE12345.org.example.app", type: .app, displayName: "Example")
            XCTAssertEqual(FillRequester([saving]), .app(id: "ABCDE12345.org.example.app", name: "Example"))
        }
    }

    func testAnOriginIsOfferedOnlyTheLoginsSavedForIt() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        try FileManager.default.copyItem(at: URL(fileURLWithPath: frozenVault), to: folder.appendingPathComponent("vault.sqlite3"))
        let device = try Device.open(folder: folder.path, keystore: KeychainKeystore.shared)
        try device.unlock(password: fixturePassword)

        func offered(_ requester: FillRequester) throws -> [String] {
            guard case let .origins(origins) = requester else { return [] }
            return try origins.flatMap { try device.loginsForWeb(origin: $0) }.map(\.title)
        }
        XCTAssertEqual(try offered(requester(("https://mail.example.test/login", .URL))), ["Mail"])
        XCTAssertEqual(try offered(requester(("https://bank.example.test:8443/", .URL))), ["Bank"])
        XCTAssertEqual(try offered(requester(("bank.example.test", .domain))), [])
        XCTAssertEqual(try offered(requester(("https://login.mail.example.test/", .URL))), [])
        let filled = try device.fillForWeb(id: "fixture-mail", origin: "https://mail.example.test")
        XCTAssertEqual(filled.username, "owner@example.test")
        XCTAssertThrowsError(try device.fillForWeb(id: "fixture-bank", origin: "https://mail.example.test")) { error in
            guard case MobileError.NotForThisPage = error else { return XCTFail("\(error)") }
        }
        device.lock()
    }
}
