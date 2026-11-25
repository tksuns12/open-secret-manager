import AuthenticationServices
import XCTest

/// How the AutoFill extension reads who asks (Shared/FillRequester.swift),
/// and hands it to the vault: the cases the simulator's own requests do not
/// reach, such as Safari's pages. What the vault then offers each is proved
/// in crates/mobile/tests/fill.rs.
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
        XCTAssertEqual(requester(("https://[::1]:8443/login", .URL)), .origins(["https://[::1]:8443"]))
        XCTAssertEqual(requester(("https://bücher.example/login", .URL)), .origins(["https://xn--bcher-kva.example"]))
        XCTAssertEqual(requester(("https://user:pass@evil.test/", .URL)), .unnamed)
        XCTAssertEqual(requester(("*.example.test", .domain)), .unnamed)
        XCTAssertEqual(requester(), .unnamed)
        XCTAssertEqual(requester(("not a url", .URL)), .unnamed)
        // As the vault is told: an http address is told nothing.
        XCTAssertEqual(requester(("mail.example.test", .domain), ("bank.example.test", .domain)).asked, .page(origins: ["https://mail.example.test", "https://bank.example.test"]))
        XCTAssertEqual(requester().asked, .unnamed)
        XCTAssertNil(requester(("http://mail.example.test/", .URL)).asked)
        if #available(iOS 26.2, *) {
            let app = ASCredentialServiceIdentifier(identifier: "ABCDE12345.org.example.app", type: .app, displayName: "Example")
            XCTAssertEqual(FillRequester([app]), .app(id: "ABCDE12345.org.example.app", name: "Example"))
            XCTAssertEqual(FillRequester([app]).asked, .app(key: "ABCDE12345.org.example.app", linkedDomains: []))
            // As a save request names it.
            let saving = ASCredentialServiceIdentifier(identifier: "app://ABCDE12345.org.example.app", type: .app, displayName: "Example")
            XCTAssertEqual(FillRequester([saving]), .app(id: "ABCDE12345.org.example.app", name: "Example"))
        }
    }
}
