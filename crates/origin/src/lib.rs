//! The origin a login may be filled into.
//!
//! A login is filled only into a page whose origin is exactly the origin of
//! the address stored with it: HTTPS, the same host, and the same effective
//! port. A parent domain, a subdomain, another port, and plain HTTP are all
//! different origins. The vault core, the desktop session, and the native
//! messaging host all decide this with the one type here.

use std::fmt;

use url::Url;

const HTTPS_PORT: u16 = 443;

/// An HTTPS origin: a host and its effective port.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    /// As the URL standard serializes it: lower case, an international name
    /// in its ASCII form, an IPv6 address in brackets.
    host: String,
    port: u16,
}

impl Origin {
    /// Reads an origin as a browser serializes one, such as
    /// `https://example.com` or `https://example.com:8443`. Anything that is
    /// not already in that form is refused, so that a value which only
    /// resembles an origin is never taken for one.
    pub fn parse(serialized: &str) -> Option<Self> {
        let origin = Self::of_url(serialized)?;
        (origin.to_string() == serialized).then_some(origin)
    }

    /// The origin of an address stored with a login, whatever its path. An
    /// address that is not HTTPS, or that carries a user name or password,
    /// has none.
    pub fn of_url(address: &str) -> Option<Self> {
        let url = Url::parse(address).ok()?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return None;
        }
        let host = url.host_str().filter(|host| !host.is_empty())?;
        Some(Self {
            host: host.to_owned(),
            port: url.port().unwrap_or(HTTPS_PORT),
        })
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}", self.host)?;
        if self.port != HTTPS_PORT {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Origin({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(serialized: &str) -> Origin {
        Origin::parse(serialized).unwrap_or_else(|| panic!("{serialized} is an origin"))
    }

    fn stored(address: &str) -> Option<Origin> {
        Origin::of_url(address)
    }

    #[test]
    fn a_stored_address_matches_only_its_own_origin() {
        let origin = page("https://example.com");
        assert_eq!(stored("https://example.com"), Some(origin.clone()));
        assert_eq!(stored("https://example.com/"), Some(origin.clone()));
        assert_eq!(
            stored("https://example.com/login?next=%2Fhome#form"),
            Some(origin.clone())
        );
        // The default port is the same origin, written or not.
        assert_eq!(
            stored("https://example.com:443/login"),
            Some(origin.clone())
        );
        assert_eq!(stored("https://EXAMPLE.com/Login"), Some(origin.clone()));
        assert_eq!(stored("  https://example.com/  "), Some(origin.clone()));

        for other in [
            "http://example.com/",
            "https://www.example.com/",
            "https://login.example.com/",
            "https://example.com.evil.test/",
            "https://evil.test/example.com",
            "https://example.co/",
            "https://example.com:8443/",
            "https://example.com:80/",
            // A trailing dot names a different origin to the browser.
            "https://example.com./",
        ] {
            assert_ne!(stored(other), Some(origin.clone()), "{other}");
        }
    }

    #[test]
    fn an_address_that_is_not_plain_https_has_no_origin() {
        for address in [
            "",
            "example.com",
            "example.com/login",
            "//example.com/",
            "http://example.com/",
            "ftp://example.com/",
            "https://",
            "https://user@example.com/",
            "https://user:secret@example.com/",
            "https://:secret@example.com/",
            "data:text/html,<form>",
            "about:blank",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "blob:https://example.com/0b4e1e0a",
            "null",
        ] {
            assert_eq!(stored(address), None, "{address}");
        }
    }

    #[test]
    fn a_page_origin_is_accepted_only_as_the_browser_writes_it() {
        for serialized in [
            "https://example.com",
            "https://example.com:8443",
            "https://sub.example.com",
            "https://xn--bcher-kva.example",
            "https://192.0.2.7",
            "https://192.0.2.7:8443",
            "https://[2001:db8::1]",
            "https://[2001:db8::1]:8443",
            "https://example.com.",
        ] {
            assert_eq!(page(serialized).to_string(), serialized);
        }
        for serialized in [
            "https://example.com/",
            "https://example.com/login",
            "https://example.com?x",
            "https://example.com#x",
            "https://example.com:443",
            "https://EXAMPLE.com",
            "https://bücher.example",
            " https://example.com",
            "https://example.com ",
            "https:example.com",
            "https:///example.com",
            "https://user@example.com",
            "http://example.com",
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
            "null",
            "",
        ] {
            assert_eq!(Origin::parse(serialized), None, "{serialized}");
        }
    }

    #[test]
    fn an_international_name_matches_in_either_spelling() {
        let origin = page("https://xn--bcher-kva.example");
        assert_eq!(stored("https://bücher.example/konto"), Some(origin.clone()));
        assert_eq!(stored("https://BÜCHER.example/"), Some(origin.clone()));
        assert_eq!(stored("https://xn--bcher-kva.example/"), Some(origin));
        // A look-alike spelled with another letter is another origin.
        assert_ne!(
            stored("https://bucher.example/"),
            Origin::parse("https://xn--bcher-kva.example")
        );
    }

    #[test]
    fn hosts_written_as_numbers_are_compared_as_addresses() {
        assert_eq!(
            stored("https://192.0.2.7/admin"),
            Origin::parse("https://192.0.2.7")
        );
        // The URL standard reads these as the same IPv4 address.
        assert_eq!(
            stored("https://0xC0.0.2.7/"),
            Origin::parse("https://192.0.2.7")
        );
        assert_eq!(
            stored("https://[2001:DB8:0:0:0:0:0:1]:8443/"),
            Origin::parse("https://[2001:db8::1]:8443")
        );
    }

    #[test]
    fn debug_output_names_the_origin() {
        assert_eq!(
            format!("{:?}", page("https://example.com:8443")),
            "Origin(https://example.com:8443)"
        );
    }
}
