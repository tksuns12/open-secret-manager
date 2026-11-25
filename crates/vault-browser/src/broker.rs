use std::{
    collections::{HashSet, VecDeque},
    time::{Duration, Instant},
};

use osm_browser_link::{
    Caller, CardRequest, Ceremony, FillRequest, Origin, PasskeyRequest, Refusal,
};
use osm_vault_core::passkey::{Registering, Signing};

/// How many request IDs are remembered, to refuse one that comes again.
const REMEMBERED: usize = 65_536;

/// What a request asks for: a login for a page, a card for the documents
/// of a tab, or a passkey for a page.
#[derive(Debug)]
pub(crate) enum Asked {
    Login(FillRequest),
    Card(CardRequest),
    Passkey(Ceremony, PasskeyRequest),
}

impl Asked {
    pub fn request_id(&self) -> &str {
        match self {
            Self::Login(request) => &request.request_id,
            Self::Card(request) => &request.request_id,
            Self::Passkey(_, request) => &request.request_id,
        }
    }

    /// Whether a page asked, as a passkey's request is made by the page's
    /// call, rather than the owner, who presses the extension's button for
    /// a login or a card.
    pub fn started_by_page(&self) -> bool {
        matches!(self, Self::Passkey(..))
    }

    /// The sign-in a passkey's request asks for, read.
    pub fn sign_in(&self) -> Option<Signing> {
        let Self::Passkey(Ceremony::Get, request) = self else {
            return None;
        };
        let origin = request.check().ok()?;
        Signing::from_options(&request.options, Some(&origin)).ok()
    }

    pub(crate) fn check(&self) -> Result<Origin, Refusal> {
        match self {
            Self::Login(request) => request.check(),
            Self::Card(request) => request.check(),
            // And the site's options, which only the app reads: a request
            // it does not answer is left to the browser.
            Self::Passkey(ceremony, request) => {
                let origin = request.check()?;
                let read = match ceremony {
                    Ceremony::Create => {
                        Registering::from_options(&request.options, Some(&origin)).map(drop)
                    }
                    Ceremony::Get => {
                        Signing::from_options(&request.options, Some(&origin)).map(drop)
                    }
                };
                read.map_err(|_| Refusal::PasskeyRefused)?;
                Ok(origin)
            }
        }
    }
}

/// The request waiting for the owner.
#[derive(Debug)]
pub(crate) struct Pending {
    /// Names this request to the connection that brought it.
    pub ticket: u64,
    pub caller: Caller,
    pub asked: Asked,
    /// The page's origin, as checked.
    pub origin: Origin,
    /// When the request ends if the owner has not decided.
    pub deadline: Instant,
}

/// Decides which request, if any, is waiting for the owner. It does no
/// input or output and reads no clock: the caller says what time it is.
#[derive(Debug)]
pub(crate) struct Broker {
    /// How long the owner has to decide.
    limit: Duration,
    pending: Option<Pending>,
    /// IDs of requests taken in before, oldest first, paired with an O(1) lookup set.
    seen: VecDeque<String>,
    seen_set: HashSet<String>,
    tickets: u64,
}

impl Broker {
    pub fn new(limit: Duration) -> Self {
        Self {
            limit,
            pending: None,
            seen: VecDeque::new(),
            seen_set: HashSet::new(),
            tickets: 0,
        }
    }

    pub fn has_seen(&self, request_id: &str) -> bool {
        self.seen_set.contains(request_id)
    }

    pub fn remember(&mut self, request_id: &str) {
        if self.seen_set.contains(request_id) {
            return;
        }
        if self.seen.len() == REMEMBERED {
            if let Some(oldest) = self.seen.pop_front() {
                self.seen_set.remove(&oldest);
            }
        }
        let owned = request_id.to_owned();
        self.seen_set.insert(owned.clone());
        self.seen.push_back(owned);
    }

    /// Takes a request in to wait for the owner, or says why not. The host
    /// checked it already; it is checked again here because the socket can
    /// be reached by any program of this account.
    pub fn submit(
        &mut self,
        caller: Caller,
        asked: Asked,
        now: Instant,
    ) -> Result<&Pending, Refusal> {
        if !caller.is_allowed() {
            return Err(Refusal::ExtensionNotAllowed);
        }
        let origin = asked.check()?;
        if self.has_seen(asked.request_id()) {
            return Err(Refusal::Replayed);
        }
        if self.pending(now).is_some() {
            return Err(Refusal::Busy);
        }
        self.remember(asked.request_id());
        self.tickets += 1;
        Ok(self.pending.insert(Pending {
            ticket: self.tickets,
            caller,
            asked,
            origin,
            deadline: now + self.limit,
        }))
    }

    /// The request waiting for the owner, unless its time is up.
    pub fn pending(&self, now: Instant) -> Option<&Pending> {
        self.pending
            .as_ref()
            .filter(|pending| now < pending.deadline)
    }

    /// Ends a request without a decision: its connection closed or its
    /// time ran out. Says whether it was still waiting.
    pub fn withdraw(&mut self, ticket: u64) -> bool {
        let waiting = self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.ticket == ticket);
        if waiting {
            self.pending = None;
        }
        waiting
    }

    /// Takes the waiting request out, for the owner's decision on it. A
    /// request is decided once: after this it waits no longer.
    pub fn take(&mut self, request_id: &str, now: Instant) -> Option<Pending> {
        self.pending(now)
            .is_some_and(|pending| pending.asked.request_id() == request_id)
            .then(|| self.pending.take())
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use osm_browser_link::{Forwarded, CHROMIUM_EXTENSION_ID, FIREFOX_EXTENSION_ID, VERSION};

    use super::*;

    impl Broker {
        /// Takes in a login's request as the host forwards it.
        fn take_in(&mut self, forwarded: Forwarded, now: Instant) -> Result<&Pending, Refusal> {
            self.submit(forwarded.caller, Asked::Login(forwarded.request), now)
        }
    }

    const LIMIT: Duration = Duration::from_secs(120);

    fn extension() -> Caller {
        Caller::Chromium(format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/"))
    }

    fn request(id: &str, origin: &str) -> FillRequest {
        FillRequest {
            version: VERSION,
            request_id: id.into(),
            tab_id: 7,
            frame_id: 0,
            document_id: "document".into(),
            origin: origin.into(),
        }
    }

    fn from(caller: Caller, request: FillRequest) -> Forwarded {
        Forwarded { caller, request }
    }

    fn fill(id: &str) -> Forwarded {
        from(extension(), request(id, "https://example.com"))
    }

    #[test]
    fn one_request_waits_at_a_time_and_is_decided_once() {
        let start = Instant::now();
        let mut broker = Broker::new(LIMIT);
        assert!(broker.pending(start).is_none());

        let first = broker.take_in(fill("first"), start).unwrap();
        assert_eq!(first.origin.to_string(), "https://example.com");
        assert_eq!(first.deadline, start + LIMIT);
        let ticket = first.ticket;
        assert_eq!(broker.pending(start).unwrap().asked.request_id(), "first");

        // While it waits, another is turned away, and so is the same again.
        assert_eq!(
            broker.take_in(fill("second"), start).unwrap_err(),
            Refusal::Busy
        );
        assert_eq!(
            broker.take_in(fill("first"), start).unwrap_err(),
            Refusal::Replayed
        );
        assert_eq!(broker.pending(start).unwrap().ticket, ticket);

        // Only the waiting request can be decided, and only once.
        assert!(broker.take("second", start).is_none());
        assert_eq!(broker.take("first", start).unwrap().ticket, ticket);
        assert!(broker.take("first", start).is_none());
        assert!(broker.pending(start).is_none());
        assert!(!broker.withdraw(ticket));

        // Its ID is spent; one that was turned away as busy is not.
        assert_eq!(
            broker.take_in(fill("first"), start).unwrap_err(),
            Refusal::Replayed
        );
        let second = broker.take_in(fill("second"), start).unwrap().ticket;
        assert_ne!(second, ticket);

        // A withdrawal ends only the request it names.
        assert!(!broker.withdraw(ticket));
        assert!(broker.pending(start).is_some());
        assert!(broker.withdraw(second));
        assert!(broker.pending(start).is_none());
        assert!(broker.take("second", start).is_none());
        assert_eq!(
            broker.take_in(fill("second"), start).unwrap_err(),
            Refusal::Replayed
        );
    }

    #[test]
    fn a_request_waits_no_longer_than_the_limit() {
        let start = Instant::now();
        let mut broker = Broker::new(LIMIT);
        broker.take_in(fill("first"), start).unwrap();
        let last_moment = start + LIMIT - Duration::from_millis(1);
        assert!(broker.pending(last_moment).is_some());
        assert!(broker.pending(start + LIMIT).is_none());
        assert!(broker.take("first", start + LIMIT).is_none());

        // Once its time is up it does not hold the next one back, even
        // before its connection has noticed.
        let next = broker.take_in(fill("next"), start + LIMIT).unwrap();
        assert_eq!(next.deadline, start + LIMIT + LIMIT);
        assert!(broker.take("first", start + LIMIT).is_none());
        assert!(broker.take("next", start + LIMIT).is_some());
    }

    #[test]
    fn what_the_host_should_have_refused_is_refused_here_too() {
        let now = Instant::now();
        let mut broker = Broker::new(LIMIT);
        let refused = |broker: &mut Broker, forwarded| broker.take_in(forwarded, now).unwrap_err();

        for forged in [
            Caller::Chromium("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".into()),
            Caller::Chromium(CHROMIUM_EXTENSION_ID.into()),
            Caller::Firefox("another@example.org".into()),
            Caller::Firefox(CHROMIUM_EXTENSION_ID.into()),
        ] {
            assert_eq!(
                refused(
                    &mut broker,
                    from(forged, request("a", "https://example.com"))
                ),
                Refusal::ExtensionNotAllowed
            );
        }
        for origin in [
            "http://example.com",
            "https://example.com/",
            "https://EXAMPLE.com",
            "https://user@example.com",
            "null",
        ] {
            assert_eq!(
                refused(&mut broker, from(extension(), request("a", origin))),
                Refusal::OriginRejected,
                "{origin}"
            );
        }
        let mut framed = request("a", "https://example.com");
        framed.frame_id = 4;
        assert_eq!(
            refused(&mut broker, from(extension(), framed)),
            Refusal::FrameRejected
        );
        let mut versioned = request("a", "https://example.com");
        versioned.version = VERSION + 1;
        assert_eq!(
            refused(&mut broker, from(extension(), versioned)),
            Refusal::UnsupportedVersion
        );
        assert_eq!(
            refused(
                &mut broker,
                from(extension(), request("a b", "https://example.com"))
            ),
            Refusal::InvalidMessage
        );
        // None of these waited, and none spent its ID.
        assert!(broker.pending(now).is_none());
        let firefox = Caller::Firefox(FIREFOX_EXTENSION_ID.into());
        let taken = broker
            .take_in(from(firefox, request("a", "https://example.com:8443")), now)
            .unwrap();
        assert_eq!(taken.origin.to_string(), "https://example.com:8443");
        assert_eq!(taken.caller.browser(), "Firefox");
    }

    #[test]
    fn only_so_many_spent_ids_are_remembered() {
        let now = Instant::now();
        let mut broker = Broker::new(LIMIT);
        for number in 0..=REMEMBERED {
            let id = format!("request-{number}");
            broker.take_in(fill(&id), now).unwrap();
            assert!(broker.take(&id, now).is_some());
        }
        assert_eq!(broker.seen.len(), REMEMBERED);
        // The newest are still refused; the very oldest has been forgotten.
        assert_eq!(
            broker.take_in(fill("request-1"), now).unwrap_err(),
            Refusal::Replayed
        );
        assert!(broker.take_in(fill("request-0"), now).is_ok());
    }
}
