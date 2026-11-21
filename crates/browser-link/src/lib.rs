//! What the browser extension, the native messaging host, and the desktop
//! session say to each other when the owner asks for a login or, since
//! Phase 17, a card to be filled into a page.
//!
//! The extension sends a [`Request`] to the host over the browser's native
//! messaging. The host checks it and passes a fill request on, as a
//! [`Forwarded`] (or a [`ForwardedCard`]), over a socket that only the owner's account can reach; the
//! desktop session answers there with [`Response`]s, which the host checks
//! against the request before handing them to the extension. Nothing here
//! can open a vault: this crate is all the vault-related code the host
//! links.

pub mod frame;
#[cfg(any(windows, test))]
pub mod handshake;
mod message;

#[cfg(unix)]
pub mod endpoint;
#[cfg(windows)]
#[path = "endpoint_windows.rs"]
pub mod endpoint;

pub use message::{
    Caller, Cancel, CardField, CardFrame, CardReply, CardRequest, CardValues, Ceremony, Failure,
    FillReply, FillRequest, Forwarded, ForwardedCard, ForwardedPasskey, PasskeyReply,
    PasskeyRequest, Refusal, Request, Response, Waiting, CARD_VERSION, CHROMIUM_EXTENSION_ID,
    CHROMIUM_EXTENSION_IDS, CHROMIUM_STORE_EXTENSION_ID, FIREFOX_EXTENSION_ID, HOST_NAME,
    MAX_PASSKEY_OPTIONS, PASSKEY_VERSION, VERSION,
};
pub use osm_origin::Origin;

#[cfg(test)]
mod fixture_tests;
#[cfg(test)]
mod properties;
