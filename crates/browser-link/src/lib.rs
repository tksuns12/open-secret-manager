//! What the browser extension, the native messaging host, and the desktop
//! session say to each other when the owner asks for a login to be filled
//! into a page.
//!
//! The extension sends a [`Request`] to the host over the browser's native
//! messaging. The host checks it and passes a fill request on, as a
//! [`Forwarded`], over a socket that only the owner's account can reach; the
//! desktop session answers there with [`Response`]s, which the host checks
//! against the request before handing them to the extension. Nothing here
//! can open a vault: this crate is all the vault-related code the host
//! links.

pub mod frame;
mod message;

#[cfg(unix)]
pub mod endpoint;

pub use message::{
    Caller, Cancel, Failure, FillReply, FillRequest, Forwarded, Refusal, Request, Response,
    Waiting, CHROMIUM_EXTENSION_ID, FIREFOX_EXTENSION_ID, HOST_NAME, VERSION,
};
pub use osm_origin::Origin;

#[cfg(test)]
mod fixture_tests;
#[cfg(test)]
mod properties;
