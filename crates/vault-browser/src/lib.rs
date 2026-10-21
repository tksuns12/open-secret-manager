//! The desktop session's end of filling a login, or a card, into a browser
//! page.
//!
//! The native messaging host brings a request to the session's socket. The
//! [`Desk`] holds it, one at a time, until the owner decides: the app shows
//! the page's origin and the logins stored for exactly that origin, and the
//! owner picks one or turns the request down. Only then, and only if the
//! vault is still in the unlock the owner chose under, does a user name and
//! password leave the vault, once, as the answer to that one request.
//!
//! The request ends without a login if the owner denies it, does not decide
//! in time, or if the connection that brought it closes, which is how the
//! extension withdraws a request when its page goes away.

#![cfg(unix)]

mod broker;
mod desk;
mod listen;

#[cfg(test)]
mod tests;

pub use desk::{CardChoices, Choices, Config, Desk, Refused};
pub use listen::{bind, serve, Bound};
