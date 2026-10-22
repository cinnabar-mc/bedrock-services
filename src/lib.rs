//! Sign in, restore accounts, and use Minecraft and Xbox services from Rust.
//!
//! Start with [`oauth::MicrosoftAuth`]. Keep the returned [`xbox::Account`] for
//! social reads, or move it into [`minecraft::Minecraft`] for multiplayer tokens
//! and Realms. HTTP calls use your Tokio runtime; no account worker is started.

#![doc = include_str!("../README.md")]

mod error;
mod http;
pub mod minecraft;
mod nsal;
pub mod oauth;
pub mod playfab;
pub mod realms;
pub mod signaling;
pub mod signature;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;
#[cfg(any(feature = "signaling-tokio", feature = "rta-tokio"))]
mod websocket_io;
pub mod xbox;

pub use error::Error;
