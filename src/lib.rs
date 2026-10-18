//! Account-owned Microsoft/Xbox authentication for native Bedrock clients.
//!
//! Credential acquisition uses exclusive ownership. Returned authorizations can
//! be shared across concurrent service requests without sharing mutable state.

#![doc = include_str!("../README.md")]

mod error;
mod http;
mod nsal;
pub mod oauth;
pub mod signature;
pub mod xbox;

pub use error::Error;
