//! hh-net: remote targets. `hh-server` runs on the machine with the processes (a Linux box,
//! a Steam Deck, a VM); [`connect`] returns a [`RemoteHost`] whose processes implement
//! `hh_core::Process`, so the scanner, assembler, pointer scanner and tools work unchanged.
//!
//! The wire protocol is documented in [`proto`].
//!
//! Security: authentication is an HMAC challenge-response over a shared token (the token is
//! never sent), but there is NO encryption: memory and requests travel in clear text and a
//! man in the middle can read or tamper with them after the handshake. Use the server on
//! trusted networks or through an SSH tunnel; it binds to 127.0.0.1 unless told otherwise.
pub mod client;
pub mod proto;
pub mod server;

pub use client::{RemoteHost, RemoteProcess, connect};
pub use server::{Backend, LocalBackend, Server, ServerConfig, ServerHandle};
