//! PandaPass CLI library surface.
//!
//! The binary (`main.rs`) is a thin shell around these modules. Exposing them
//! here lets integration tests drive the real CLI client and command handlers
//! against a live server without going through `std::process::Command`.

pub mod client;
pub mod commands;
pub mod model;
