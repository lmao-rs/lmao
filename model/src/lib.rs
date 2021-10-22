//! # twilight-model
//!
//! [![discord badge][]][discord link] [![github badge][]][github link] [![license badge][]][license link] ![rust badge]
//!
//! See the [`twilight`] documentation for more information.
//!
//! `twilight-model` is a crate of serde models defining the Discord APIs with
//! few convenience methods on top of them.
//!
//! These are in a single crate for ease of use, a single point of definition,
//! and a sort of versioning of the Discord API. Similar to how a database
//! schema progresses in versions, the definition of the API also progresses in
//! versions.
//!
//! The types in this crate are reproducible: deserializing a payload into a
//! type, serializing it, and then deserializing it again will work.
//!
//! Defined are a number of modules defining types returned by or owned by
//! resource categories. For example, `gateway` are types used to interact with
//! and returned by the gateway API. `guild` contains types owned by the Guild
//! resource category. These types may be directly returned by, built on top of,
//! or extended by other crates.
//!
//! Some models have associated builders, which can be found in the
//! [`twilight-util`] crate.
//!
//! ## License
//!
//! [ISC][LICENSE.md]
//!
//! [LICENSE.md]: https://github.com/twilight-rs/twilight/blob/main/LICENSE.md
//! [`twilight-util`]: https://docs.rs/twilight-util
//! [`twilight`]: https://docs.rs/twilight
//! [discord badge]: https://img.shields.io/discord/745809834183753828?color=%237289DA&label=discord%20server&logo=discord&style=for-the-badge
//! [discord link]: https://discord.gg/7jj8n7D
//! [github badge]: https://img.shields.io/badge/github-twilight-6f42c1.svg?style=for-the-badge&logo=github
//! [github link]: https://github.com/twilight-rs/twilight
//! [license badge]: https://img.shields.io/badge/license-ISC-blue.svg?style=for-the-badge&logo=pastebin
//! [license link]: https://github.com/twilight-rs/twilight/blob/main/LICENSE.md
//! [rust badge]: https://img.shields.io/badge/rust-1.53+-93450a.svg?style=for-the-badge&logo=rust

#![deny(
    clippy::all,
    clippy::missing_const_for_fn,
    clippy::pedantic,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rustdoc::broken_intra_doc_links,
    unsafe_code,
    unused,
    warnings
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::semicolon_if_nothing_returned
)]

pub mod application;
pub mod channel;
pub mod datetime;
pub mod gateway;
pub mod guild;
pub mod id;
pub mod invite;
pub mod oauth;
pub mod template;
pub mod user;
pub mod voice;

pub(crate) mod util;
mod visitor;
