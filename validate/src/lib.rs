#![doc = include_str!("../README.md")]
#![deny(
    clippy::all,
    clippy::missing_const_for_fn,
    clippy::missing_docs_in_private_items,
    clippy::pedantic,
    future_incompatible,
    missing_docs,
    nonstandard_style,
    rust_2018_idioms,
    unsafe_code,
    unused,
    warnings
)]
#![allow(clippy::module_name_repetitions)]

pub mod channel;
pub mod command;
pub mod component;
pub mod embed;
pub mod message;
pub mod request;
pub mod sticker;
