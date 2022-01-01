#![doc = include_str!("../README.md")]
#![deny(
    clippy::all,
    clippy::missing_const_for_fn,
    clippy::pedantic,
    future_incompatible,
    missing_docs,
    nonstandard_style,
    rust_2018_idioms,
    unsafe_code,
    unused,
    warnings
)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "builder")]
#[cfg_attr(docsrs, doc(cfg(feature = "builder")))]
pub mod builder;

#[cfg(feature = "link")]
#[cfg_attr(docsrs, doc(cfg(feature = "link")))]
pub mod link;

#[cfg(feature = "permission-calculator")]
#[cfg_attr(docsrs, doc(cfg(feature = "permission-calculator")))]
pub mod permission_calculator;
