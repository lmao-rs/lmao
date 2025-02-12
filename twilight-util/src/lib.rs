#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![warn(
    clippy::missing_const_for_fn,
    clippy::pedantic,
    missing_docs,
    unsafe_code
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::unnecessary_wraps,
    clippy::used_underscore_items
)]

#[cfg(feature = "builder")]
pub mod builder;

#[cfg(feature = "format")]
pub mod fmt;

#[cfg(feature = "link")]
pub mod link;

#[cfg(feature = "permission-calculator")]
pub mod permission_calculator;

#[cfg(feature = "snowflake")]
pub mod snowflake;
