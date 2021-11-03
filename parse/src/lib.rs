#![warn(
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    unreachable_pub,
    unused_crate_dependencies,
    clippy::pedantic
)]
#![allow(clippy::non_ascii_literal)]
#![cfg_attr(docsrs, deny(broken_intra_doc_links))]

//! Parse http requests.

#[cfg(test)]
use ::url as _;

#[cfg(all(test, debug_assertions))]
use assert_no_alloc::AllocDisabler;

#[cfg(all(test, debug_assertions))]
#[global_allocator]
static A: AllocDisabler = AllocDisabler;

mod idna;
mod ipv4;
mod ipv6;
mod parse;
mod uri;

pub use crate::parse::{HttpParseError, Input, ParseResult};
pub use uri::Uri;
