#![warn(
    missing_docs,
    missing_debug_implementations,
    clippy::pedantic,
    clippy::nursery,
    rust_2018_idioms
)]
#![cfg_attr(docsrs, deny(broken_intra_doc_links))]

//! Parse http requests.

#[cfg(all(test, debug_assertions))]
use assert_no_alloc::AllocDisabler;

#[cfg(all(test, debug_assertions))]
#[global_allocator]
static A: AllocDisabler = AllocDisabler;

mod ipv4;
mod ipv6;
mod parse;
mod uri;

pub use crate::parse::{HttpParseError, Input, ParseResult};
pub use uri::Uri;
