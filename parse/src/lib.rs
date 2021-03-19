#[cfg(all(test, debug_assertions))]
use assert_no_alloc::AllocDisabler;

#[cfg(all(test, debug_assertions))]
#[global_allocator]
static A: AllocDisabler = AllocDisabler;

mod ipv4;
mod ipv6;
mod parse;
mod uri;

pub use crate::parse::HttpParseError;
pub use ipv4::parse_ipv4;
pub use ipv6::parse_ipv6;
pub use uri::Uri;
