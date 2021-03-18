use std::str::{from_utf8, FromStr};

use nom::{
    bytes::complete::take_while1,
    character::{complete::char, is_digit},
    combinator::{consumed, verify},
    sequence::tuple,
};

use crate::parse::{Input, ParseResult};

/// Parse an ipv4 quad using the syntax defined by
/// [RFC3986](https://tools.ietf.org/html/rfc3986#section-3.2.2).
pub fn parse_ipv4(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    parse_ipv4_quad(i)
}

fn parse_ipv4_quad_section(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    verify(take_while1(is_digit), |x: &[u8]| {
        let str = from_utf8(x).unwrap();
        let num = u32::from_str(str).unwrap();

        num <= 255
    })(i)
}

fn parse_ipv4_quad(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let (i, (c, _)) = consumed(tuple((
        parse_ipv4_quad_section,
        char('.'),
        parse_ipv4_quad_section,
        char('.'),
        parse_ipv4_quad_section,
        char('.'),
        parse_ipv4_quad_section,
    )))(i)?;

    Ok((i, c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_no_alloc::*;

    #[test]
    fn test_parse_ipv4_quad() {
        let result = assert_no_alloc(|| parse_ipv4(b"10.10.10.1"));
        let (res, ipv4) = result.unwrap();
        assert_eq!(res.len(), 0);
        assert_eq!(ipv4, b"10.10.10.1");
    }

    #[test]
    fn test_parse_ipv4_quad_big_numbers() {
        let result = assert_no_alloc(|| parse_ipv4(b"10.0.0.999"));
        assert!(result.is_err());

        let result = assert_no_alloc(|| parse_ipv4(b"10.0.256.0"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ipv4_quad_invalid() {
        let result = assert_no_alloc(|| parse_ipv4_quad(b"10.0.0.2567"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ipv4_quad_short() {
        let result = assert_no_alloc(|| parse_ipv4_quad(b"10.1.1"));
        assert!(result.is_err());
    }
}
