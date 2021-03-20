use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::{complete::char, is_hex_digit},
    combinator::{consumed, map, opt, verify},
    sequence::tuple,
};

use crate::{
    ipv4,
    parse::{count_, many_m_n_, Input, ParseResult},
};

/// Parse an ipv6 address using the syntax defined in
/// [RFC3986](https://tools.ietf.org/html/rfc3986#section-3.2.2). This function does not normalize
/// ipv6 addresses, it only checks that they are valid.
///
/// See also: [RFC4291](https://tools.ietf.org/html/rfc4291)
// IPv6address =                            6( h16 ":" ) ls32
//                  /                       "::" 5( h16 ":" ) ls32
//                  / [               h16 ] "::" 4( h16 ":" ) ls32
//                  / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
//                  / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
//                  / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
//                  / [ *4( h16 ":" ) h16 ] "::"              ls32
//                  / [ *5( h16 ":" ) h16 ] "::"              h16
//                  / [ *6( h16 ":" ) h16 ] "::"
pub fn parse(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    alt((
        parse_ipv6_1,
        parse_ipv6_2,
        parse_ipv6_3,
        parse_ipv6_4,
        parse_ipv6_4,
        parse_ipv6_5,
        parse_ipv6_6,
        parse_ipv6_7,
        parse_ipv6_8,
        parse_ipv6_9,
    ))(i)
}

// h16 = 1*4HEXDIG
fn parse_h16(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    verify(take_while1(is_hex_digit), |x: &[u8]| x.len() <= 4)(i)
}

// ls32 = ( h16 ":" h16 ) / IPv4address
fn parse_ls32(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let parse_double_h16 = map(
        consumed(tuple((parse_h16, char(':'), parse_h16))),
        |(c, _)| c,
    );
    alt((parse_double_h16, ipv4::parse))(i)
}

// h16_colon = h16 ":"
fn parse_h16_colon(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let (i, (c, _)) = consumed(tuple((parse_h16, char(':'))))(i)?;

    Ok((i, c))
}

// helper function used in some ipv6 rules
// ipv6_pre_block = *N( h1 ":" ) h16
fn parse_ipv6_pre_block(n: usize) -> impl Fn(Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    move |i: Input<'_>| {
        let (i, (c, _)) = consumed(tuple((many_m_n_(0, n, parse_h16_colon), parse_h16)))(i)?;

        Ok((i, c))
    }
}

// Parse a ipv6 address in the form of [ *N( h1 ":" ) h16 ] "::" F.
fn parse_ipv6_compressed<'a, F, O>(
    n: usize,
    f: F,
) -> impl FnOnce(Input<'a>) -> ParseResult<'a, &'a [u8]>
where
    F: FnMut(Input<'a>) -> ParseResult<'a, O> + 'a,
{
    move |i| {
        let (i, (c, _)) = consumed(tuple((
            alt((
                map(parse_h16, |_| ()),
                map(opt(parse_ipv6_pre_block(n)), |_| ()),
            )),
            tag("::"),
            f,
        )))(i)?;

        Ok((i, c))
    }
}

// 6( h16 ":" ) ls32
fn parse_ipv6_1(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let (i, (c, _)) = consumed(tuple((count_(parse_h16_colon, 6), parse_ls32)))(i)?;

    Ok((i, c))
}

// "::" 5( h16 ":" ) ls32
fn parse_ipv6_2(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let (i, (c, _)) = consumed(tuple((tag("::"), count_(parse_h16_colon, 5), parse_ls32)))(i)?;

    Ok((i, c))
}

// [ h16 ] "::" 4( h16 ":" ) ls32
fn parse_ipv6_3(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let (i, (c, _)) = consumed(tuple((
        opt(parse_h16),
        tag("::"),
        count_(parse_h16_colon, 4),
        parse_ls32,
    )))(i)?;

    Ok((i, c))
}

// [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
fn parse_ipv6_4(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    parse_ipv6_compressed(1, tuple((count_(parse_h16_colon, 3), parse_ls32)))(i)
}

// [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
fn parse_ipv6_5(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    parse_ipv6_compressed(2, tuple((count_(parse_h16_colon, 2), parse_ls32)))(i)
}

// [ *3( h16 ":" ) h16 ] "::" h16 ":" ls32
fn parse_ipv6_6(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    parse_ipv6_compressed(3, tuple((parse_h16_colon, parse_ls32)))(i)
}

// [ *4( h16 ":" ) h16 ] "::" ls32
fn parse_ipv6_7(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    parse_ipv6_compressed(4, parse_ls32)(i)
}

// [ *5( h16 ":" ) h16 ] "::" h16
fn parse_ipv6_8(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    parse_ipv6_compressed(5, parse_h16)(i)
}

// [ *6( h16 ":" ) h 16 ] "::"
fn parse_ipv6_9(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let (i, (c, _)) = consumed(tuple((opt(parse_ipv6_pre_block(6)), tag("::"))))(i)?;

    Ok((i, c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_no_alloc::assert_no_alloc;

    #[test]
    fn test_parse_ipv6() {
        let addrs = vec![
            "ABCD:EF01:2345:6789:ABCD:EF01:2345:6789",
            "2001:DB8:0:0:8:800:200C:417A",
            "FF01:0:0:0:0:0:0:101",
            "0:0:0:0:0:0:0:1",
            "0:0:0:0:0:0:0:0",
            "FF01::101",
            "::1",
            "::",
            "0:0:0:0:0:0:13.1.68.3",
            "0:0:0:0:0:FFFF:129.144.52.38",
            "::13.1.68.3",
            "F::13.1.68.3",
            "FF01::1:1:1",
            "::FFFF:129.144.52.38",
        ];

        for addr in addrs {
            println!("parsing addr: {}", addr);
            let result = assert_no_alloc(|| parse(addr.as_bytes()));
            let (remaining, addr_) = result.unwrap();
            assert_eq!(addr.as_bytes(), addr_);
            assert!(remaining.is_empty());
        }
    }
}
