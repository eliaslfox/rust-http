use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::{complete::char, is_hex_digit},
    combinator::{consumed, map, opt, verify},
    error::context,
    multi::{count, many_m_n},
    sequence::tuple,
};

use crate::ipv4::parse_ipv4;
use crate::parse::{Input, ParseResult};

// h16 = 1*4HEXDIG
fn parse_h16(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    context("h16", |i| {
        verify(take_while1(is_hex_digit), |x: &[u8]| x.len() <= 4)(i)
    })(i)
}

// h16_colon = h16 ":"
fn parse_h16_colon(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let (i, (c, _)) = consumed(tuple((parse_h16, char(':'))))(i)?;

    Ok((i, c))
}

// ls32 = ( h16 ":" h16 ) / IPv4address
fn parse_ls32(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    context("ls32", |i| {
        let parse_double_h16 = map(
            consumed(tuple((parse_h16, char(':'), parse_h16))),
            |(c, _)| c,
        );
        alt((parse_double_h16, parse_ipv4))(i)
    })(i)
}

// helper function used in some ipv6 rules
// ipv6_pre_block = *N( h1 ":" ) h16
fn parse_ipv6_pre_block(n: usize) -> impl Fn(Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    move |i: Input<'_>| {
        let (i, (c, _)) = consumed(tuple((many_m_n(0, n, parse_h16_colon), parse_h16)))(i)?;

        Ok((i, c))
    }
}

// Parse a ipv6 address in the form of [ *N( h1 ":" ) h16 ] "::" F.
//
// This function special cases addresses in the form of "FF::2005:F005" because the main parser
// will grab the first colon in the double colon structure and cause the parser to fail.
//
// This function avoids using use nom::combinator::alt to not double borrow f.
fn parse_ipv6_compressed<'a, F, O>(
    n: usize,
    mut f: F,
) -> impl FnOnce(Input<'a>) -> ParseResult<'a, &'a [u8]>
where
    F: FnMut(Input<'a>) -> ParseResult<'a, O> + 'a,
{
    move |i| {
        let p1_f = |i| {
            let (i, _) = parse_h16(i)?;
            let (i, _) = tag("::")(i)?;
            let (i, _) = f(i)?;
            Ok((i, ()))
        };
        let mut p1 = map(consumed(p1_f), |(c, _)| c);

        let p1_res = p1(i);
        drop(p1);

        if let Err(_) = p1_res {
            let p2_f = |i| {
                let (i, _) = opt(parse_ipv6_pre_block(n))(i)?;
                let (i, _) = tag("::")(i)?;
                let (i, _) = f(i)?;
                Ok((i, ()))
            };
            let mut p2 = map(consumed(p2_f), |(c, _)| c);
            p2(i)
        } else {
            p1_res
        }
    }
}

// 6( h16 ":" ) ls32
fn parse_ipv6_1(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let (i, (c, _)) = consumed(tuple((count(parse_h16_colon, 6), parse_ls32)))(i)?;

    Ok((i, c))
}

// "::" 5( h16 ":" ) ls32
fn parse_ipv6_2(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let (i, (c, _)) = consumed(tuple((tag("::"), count(parse_h16_colon, 5), parse_ls32)))(i)?;

    Ok((i, c))
}

// [ h16 ] "::" 4( h16 ":" ) ls32
fn parse_ipv6_3(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    let (i, (c, _)) = consumed(tuple((
        opt(parse_h16),
        tag("::"),
        count(parse_h16_colon, 4),
        parse_ls32,
    )))(i)?;

    Ok((i, c))
}

// [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
fn parse_ipv6_4(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    parse_ipv6_compressed(1, tuple((count(parse_h16_colon, 3), parse_ls32)))(i)
}

// [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
fn parse_ipv6_5(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
    parse_ipv6_compressed(2, tuple((count(parse_h16_colon, 2), parse_ls32)))(i)
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

pub fn parse_ipv6(i: Input<'_>) -> ParseResult<'_, &'_ [u8]> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
            let result = parse_ipv6(addr.as_bytes());
            let (remaining, addr_) = result.unwrap();
            assert_eq!(addr.as_bytes(), addr_);
            assert!(remaining.len() == 0);
        }
    }
}
