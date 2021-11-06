use std::net::Ipv6Addr;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while_m_n},
    character::{complete::char, is_hex_digit},
    combinator::{map, success},
    sequence::tuple,
};

use crate::{
    ipv4::parse_ipv4_three_dots,
    parse::{u8_to_u16_radix, Input, ParseResult},
};

/// Parse an ipv6 address using the syntax defined in
/// [RFC3986](https://tools.ietf.org/html/rfc3986#section-3.2.2).
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
pub(crate) fn parse(i: Input<'_>) -> ParseResult<'_, Ipv6Addr> {
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
fn parse_h16(i: Input<'_>) -> ParseResult<'_, u16> {
    let (i, h16) = take_while_m_n(1, 4, is_hex_digit)(i)?;

    let h16 = u8_to_u16_radix(h16, 16)?;

    Ok((i, h16))
}

// ls32 = ( h16 ":" h16 ) / IPv4address
fn parse_ls32(i: Input<'_>) -> ParseResult<'_, (u16, u16)> {
    let parse_double_h16 = map(tuple((parse_h16, char(':'), parse_h16)), |(a, _, b)| (a, b));

    alt((
        parse_double_h16,
        map(parse_ipv4_three_dots, |x| {
            let x: u32 = x.into();
            let h16_a = (x >> 16) as u16;
            let h16_b = (x & 0x0000_FFFF) as u16;
            (h16_a, h16_b)
        }),
    ))(i)
}

// h16_colon = h16 ":"
fn parse_h16_colon(i: Input<'_>) -> ParseResult<'_, u16> {
    let (i, h16) = parse_h16(i)?;
    let (i, _) = char(':')(i)?;

    Ok((i, h16))
}

// 6( h16 ":" ) ls32
fn parse_ipv6_1(i: Input<'_>) -> ParseResult<'_, Ipv6Addr> {
    let (i, h16_a) = parse_h16_colon(i)?;
    let (i, h16_b) = parse_h16_colon(i)?;
    let (i, h16_c) = parse_h16_colon(i)?;
    let (i, h16_d) = parse_h16_colon(i)?;
    let (i, h16_e) = parse_h16_colon(i)?;
    let (i, h16_f) = parse_h16_colon(i)?;
    let (i, (h16_g, h16_h)) = parse_ls32(i)?;

    Ok((
        i,
        Ipv6Addr::new(h16_a, h16_b, h16_c, h16_d, h16_e, h16_f, h16_g, h16_h),
    ))
}

// "::" 5( h16 ":" ) ls32
fn parse_ipv6_2(i: Input<'_>) -> ParseResult<'_, Ipv6Addr> {
    let (i, _) = tag("::")(i)?;
    let (i, h16_b) = parse_h16_colon(i)?;
    let (i, h16_c) = parse_h16_colon(i)?;
    let (i, h16_d) = parse_h16_colon(i)?;
    let (i, h16_e) = parse_h16_colon(i)?;
    let (i, h16_f) = parse_h16_colon(i)?;
    let (i, (h16_g, h16_h)) = parse_ls32(i)?;

    Ok((
        i,
        Ipv6Addr::new(0, h16_b, h16_c, h16_d, h16_e, h16_f, h16_g, h16_h),
    ))
}

fn parse_stuff<const N: usize>(mut i: &'_ [u8]) -> (&'_ [u8], [u16; N]) {
    let mut out = [0_u16; N];
    let mut p = 0;
    if i.starts_with(b"::") {
        return (i, out);
    }
    while p < N {
        match parse_h16(i) {
            Ok((i_, h16)) => {
                i = i_;
                out[p] = h16;
                p += 1;
                if i.starts_with(b"::") {
                    return (i, out);
                }
                if i.starts_with(b":") {
                    i = &i[1..];
                }
            }
            _ => break,
        }
    }

    (i, out)
}

// [ h16 ] "::" 4( h16 ":" ) ls32
fn parse_ipv6_3(i: Input<'_>) -> ParseResult<'_, Ipv6Addr> {
    let (i, h16_a) = alt((parse_h16, success(0)))(i)?;
    let (i, _) = tag("::")(i)?;
    let (i, h16_c) = parse_h16_colon(i)?;
    let (i, h16_d) = parse_h16_colon(i)?;
    let (i, h16_e) = parse_h16_colon(i)?;
    let (i, h16_f) = parse_h16_colon(i)?;
    let (i, (h16_g, h16_h)) = parse_ls32(i)?;

    Ok((
        i,
        Ipv6Addr::new(h16_a, 0, h16_c, h16_d, h16_e, h16_f, h16_g, h16_h),
    ))
}

// [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
fn parse_ipv6_4(i: Input<'_>) -> ParseResult<'_, Ipv6Addr> {
    let (i, [h16_a, h16_b]) = parse_stuff::<2>(i);
    let (i, _) = tag("::")(i)?;
    let (i, h16_d) = parse_h16_colon(i)?;
    let (i, h16_e) = parse_h16_colon(i)?;
    let (i, h16_f) = parse_h16_colon(i)?;
    let (i, (h16_g, h16_h)) = parse_ls32(i)?;

    Ok((
        i,
        Ipv6Addr::new(h16_a, h16_b, 0, h16_d, h16_e, h16_f, h16_g, h16_h),
    ))
}

// [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
fn parse_ipv6_5(i: Input<'_>) -> ParseResult<'_, Ipv6Addr> {
    let (i, [h16_a, h16_b, h16_c]) = parse_stuff::<3>(i);
    let (i, _) = tag("::")(i)?;
    let (i, h16_e) = parse_h16_colon(i)?;
    let (i, h16_f) = parse_h16_colon(i)?;
    let (i, (h16_g, h16_h)) = parse_ls32(i)?;

    Ok((
        i,
        Ipv6Addr::new(h16_a, h16_b, h16_c, 0, h16_e, h16_f, h16_g, h16_h),
    ))
}

// [ *3( h16 ":" ) h16 ] "::" h16 ":" ls32
fn parse_ipv6_6(i: Input<'_>) -> ParseResult<'_, Ipv6Addr> {
    let (i, [h16_a, h16_b, h16_c, h16_d]) = parse_stuff::<4>(i);
    let (i, _) = tag("::")(i)?;
    let (i, h16_f) = parse_h16_colon(i)?;
    let (i, (h16_g, h16_h)) = parse_ls32(i)?;

    Ok((
        i,
        Ipv6Addr::new(h16_a, h16_b, h16_c, h16_d, 0, h16_f, h16_g, h16_h),
    ))
}

// [ *4( h16 ":" ) h16 ] "::" ls32
fn parse_ipv6_7(i: Input<'_>) -> ParseResult<'_, Ipv6Addr> {
    let (i, arr) = parse_stuff::<5>(i);
    let [h16_a, h16_b, h16_c, h16_d, h16_e] = arr;
    let (i, _) = tag("::")(i)?;
    let (i, (h16_g, h16_h)) = parse_ls32(i)?;

    Ok((
        i,
        Ipv6Addr::new(h16_a, h16_b, h16_c, h16_d, h16_e, 0, h16_g, h16_h),
    ))
}

// [ *5( h16 ":" ) h16 ] "::" h16
fn parse_ipv6_8(i: Input<'_>) -> ParseResult<'_, Ipv6Addr> {
    let (i, [h16_a, h16_b, h16_c, h16_d, h16_e, h16_f]) = parse_stuff::<6>(i);
    let (i, _) = tag("::")(i)?;
    let (i, h16_h) = parse_h16(i)?;

    Ok((
        i,
        Ipv6Addr::new(h16_a, h16_b, h16_c, h16_d, h16_e, h16_f, 0, h16_h),
    ))
}

// [ *6( h16 ":" ) h 16 ] "::"
fn parse_ipv6_9(i: Input<'_>) -> ParseResult<'_, Ipv6Addr> {
    let (i, [h16_a, h16_b, h16_c, h16_d, h16_e, h16_f, h16_g]) = parse_stuff::<7>(i);
    let (i, _) = tag("::")(i)?;

    Ok((
        i,
        Ipv6Addr::new(h16_a, h16_b, h16_c, h16_d, h16_e, h16_f, h16_g, 0),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_no_alloc::assert_no_alloc;

    #[test]
    fn test_parse_ipv6() {
        let addrs: Vec<(Ipv6Addr, &[u8])> = vec![
            (
                Ipv6Addr::new(
                    0xABCD, 0xEF01, 0x2345, 0x6789, 0xABCD, 0xEF01, 0x2345, 0x6789,
                ),
                b"ABCD:EF01:2345:6789:ABCD:EF01:2345:6789",
            ),
            (
                Ipv6Addr::new(0x2001, 0xDB8, 0x0, 0x0, 0x8, 0x800, 0x200C, 0x417A),
                b"2001:DB8:0:0:8:800:200C:417A",
            ),
            (
                Ipv6Addr::new(0xFF01, 0, 0, 0, 0, 0, 0, 0x101),
                b"FF01:0:0:0:0:0:0:101",
            ),
            (Ipv6Addr::LOCALHOST, b"0:0:0:0:0:0:0:1"),
            (Ipv6Addr::UNSPECIFIED, b"0:0:0:0:0:0:0:0"),
            (Ipv6Addr::new(0xFF01, 0, 0, 0, 0, 0, 0, 0x101), b"FF01::101"),
            (Ipv6Addr::LOCALHOST, b"::1"),
            (Ipv6Addr::UNSPECIFIED, b"::"),
            (
                Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xD01, 0x4403),
                b"0:0:0:0:0:0:13.1.68.3",
            ),
            (
                Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x8190, 0x3426),
                b"0:0:0:0:0:FFFF:129.144.52.38",
            ),
            (
                Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xD01, 0x4403),
                b"::13.1.68.3",
            ),
            (
                Ipv6Addr::new(0xF, 0, 0, 0, 0, 0, 0xD01, 0x4403),
                b"F::13.1.68.3",
            ),
            (Ipv6Addr::new(0xFF01, 0, 0, 0, 0, 1, 1, 1), b"FF01::1:1:1"),
            (
                Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x8190, 0x3426),
                b"::FFFF:129.144.52.38",
            ),
        ];

        for (addr, input) in addrs {
            dbg!(addr);
            let (remainder, res) = assert_no_alloc(|| parse(input)).unwrap();
            assert!(remainder.is_empty());
            assert_eq!(addr, res);
        }
    }
}
