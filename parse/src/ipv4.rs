use std::net::Ipv4Addr;

use nom::{
    branch::alt,
    bytes::complete::{take_while, take_while1},
    character::complete::char,
    combinator::{fail, map_res},
    AsChar,
};

use crate::parse::{many_m_n_, ParseResult};

#[allow(clippy::many_single_char_names)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn parse(i: &'_ str) -> ParseResult<Ipv4Addr> {
    fn parse_ipv4_zero_dots(i: &'_ str) -> ParseResult<'_, Ipv4Addr> {
        let (i, section) = parse_ipv4_section(u32::MAX)(i)?;
        let (i, _) = many_m_n_(0, 1, char('.'))(i)?;

        let [a, b, c, d] = section.to_ne_bytes();

        Ok((i, Ipv4Addr::new(a, b, c, d)))
    }

    fn parse_ipv4_one_dot(i: &'_ str) -> ParseResult<Ipv4Addr> {
        let (i, section_a) = parse_ipv4_section(0xFF)(i)?;
        let (i, _) = char('.')(i)?;
        let (i, section_b) = parse_ipv4_section(0x00FF_FFFF)(i)?;
        let (i, _) = many_m_n_(0, 1, char('.'))(i)?;

        let a = section_a as u8;
        let [_, b, c, d] = section_b.to_be_bytes();

        Ok((i, Ipv4Addr::new(a, b, c, d)))
    }

    fn parse_ipv4_two_dots(i: &'_ str) -> ParseResult<Ipv4Addr> {
        let (i, section_a) = parse_ipv4_section(0xFF)(i)?;
        let (i, _) = char('.')(i)?;
        let (i, section_b) = parse_ipv4_section(0xFF)(i)?;
        let (i, _) = char('.')(i)?;
        let (i, section_c) = parse_ipv4_section(0xFFFF)(i)?;
        let (i, _) = many_m_n_(0, 1, char('.'))(i)?;

        let a = section_a as u8;
        let b = section_b as u8;
        let [_, _, c, d] = section_c.to_be_bytes();

        Ok((i, Ipv4Addr::new(a, b, c, d)))
    }

    alt((
        parse_ipv4_three_dots,
        parse_ipv4_two_dots,
        parse_ipv4_one_dot,
        parse_ipv4_zero_dots,
    ))(i)
}

#[allow(clippy::many_single_char_names)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn parse_ipv4_three_dots(i: &'_ str) -> ParseResult<Ipv4Addr> {
    let (i, section_a) = parse_ipv4_section(0xFF)(i)?;
    let (i, _) = char('.')(i)?;
    let (i, section_b) = parse_ipv4_section(0xFF)(i)?;
    let (i, _) = char('.')(i)?;
    let (i, section_c) = parse_ipv4_section(0xFF)(i)?;
    let (i, _) = char('.')(i)?;
    let (i, section_d) = parse_ipv4_section(0xFF)(i)?;
    let (i, _) = many_m_n_(0, 1, char('.'))(i)?;

    let a = section_a as u8;
    let b = section_b as u8;
    let c = section_c as u8;
    let d = section_d as u8;

    Ok((i, Ipv4Addr::new(a, b, c, d)))
}

fn parse_ipv4_section(max: u32) -> impl FnMut(&'_ str) -> ParseResult<u32>
where
{
    move |i: &'_ str| {
        fn parse_ipv4_hex_section(i: &'_ str) -> ParseResult<u32> {
            let (i, _) = char('0')(i)?;
            let (i, _) = alt((char('x'), char('X')))(i)?;
            map_res(take_while(AsChar::is_hex_digit), |section: &'_ str| {
                if section.is_empty() {
                    return Ok(0);
                }

                u32::from_str_radix(section, 16)
            })(i)
        }
        fn parse_ipv4_octal_section(i: &'_ str) -> ParseResult<u32> {
            let (i, _) = char('0')(i)?;
            map_res(take_while(AsChar::is_oct_digit), |section: &'_ str| {
                if section.is_empty() {
                    return Ok(0);
                }

                u32::from_str_radix(section, 8)
            })(i)
        }

        fn parse_ipv4_decimal_section(i: &'_ str) -> ParseResult<u32> {
            map_res(take_while1(AsChar::is_dec_digit), |section: &'_ str| {
                u32::from_str_radix(section, 10)
            })(i)
        }

        let (i, num) = alt((
            parse_ipv4_hex_section,
            parse_ipv4_octal_section,
            parse_ipv4_decimal_section,
        ))(i)?;

        if num > max {
            fail::<_, u32, _>(i)?;
        }

        Ok((i, num))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_no_alloc::assert_no_alloc;
    use nom::sequence::tuple;

    #[test]
    fn test_parse_ipv4() {
        let test_data: Vec<(Ipv4Addr, &'_ str)> = vec![
            (Ipv4Addr::new(1, 1, 1, 1), "1.1.1.1"),
            (Ipv4Addr::new(8, 8, 8, 8), "010.010.010.010"),
            (Ipv4Addr::new(255, 255, 255, 255), "0xFF.0XFF.255.0377"),
            (Ipv4Addr::new(1, 0, 1, 0), "1.0.256"),
            (Ipv4Addr::new(1, 2, 3, 4), "1.2.3.4."),
            (Ipv4Addr::new(1, 253, 2, 255), "1.16581375"),
        ];

        for (expected, input) in test_data {
            assert_eq!(expected, assert_no_alloc(|| parse(input)).unwrap().1);
        }
    }

    #[test]
    fn test_parse_ipv4_invalid() {
        // Require a trailing slash to stop parsers from only consuming part of the input
        fn test_parser(i: &'_ str) -> ParseResult<(Ipv4Addr, char)> {
            tuple((parse, char('/')))(i)
        }

        let test_data: Vec<&'_ str> = vec!["0xAG.1.1.1/", "1.1.1.256/"];

        for input in test_data {
            println!("{:?}", parse(input));
            assert!(assert_no_alloc(|| test_parser(input).is_err()));
        }
    }
}
