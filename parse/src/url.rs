#![allow(dead_code)]

use std::{
    borrow::Cow,
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
};

use nom::{
    branch::alt,
    bytes::complete::{take_while, take_while1, take_while_m_n},
    character::complete::char,
    combinator::{consumed, map, success},
    sequence::tuple,
};

use crate::parse::{u8_to_utf8, Input, ParseResult};

struct URL<'a> {
    _tag: PhantomData<&'a ()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Authority<'a> {
    username: &'a str,
    password: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Host<'a> {
    IPv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    String(Cow<'a, str>),
}

// An ASCII upper alpha is a code point in the range U+0041 (A) to U+005A (Z), inclusive.
fn is_ascii_upper_alpha(c: u8) -> bool {
    matches!(c, 0x41..=0x5A)
}

// An ASCII lower alpha is a code point in the range U+0061 (a) to U+007A (z), inclusive.
fn is_ascii_lower_alpha(c: u8) -> bool {
    matches!(c, 0x61..=0x7A)
}

// An ASCII alpha is an ASCII upper alpha or ASCII lower alpha.
fn is_ascii_alpha(c: u8) -> bool {
    is_ascii_upper_alpha(c) || is_ascii_lower_alpha(c)
}

// An ASCII digit is a code point in the range U+0030 (0) to U+0039 (9), inclusive.
fn is_ascii_digit(c: u8) -> bool {
    matches!(c, 0x30..=0x39)
}

// An ASCII alphanumeric is an ASCII digit or ASCII alpha.
fn is_ascii_alphanumeric(c: u8) -> bool {
    is_ascii_alpha(c) || is_ascii_digit(c)
}

fn is_scheme_special(c: &'_ str) -> bool {
    c == "ftp" || c == "file" || c == "http" || c == "https" || c == "ws" || c == "wss"
}

fn parse_scheme(i: Input<'_>) -> ParseResult<'_, Cow<'_, str>> {
    fn is_valid_scheme_byte(c: u8) -> bool {
        is_ascii_alphanumeric(c) || c == b'+' || c == b'-' || c == b'.'
    }

    let (i, (scheme, _)) = consumed(tuple((
        take_while_m_n(1, 1, is_ascii_alpha),
        take_while(is_valid_scheme_byte),
    )))(i)?;

    let scheme = u8_to_utf8(scheme)?;

    if scheme.bytes().any(is_ascii_upper_alpha) {
        return Ok((i, Cow::Owned(scheme.to_lowercase())));
    }

    // TODO: username and password should be percent encoded
    Ok((i, Cow::Borrowed(scheme)))
}

fn parse_authority(
    url_is_special: bool,
) -> impl FnMut(Input<'_>) -> ParseResult<'_, Authority<'_>> {
    fn is_valid_authority_byte(url_is_special: bool, c: u8) -> bool {
        if url_is_special && c == b'\\' {
            return false;
        }

        c != b'/' && c != b'?' && c != b'#' && c != b':'
    }

    move |i| {
        let (i, username) =
            take_while::<_, Input<'_>, _>(|c| is_valid_authority_byte(url_is_special, c))(i)?;

        let (i, password) = alt((
            map(
                tuple((
                    char(':'),
                    take_while(|c| is_valid_authority_byte(url_is_special, c)),
                )),
                |(_, password)| Some(password),
            ),
            success(None),
        ))(i)?;

        let (i, _) = char('@')(i)?;

        let username = u8_to_utf8(username)?;
        let password = password.map(|p| u8_to_utf8(p)).transpose()?;

        Ok((i, Authority { username, password }))
    }
}

fn parse_host(is_special: bool) -> impl FnMut(Input<'_>) -> ParseResult<'_, Host<'_>> {
    |i: Input<'_>| todo!()
}

fn parse_special_url<'a>(scheme: Cow<'a, str>, i: Input<'a>) -> ParseResult<'a, URL<'a>> {
    let (i, _) = take_while1(|c| c == b'/')(i)?;

    let (i, authority) = alt((map(parse_authority(true), Some), success(None)))(i)?;

    todo!()
}

fn parse_url(i: Input<'_>) -> ParseResult<'_, Cow<str>> {
    let (i, scheme) = parse_scheme(i)?;
    let (i, _) = char(':')(i)?;

    if &scheme == "file" {
        todo!()
    }

    if is_scheme_special(&scheme) {
        //parse_special_url(scheme, i)?;
    }

    todo!()
}
