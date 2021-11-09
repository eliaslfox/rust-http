#![allow(dead_code)]

use std::{borrow::Cow, marker::PhantomData};

use nom::{
    branch::alt,
    bytes::complete::{take_while, take_while_m_n},
    character::complete::char,
    combinator::{consumed, map, success},
    sequence::tuple,
};

use crate::{
    parse::ParseResult,
    percent_encode::{is_userinfo_percent_encode, percent_encode},
};

struct Url<'a> {
    _tag: PhantomData<&'a ()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Authority<'a> {
    username: Cow<'a, str>,
    password: Option<Cow<'a, str>>,
}

// An ASCII upper alpha is a code point in the range U+0041 (A) to U+005A (Z), inclusive.
fn is_ascii_upper_alpha(c: char) -> bool {
    matches!(c, '\u{41}'..='\u{5A}')
}

// An ASCII lower alpha is a code point in the range U+0061 (a) to U+007A (z), inclusive.
fn is_ascii_lower_alpha(c: char) -> bool {
    matches!(c, '\u{61}'..='\u{7A}')
}

// An ASCII alpha is an ASCII upper alpha or ASCII lower alpha.
fn is_ascii_alpha(c: char) -> bool {
    is_ascii_upper_alpha(c) || is_ascii_lower_alpha(c)
}

// An ASCII digit is a code point in the range U+0030 (0) to U+0039 (9), inclusive.
fn is_ascii_digit(c: char) -> bool {
    matches!(c, '\u{30}'..='\u{39}')
}

// An ASCII alphanumeric is an ASCII digit or ASCII alpha.
fn is_ascii_alphanumeric(c: char) -> bool {
    is_ascii_alpha(c) || is_ascii_digit(c)
}

// The URL code points are ASCII alphanumeric, U+0021 (!), U+0024 ($), U+0026 (&), U+0027 ('),
// U+0028 LEFT PARENTHESIS, U+0029 RIGHT PARENTHESIS, U+002A (*), U+002B (+), U+002C (,), U+002D (-),
// U+002E (.), U+002F (/), U+003A (:), U+003B (;), U+003D (=), U+003F (?), U+0040 (@), U+005F (_),
// U+007E (~), and code points in the range U+00A0 to U+10FFFD, inclusive, excluding surrogates and noncharacters.
fn is_url_code_point(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || c == '!'
        || c == '$'
        || c == '&'
        || c == '\''
        || c == '.'
        || c == '/'
        || c == ':'
        || c == ';'
        || c == '='
        || c == '?'
        || c == '@'
        || c == '_'
        || c == '~'
        || matches!(c, '\u{A0}'..='\u{10FFFD}')
}

fn is_scheme_special(c: &'_ str) -> bool {
    c == "ftp" || c == "file" || c == "http" || c == "https" || c == "ws" || c == "wss"
}

fn parse_scheme(i: &'_ str) -> ParseResult<Cow<'_, str>> {
    fn is_valid_scheme_char(c: char) -> bool {
        is_ascii_alphanumeric(c) || c == '+' || c == '-' || c == '.'
    }

    let (i, (scheme, _)) = consumed(tuple((
        take_while_m_n(1, 1, is_ascii_alpha),
        take_while(is_valid_scheme_char),
    )))(i)?;

    if scheme.chars().any(is_ascii_upper_alpha) {
        return Ok((i, Cow::Owned(scheme.to_lowercase())));
    }

    // TODO: username and password should be percent encoded
    Ok((i, Cow::Borrowed(scheme)))
}

fn parse_authority(url_is_special: bool) -> impl FnMut(&'_ str) -> ParseResult<Authority> {
    fn is_valid_authority_char(url_is_special: bool, c: char) -> bool {
        if url_is_special && c == '\\' {
            return false;
        }

        c != '/' && c != '?' && c != '#' && c != ':'
    }

    move |i| {
        let (i, username) =
            take_while::<_, &'_ str, _>(|c| is_valid_authority_char(url_is_special, c))(i)?;

        let (i, password) = alt((
            map(
                tuple((
                    char(':'),
                    take_while(|c| is_valid_authority_char(url_is_special, c)),
                )),
                |(_, password)| Some(password),
            ),
            success(None),
        ))(i)?;

        let (i, _) = char('@')(i)?;

        let username = percent_encode(Cow::Borrowed(username), false, is_userinfo_percent_encode);
        let password = password
            .map(Cow::Borrowed)
            .map(|p| percent_encode(p, false, is_userinfo_percent_encode));

        Ok((i, Authority { username, password }))
    }
}
