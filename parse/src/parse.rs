use nom::{
    error::ParseError,
    lib::std::str::{from_utf8, FromStr},
    IResult,
};
use std::str::Utf8Error;

/*
 * ParseError allows returning multiples types of error from a parser
 * Returning an error type other than nom::error::VerboseError will
 * cause location information to be lost.
 */
#[derive(Debug, derive_more::From)]
pub enum HttpParseError<I> {
    Nom(nom::error::VerboseError<I>),
    Utf8(Utf8Error),
}

pub type Input<'a> = &'a [u8];
pub type ParseResult<'a, O> = IResult<Input<'a>, O, HttpParseError<Input<'a>>>;

impl<I> nom::error::ParseError<I> for HttpParseError<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        nom::error::VerboseError::from_error_kind(input, kind).into()
    }
    fn append(input: I, kind: nom::error::ErrorKind, other: Self) -> Self {
        match other {
            HttpParseError::Nom(nom) => nom::error::VerboseError::append(input, kind, nom).into(),
            _ => other,
        }
    }
}

impl<I> nom::error::ContextError<I> for HttpParseError<I> {
    fn add_context(_input: I, _ctx: &'static str, other: Self) -> Self {
        match other {
            HttpParseError::Nom(nom) => {
                nom::error::VerboseError::add_context(_input, _ctx, nom).into()
            }
            _ => other,
        }
    }
}

// TODO: both u8_to_utf8 and u8_to_u32 aren't implemented as proper parser combinators. As a result
// they likely lose location information on a parser error.

/// Converts a &[u8] to a &str by attempting to decode as utf8.
pub fn u8_to_utf8(i: &'_ [u8]) -> Result<&'_ str, nom::Err<HttpParseError<&'_ [u8]>>> {
    from_utf8(i)
        .map_err(HttpParseError::Utf8)
        .map_err(nom::Err::Error)
}

/// Convert a &[u8] to a unicode &str and then parse that string into a u32.
pub fn u8_to_u32(i: &'_ [u8]) -> Result<u32, nom::Err<HttpParseError<&'_ [u8]>>> {
    u32::from_str(u8_to_utf8(i)?).map_err(|_| {
        nom::Err::Error(HttpParseError::from_error_kind(
            i,
            nom::error::ErrorKind::Digit,
        ))
    })
}
