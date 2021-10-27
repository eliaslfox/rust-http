use nom::{
    error::{Error, ErrorKind, ParseError},
    lib::std::str::{from_utf8, FromStr},
    multi::{fold_many0, fold_many1, fold_many_m_n},
    IResult, InputLength, Parser,
};
use std::str::Utf8Error;

/// Parse error types.
#[derive(Debug, derive_more::From)]
pub enum HttpParseError<I> {
    /// An individual nom parser failed.
    Nom(nom::error::Error<I>),

    /// A conversion from &[u8] to &str failed.
    Utf8(Utf8Error),
}

/// Input type for all parsers.
pub type Input<'a> = &'a [u8];

/// Output type from all parsers.
#[allow(clippy::module_name_repetitions)]
pub type ParseResult<'a, O> = IResult<Input<'a>, O, HttpParseError<Input<'a>>>;

impl<I> nom::error::ParseError<I> for HttpParseError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        Error::from_error_kind(input, kind).into()
    }
    fn append(input: I, kind: ErrorKind, other: Self) -> Self {
        match other {
            HttpParseError::Nom(nom) => Error::append(input, kind, nom).into(),
            HttpParseError::Utf8(_) => other,
        }
    }
}

/// Converts a &[u8] to a &str by attempting to decode as utf8.
pub fn u8_to_utf8(i: &'_ [u8]) -> Result<&'_ str, nom::Err<HttpParseError<&'_ [u8]>>> {
    from_utf8(i)
        .map_err(HttpParseError::Utf8)
        .map_err(nom::Err::Error)
}

/// Convert a &[u8] to a unicode &str and then parse that string into a u32.
pub fn u8_to_u32(i: &'_ [u8]) -> Result<u32, nom::Err<HttpParseError<&'_ [u8]>>> {
    u32::from_str(u8_to_utf8(i)?)
        .map_err(|_| nom::Err::Error(HttpParseError::from_error_kind(i, ErrorKind::Digit)))
}

/// Version of [`nom::multi::count`] that doesn't allocate
pub fn count_<I, O, E, F>(parser: F, count: usize) -> impl FnMut(I) -> IResult<I, (), E>
where
    I: Clone + PartialEq + InputLength,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    many_m_n_(count, count, parser)
}

/// Version of [`nom::multi::many_m_n`] that doesn't allocate
pub fn many_m_n_<I, O, E, F>(min: usize, max: usize, parse: F) -> impl FnMut(I) -> IResult<I, (), E>
where
    I: Clone + PartialEq + InputLength,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    fold_many_m_n(min, max, parse, || (), |_, _| ())
}

/// Version of [`nom::multi::many0`] that doesn't allocate
pub fn many0_<I, O, E, F>(parser: F) -> impl FnMut(I) -> IResult<I, (), E>
where
    I: Clone + PartialEq + InputLength,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    fold_many0(parser, || (), |_, _| ())
}

/// Version of [`nom::multi::many1`] that doesn't allocate
pub fn many1_<I, O, E, F>(parser: F) -> impl FnMut(I) -> IResult<I, (), E>
where
    I: Clone + PartialEq + InputLength,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    fold_many1(parser, || (), |_, _| ())
}
