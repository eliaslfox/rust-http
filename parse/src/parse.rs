use nom::{
    error::{ErrorKind, ParseError},
    lib::std::str::{from_utf8, FromStr},
    Err, IResult, Parser,
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
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        nom::error::Error::from_error_kind(input, kind).into()
    }
    fn append(input: I, kind: nom::error::ErrorKind, other: Self) -> Self {
        match other {
            HttpParseError::Nom(nom) => nom::error::Error::append(input, kind, nom).into(),
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
    u32::from_str(u8_to_utf8(i)?).map_err(|_| {
        nom::Err::Error(HttpParseError::from_error_kind(
            i,
            nom::error::ErrorKind::Digit,
        ))
    })
}

pub fn count_<I, O, E, F>(mut f: F, count: usize) -> impl FnMut(I) -> IResult<I, (), E>
where
    I: Clone + PartialEq,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    move |i: I| {
        let mut input = i.clone();

        for _ in 0..count {
            let input_ = input.clone();
            match f.parse(input_) {
                Ok((i, _o)) => {
                    input = i;
                }
                Err(Err::Error(e)) => {
                    return Err(Err::Error(E::append(i, ErrorKind::Count, e)));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok((input, ()))
    }
}

pub fn many_m_n_<I, O, E, F>(
    min: usize,
    max: usize,
    mut parse: F,
) -> impl FnMut(I) -> IResult<I, (), E>
where
    I: Clone + PartialEq,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    move |mut input: I| {
        for count in 0..max {
            match parse.parse(input.clone()) {
                Ok((tail, _value)) => {
                    // do not allow parsers that do not consume input (causes infinite loops)
                    if tail == input {
                        return Err(Err::Error(E::from_error_kind(input, ErrorKind::ManyMN)));
                    }

                    input = tail;
                }
                Err(Err::Error(e)) => {
                    if count < min {
                        return Err(Err::Error(E::append(input, ErrorKind::ManyMN, e)));
                    }
                    return Ok((input, ()));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok((input, ()))
    }
}

pub fn many0_<I, O, E, F>(mut f: F) -> impl FnMut(I) -> IResult<I, (), E>
where
    I: Clone + PartialEq,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    move |mut i: I| loop {
        match f.parse(i.clone()) {
            Err(Err::Error(_)) => return Ok((i, ())),
            Err(e) => return Err(e),
            Ok((i1, _o)) => {
                if i1 == i {
                    return Err(Err::Error(E::from_error_kind(i, ErrorKind::Many0)));
                }

                i = i1;
            }
        }
    }
}

pub fn many1_<I, O, E, F>(mut f: F) -> impl FnMut(I) -> IResult<I, (), E>
where
    I: Clone + PartialEq,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    move |mut i: I| match f.parse(i.clone()) {
        Err(Err::Error(err)) => Err(Err::Error(E::append(i, ErrorKind::Many1, err))),
        Err(e) => Err(e),
        Ok((i1, _o)) => {
            i = i1;

            loop {
                match f.parse(i.clone()) {
                    Err(Err::Error(_)) => return Ok((i, ())),
                    Err(e) => return Err(e),
                    Ok((i1, _o)) => {
                        if i1 == i {
                            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Many1)));
                        }

                        i = i1;
                    }
                }
            }
        }
    }
}
