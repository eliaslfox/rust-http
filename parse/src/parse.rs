use nom::{error::ParseError, multi::fold_many_m_n, IResult, InputLength, Parser};

#[allow(clippy::module_name_repetitions)]
pub(crate) type ParseResult<'a, O> = IResult<&'a str, O>;

pub(crate) fn many_m_n_<I, O, E, F>(
    min: usize,
    max: usize,
    parse: F,
) -> impl FnMut(I) -> IResult<I, (), E>
where
    I: Clone + PartialEq + InputLength,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    fold_many_m_n(min, max, parse, || (), |_, _| ())
}
