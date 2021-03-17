use nom::{
    branch::alt,
    bytes::complete::tag,
    bytes::complete::{take_while, take_while1},
    character::{complete::char, is_alphanumeric, is_digit},
    combinator::{consumed, map, opt},
    error::context,
    multi::{many0, many1},
    sequence::{preceded, terminated, tuple},
    AsChar,
};

use crate::parse::{u8_to_u32, u8_to_utf8, Input, ParseResult};
use crate::{ipv4::parse_ipv4, ipv6::parse_ipv6};

// characters allowed in an URI and not given a reserved meaning
// as defined by rfc3986 2.3
fn uri_unreserved_character(i: u8) -> bool {
    if is_alphanumeric(i) {
        return true;
    }
    let c = i.as_char();
    c == '-' || c == '.' || c == '_' || c == '~'
}

// characters valid as sub delimiters in an URI as defined by rfc3986 2.2
fn uri_sub_delimeter(i: u8) -> bool {
    let c = i.as_char();
    c == '!'
        || c == '$'
        || c == '&'
        || c == '\''
        || c == '('
        || c == ')'
        || c == '*'
        || c == '+'
        || c == ','
        || c == ';'
        || c == '='
}

// TODO: fix this
fn uri_encoded_character(i: u8) -> bool {
    i.as_char() == '%'
}

#[derive(PartialEq, Eq, Debug)]
struct Scheme<'a>(&'a str);

impl<'a> Scheme<'a> {
    // Valid characters for a URI scheme as defined by rfc3986 3.1
    fn valid_character(i: u8) -> bool {
        if is_alphanumeric(i) {
            return true;
        }
        let c = i.as_char();
        c == '+' || c == '-' || c == '.'
    }

    fn parse(i: Input<'a>) -> ParseResult<'a, Self> {
        context("uri scheme", |i| {
            let (i, scheme) = terminated(take_while(Self::valid_character), tag(":"))(i)?;
            Ok((i, Scheme(u8_to_utf8(scheme)?)))
        })(i)
    }
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
struct UserInfo<'a>(&'a str);

impl<'a> UserInfo<'a> {
    // Valid characters for a URI userinfo subcomponent as defined by rfc3986 3.2.1
    fn valid_character(i: u8) -> bool {
        uri_unreserved_character(i)
            || uri_encoded_character(i)
            || uri_sub_delimeter(i)
            || i.as_char() == ':'
    }

    fn parse(i: Input<'a>) -> ParseResult<'a, Self> {
        context("uri userinfo", |i| {
            let (i, user_info) = terminated(take_while(UserInfo::valid_character), tag("@"))(i)?;
            let user_info = u8_to_utf8(user_info)?;
            Ok((i, UserInfo(user_info)))
        })(i)
    }
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
struct Host<'a>(&'a str);

impl<'a> Host<'a> {
    // Valid characters to appear in a reg-name.
    fn valid_reg_name_character(i: u8) -> bool {
        uri_unreserved_character(i) || uri_encoded_character(i) || uri_sub_delimeter(i)
    }

    // Valid host subcomponents of an URI are defined as rfc3986 3.2.2.
    fn parse(i: Input<'a>) -> ParseResult<'a, Self> {
        context("uri host", |i| {
            let (i, host) = alt((
                // check if the host is a valid ipv4 address first as ipv4 addresses are also valid
                // reg-names
                parse_ipv4,
                take_while1(Self::valid_reg_name_character),
                map(
                    consumed(tuple((char('['), parse_ipv6, char(']')))),
                    |(c, _)| c,
                ),
            ))(i)?;
            let host = u8_to_utf8(host)?;
            Ok((i, Host(host)))
        })(i)
    }
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
struct Port(u32);

impl Port {
    // Valid ports for an URI as defined in rfc3986 3.2.3.
    fn parse(i: Input<'_>) -> ParseResult<'_, Self> {
        context("url port", |i| {
            let (i, port) = preceded(tag(":"), take_while(is_digit))(i)?;
            let port = u8_to_u32(port)?;
            Ok((i, Port(port)))
        })(i)
    }
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
struct Authority<'a> {
    user_info: Option<UserInfo<'a>>,
    host: Option<Host<'a>>,
    port: Option<Port>,
}

impl<'a> Authority<'a> {
    #[cfg(test)]
    fn new(user_info: Option<&'a str>, host: Option<&'a str>, port: Option<u32>) -> Self {
        Authority {
            user_info: user_info.map(UserInfo),
            host: host.map(Host),
            port: port.map(Port),
        }
    }
    fn parse(i: Input<'a>) -> ParseResult<'_, Self> {
        context("uri authority", |i| {
            let (i, _) = tag("//")(i)?;
            let (i, user_info) = opt(UserInfo::parse)(i)?;
            let (i, host) = opt(Host::parse)(i)?;
            let (i, port) = opt(Port::parse)(i)?;

            Ok((
                i,
                Authority {
                    user_info,
                    host,
                    port,
                },
            ))
        })(i)
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Path<'a>(Vec<&'a str>);

impl<'a> Path<'a> {
    fn valid_path_segment_char(i: u8) -> bool {
        uri_unreserved_character(i)
            || uri_sub_delimeter(i)
            || uri_encoded_character(i)
            || i.as_char() == ':'
            || i.as_char() == '@'
    }

    // Parse an URI absolute path as defined by rfc3986 3.3. This is stricter than the rfc as it
    // does not allow rootless paths. Rootless paths are disallowed by http 1.1 (rfc2616 3.2.2) so
    // this should be fine.
    //
    // This implentation also collapses duplicate slashes between segments and consumes slashes at
    // the end of a path. This is not required by the URI spec but makes the parser more lenient.
    fn parse(i: Input<'a>) -> ParseResult<'_, Self> {
        context("uri path", |i| {
            let (i, path) = many0(preceded(
                many1(tag("/")),
                take_while1(Self::valid_path_segment_char),
            ))(i)?;

            let mut path_utf8 = Vec::with_capacity(path.len());
            for path_segment in path {
                path_utf8.push(u8_to_utf8(path_segment)?);
            }

            let (i, _) = many0(tag("/"))(i)?;

            Ok((i, Path(path_utf8)))
        })(i)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
struct Query<'a>(&'a str);

impl<'a> Query<'a> {
    fn valid_query_char(i: u8) -> bool {
        Path::valid_path_segment_char(i) || i.as_char() == '/' || i.as_char() == '?'
    }
    fn parse(i: Input<'a>) -> ParseResult<'_, Self> {
        context("uri query", |i| {
            let (i, query) = preceded(tag("?"), take_while(Self::valid_query_char))(i)?;
            let query = u8_to_utf8(query)?;
            Ok((i, Query(query)))
        })(i)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
struct Fragment<'a>(&'a str);

impl<'a> Fragment<'a> {
    fn valid_query_char(i: u8) -> bool {
        Path::valid_path_segment_char(i) || i.as_char() == '/' || i.as_char() == '?'
    }
    fn parse(i: Input<'a>) -> ParseResult<'_, Self> {
        context("uri query", |i| {
            let (i, query) = preceded(tag("#"), take_while(Self::valid_query_char))(i)?;
            let query = u8_to_utf8(query)?;
            Ok((i, Fragment(query)))
        })(i)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Uri<'a> {
    scheme: Scheme<'a>,
    authority: Option<Authority<'a>>,
    path: Path<'a>,
    query: Option<Query<'a>>,
    fragment: Option<Fragment<'a>>,
}

impl<'a> Uri<'a> {
    #[cfg(test)]
    fn new(
        scheme: &'a str,
        authority: Option<Authority<'a>>,
        path: Vec<&'a str>,
        query: Option<&'a str>,
        fragment: Option<&'a str>,
    ) -> Self {
        Uri {
            scheme: Scheme(scheme),
            authority,
            path: Path(path),
            query: query.map(Query),
            fragment: fragment.map(Fragment),
        }
    }

    #[inline]
    pub fn scheme(&self) -> &'a str {
        self.scheme.0
    }

    #[inline]
    pub fn user_info(&self) -> Option<&'a str> {
        self.authority.and_then(|x| x.user_info).map(|x| x.0)
    }

    #[inline]
    pub fn host(&self) -> Option<&'a str> {
        self.authority.and_then(|x| x.host).map(|x| x.0)
    }

    #[inline]
    pub fn port(&self) -> Option<u32> {
        self.authority.and_then(|x| x.port).map(|x| x.0)
    }

    #[inline]
    pub fn path(&self) -> &'_ [&'a str] {
        &self.path.0[..]
    }

    #[inline]
    pub fn query(&self) -> Option<&'a str> {
        self.query.map(|x| x.0)
    }

    #[inline]
    pub fn fragment(&self) -> Option<&'a str> {
        self.fragment.map(|x| x.0)
    }

    pub fn parse(i: Input<'a>) -> ParseResult<'_, Self> {
        context("uri", |i| {
            let (i, scheme) = Scheme::parse(i)?;
            let (i, authority) = opt(Authority::parse)(i)?;

            // If a URI does not have an authority then the path is a single segment
            let (i, path) = match authority {
                Some(_) => Path::parse(i)?,
                None => {
                    let (i, path) = take_while(Path::valid_path_segment_char)(i)?;
                    let path = u8_to_utf8(path)?;
                    (i, Path(vec![path]))
                }
            };

            let (i, query) = opt(Query::parse)(i)?;
            let (i, fragment) = opt(Fragment::parse)(i)?;

            Ok((
                i,
                Uri {
                    scheme,
                    authority,
                    path,
                    query,
                    fragment,
                },
            ))
        })(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL1: &'static [u8] = b"ftp://ftp.is.co.za/rfc/rfc1808.txt";
    const URL2: &'static [u8] = b"http://www.ietf.org/rfc/rfc2396.txt";
    const URL3: &'static [u8] = b"://example.com";

    #[test]
    fn parse_scheme() {
        let result = Scheme::parse(URL1);
        let (_, scheme) = result.unwrap();

        assert_eq!(scheme, Scheme("ftp"));

        let result = Scheme::parse(URL2);
        let (_, scheme) = result.unwrap();

        assert_eq!(scheme, Scheme("http"));
    }

    #[test]
    fn parse_scheme_empty() {
        let result = Scheme::parse(URL3);
        let (_, scheme) = result.unwrap();

        assert_eq!(scheme, Scheme(""));
    }

    #[test]
    fn parse_user_info() {
        let result = UserInfo::parse(b"admin@example.com");
        let (_, user_info) = result.unwrap();

        assert_eq!(user_info, UserInfo("admin"));

        let result = UserInfo::parse(b"admin:password@example.com");
        let (_, user_info) = result.unwrap();

        assert_eq!(user_info, UserInfo("admin:password"));
    }

    #[test]
    fn parse_host() {
        let result = Host::parse(b"example.com/aaa/bbb");
        let (_, host) = result.unwrap();

        assert_eq!(host, Host("example.com"));

        let result = Host::parse(b"127.0.0.1/aaa/bbb");
        let (_, host) = result.unwrap();

        assert_eq!(host, Host("127.0.0.1"));

        let result = Host::parse(b"[::1]/aaa/bbb");
        let (_, host) = result.unwrap();

        assert_eq!(host, Host("[::1]"));
    }

    #[test]
    fn parse_host_with_port() {
        let result = Host::parse(b"example.com:8080/aaa/bbb");
        let (_, host) = result.unwrap();

        assert_eq!(host, Host("example.com"));

        let result = Host::parse(b"127.0.0.1:3000/aaa/bbb");
        let (_, host) = result.unwrap();

        assert_eq!(host, Host("127.0.0.1"));

        let result = Host::parse(b"[::1]:9000/aaa/bbb");
        let (_, host) = result.unwrap();

        assert_eq!(host, Host("[::1]"));
    }

    #[test]
    fn parse_port() {
        let result = Port::parse(b":8080/aaa/bbb");
        let (_, port) = result.unwrap();

        assert_eq!(port, Port(8080));
    }

    #[test]
    fn parse_authority() {
        let result = Authority::parse(b"//example.com:8080/aaa/bbb");
        let (_, authority) = result.unwrap();

        assert_eq!(
            authority,
            Authority::new(None, Some("example.com"), Some(8080))
        );

        let result = Authority::parse(b"//admin@example.com:8080/aaa/bbb");
        let (_, authority) = result.unwrap();

        assert_eq!(
            authority,
            Authority::new(Some("admin"), Some("example.com"), Some(8080))
        );

        let result = Authority::parse(b"//admin:password@example.com/aaa/bbb");
        let (_, authority) = result.unwrap();

        assert_eq!(
            authority,
            Authority::new(Some("admin:password"), Some("example.com"), None)
        );
    }

    #[test]
    fn parse_path() {
        let result = Path::parse(b"/aaa/bbb");
        let (_, path) = result.unwrap();

        assert_eq!(path, Path(vec!["aaa", "bbb"]));

        let result = Path::parse(b"/aaa");
        let (_, path) = result.unwrap();

        assert_eq!(path, Path(vec!["aaa"]));

        let result = Path::parse(b"/");
        let (_, path) = result.unwrap();

        assert_eq!(path, Path(vec![]));

        let result = Path::parse(b"");
        let (_, path) = result.unwrap();

        assert_eq!(path, Path(vec![]));
    }

    #[test]
    fn parse_query() {
        let result = Query::parse(b"?q=1#test");
        let (_, query) = result.unwrap();

        assert_eq!(query, Query("q=1"));
    }

    #[test]
    fn parse_fragment() {
        let result = Fragment::parse(b"#test");
        let (_, fragment) = result.unwrap();

        assert_eq!(fragment, Fragment("test"));
    }

    #[test]
    fn parse_uri() {
        let result = Uri::parse(b"http://example.com/aaa/bbb");
        let (_, uri) = result.unwrap();

        assert_eq!(
            uri,
            Uri::new(
                "http",
                Some(Authority::new(None, Some("example.com"), None)),
                vec!["aaa", "bbb"],
                None,
                None
            )
        );

        let result = Uri::parse(b"https://127.0.0.1:8080?test=7");
        let (_, uri) = result.unwrap();

        assert_eq!(
            uri,
            Uri::new(
                "https",
                Some(Authority::new(None, Some("127.0.0.1"), Some(8080))),
                vec![],
                Some("test=7"),
                None
            )
        );

        let result = Uri::parse(b"ftp:///etc/passwd");
        let (_, uri) = result.unwrap();

        assert_eq!(
            uri,
            Uri::new(
                "ftp",
                Some(Authority::new(None, None, None)),
                vec!["etc", "passwd"],
                None,
                None
            )
        );
    }

    #[test]
    fn parse_uri_no_authority() {
        let result = Uri::parse(b"news:comp.infosystems.www.servers.unix");
        let (_, uri) = result.unwrap();

        assert_eq!(
            uri,
            Uri::new(
                "news",
                None,
                vec!["comp.infosystems.www.servers.unix"],
                None,
                None
            )
        );

        let result = Uri::parse(b"tel:+1-816-555-1212");
        let (_, uri) = result.unwrap();

        assert_eq!(
            uri,
            Uri::new("tel", None, vec!["+1-816-555-1212"], None, None)
        );
    }

    #[test]
    #[should_panic]
    fn parse_uri_no_scheme() {
        let url = b"http//example.com";
        let result = Uri::parse(url);
        let (_, _uri) = result.unwrap();
    }
}
