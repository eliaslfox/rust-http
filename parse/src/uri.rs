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

// Characters allowed in an URI and not given a reserved meaning
// as defined by rfc3986 2.3.
fn uri_unreserved_character(i: u8) -> bool {
    if is_alphanumeric(i) {
        return true;
    }
    let c = i.as_char();
    c == '-' || c == '.' || c == '_' || c == '~'
}

// Characters valid as sub delimiters in an URI as defined by rfc3986 2.2.
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

// Allow % where url encoded character can be present.
fn uri_encoded_character(i: u8) -> bool {
    i.as_char() == '%'
}

#[derive(PartialEq, Eq, Debug)]
struct Scheme<'a>(&'a str);

impl<'a> Scheme<'a> {
    fn valid_character(i: u8) -> bool {
        if is_alphanumeric(i) {
            return true;
        }
        let c = i.as_char();
        c == '+' || c == '-' || c == '.'
    }

    // Parse an URI scheme as defined by rfc3986 3.1.
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
    fn valid_character(i: u8) -> bool {
        uri_unreserved_character(i)
            || uri_encoded_character(i)
            || uri_sub_delimeter(i)
            || i.as_char() == ':'
    }

    // Parse a URI user_info subcomponent as defined by rfc3986 3.2.1.
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

    // Parse an URI authority as defined by rfc3986 3.2
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
struct Path<'a>(&'a str);

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
            let (i, (c, _)) = consumed(tuple((
                many0(preceded(
                    many1(tag("/")),
                    take_while1(Self::valid_path_segment_char),
                )),
                // Remove trailing slashes
                many0(tag("/")),
            )))(i)?;

            let path = u8_to_utf8(c)?;

            Ok((i, Path(path)))
        })(i)
    }

    fn iterate(&self) -> impl Iterator<Item = &'a str> {
        self.0.split('/').filter(|x| *x != "" && *x != ".")
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
struct Query<'a>(&'a str);

impl<'a> Query<'a> {
    fn valid_query_char(i: u8) -> bool {
        Path::valid_path_segment_char(i) || i.as_char() == '/' || i.as_char() == '?'
    }

    // Parse an URI authority as defined by rfc3986 3.4.
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

    // Parse an URI authority as defined by rfc3986 3.5.
    fn parse(i: Input<'a>) -> ParseResult<'_, Self> {
        context("uri query", |i| {
            let (i, query) = preceded(tag("#"), take_while(Self::valid_query_char))(i)?;
            let query = u8_to_utf8(query)?;
            Ok((i, Fragment(query)))
        })(i)
    }
}

/// A parsed URI.
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
        path: &'a str,
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

    /// Get the scheme of an URI.
    ///
    /// ```
    /// # use parse::{Uri, HttpParseError};
    ///
    /// let (_, uri) = Uri::parse(b"http://example.com/aa/bb")?;
    /// assert_eq!(uri.scheme(), "http");
    ///
    /// # Ok::<(), nom::Err<HttpParseError<&'_ [u8]>>>(())
    /// ```
    #[inline]
    pub fn scheme(&self) -> &'a str {
        self.scheme.0
    }

    /// Get the user info part of an URI.
    ///
    /// ```
    /// # use parse::{Uri, HttpParseError};
    ///
    /// let (_, uri) = Uri::parse(b"ftp://admin@example.com/aa/bb")?;
    /// assert_eq!(uri.user_info(), Some("admin"));
    ///
    /// # Ok::<(), nom::Err<HttpParseError<&'_ [u8]>>>(())
    /// ```
    #[inline]
    pub fn user_info(&self) -> Option<&'a str> {
        self.authority.and_then(|x| x.user_info).map(|x| x.0)
    }

    /// Get the host of an URI.
    ///
    /// ```
    /// # use parse::{Uri, HttpParseError};
    ///
    /// let (_, uri) = Uri::parse(b"http://example.com")?;
    /// assert_eq!(uri.host(), Some("example.com"));
    ///
    /// let (_, uri) = Uri::parse(b"https://[::1]/files")?;
    /// assert_eq!(uri.host(), Some("[::1]"));
    ///
    /// # Ok::<(), nom::Err<HttpParseError<&'_ [u8]>>>(())
    /// ```
    #[inline]
    pub fn host(&self) -> Option<&'a str> {
        self.authority.and_then(|x| x.host).map(|x| x.0)
    }

    /// Get the port of an URI if it exists. This function will not return the default port of a
    /// protocol if it is not specified in the URI.
    ///
    /// ```
    /// # use parse::{Uri, HttpParseError};
    ///
    /// let (_, uri) = Uri::parse(b"http://example.com:8080")?;
    /// assert_eq!(uri.port(), Some(8080));
    ///
    /// let (_, uri) = Uri::parse(b"http://example.com")?;
    /// assert_eq!(uri.port(), None);
    ///
    /// # Ok::<(), nom::Err<HttpParseError<&'_ [u8]>>>(())
    /// ```
    #[inline]
    pub fn port(&self) -> Option<u32> {
        self.authority.and_then(|x| x.port).map(|x| x.0)
    }

    /// Get the path of an URI. If the path is empty or the root path then this function will
    /// return an empty vector. If the URI does not have an authority such as `tel:+1-816-555-1212`
    /// then the entire path will be in a single item vector.
    ///
    /// ```
    /// # use parse::{Uri, HttpParseError};
    ///
    /// let (_, uri) = Uri::parse(b"http://example.com/aaa/bbb")?;
    /// assert_eq!(uri.path().collect::<Vec<&str>>(), vec!["aaa", "bbb"]);
    ///
    /// let (_, uri) = Uri::parse(b"tel:+1-816-555-1212")?;
    /// assert_eq!(uri.path().collect::<Vec<&str>>(), vec!["+1-816-555-1212"]);
    ///
    /// # Ok::<(), nom::Err<HttpParseError<&'_ [u8]>>>(())
    /// ```
    #[inline]
    pub fn path(&self) -> impl Iterator<Item = &'a str> {
        self.path.iterate()
    }

    /// Get the query of an URI.
    ///
    /// ```
    ///
    /// # use parse::{Uri, HttpParseError};
    ///
    /// let (_, uri) = Uri::parse(b"http://example.com:8080?test=1&a=b")?;
    /// assert_eq!(uri.query(), Some("test=1&a=b"));
    ///
    /// # Ok::<(), nom::Err<HttpParseError<&'_ [u8]>>>(())
    /// ```
    #[inline]
    pub fn query(&self) -> Option<&'a str> {
        self.query.map(|x| x.0)
    }

    /// Get the fragment of an URI.
    ///
    /// ```
    /// # use parse::{Uri, HttpParseError};
    ///
    /// let (_, uri) = Uri::parse(b"http://example.com:8080?test=1&a=b#aa/bb")?;
    /// assert_eq!(uri.fragment(), Some("aa/bb"));
    ///
    /// # Ok::<(), nom::Err<HttpParseError<&'_ [u8]>>>(())
    /// ```
    #[inline]
    pub fn fragment(&self) -> Option<&'a str> {
        self.fragment.map(|x| x.0)
    }

    /// Attempt to parse a buffer into an URI.
    /// The implemented URI parsing is somewhat limited. Values are not lowercased and
    /// thus the following will not compare as equal `http://EXAMPLE.com` and `http://example.com` even
    /// though they are defined to be. Parsing also does not preform url decoding and will leave hex
    /// encoded characters such as `%20` as is. Parsing does however implement path normalization by
    /// removing path segments in the form of `/./` and stripping double and trailing slashes.
    ///
    /// The following will all compare equal:
    /// - `http://example.com/a/b`
    /// - `http://example.com/a//b`
    /// - `http://example.com/a/./b`
    /// - `http://example.com/a/b//`
    ///
    /// Parsing grammar and specification is taken from [RFC3986](https://tools.ietf.org/html/rfc3986).
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
                    (i, Path(path))
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

        assert_eq!(path.iterate().collect::<Vec<&str>>(), vec!["aaa", "bbb"]);

        let result = Path::parse(b"/aaa");
        let (_, path) = result.unwrap();

        assert_eq!(path.iterate().collect::<Vec<&str>>(), vec!["aaa"]);

        let result = Path::parse(b"/");
        let (_, path) = result.unwrap();

        let empty: Vec<&str> = vec![];

        assert_eq!(path.iterate().collect::<Vec<&str>>(), empty);

        let result = Path::parse(b"");
        let (_, path) = result.unwrap();

        assert_eq!(path.iterate().collect::<Vec<&str>>(), empty);
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
                "/aaa/bbb",
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
                "",
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
                "/etc/passwd",
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
                "comp.infosystems.www.servers.unix",
                None,
                None
            )
        );

        let result = Uri::parse(b"tel:+1-816-555-1212");
        let (_, uri) = result.unwrap();

        assert_eq!(uri, Uri::new("tel", None, "+1-816-555-1212", None, None));
    }

    #[test]
    #[should_panic]
    fn parse_uri_no_scheme() {
        let uri = b"http//example.com";
        let result = Uri::parse(uri);
        let (_, _uri) = result.unwrap();
    }

    #[test]
    fn parse_uri_path_normalization() {
        let uri1 = b"http://example.com/a/b";
        let uri2 = b"http://example.com/a//b";
        let uri3 = b"http://example.com/a/./b";
        let uri4 = b"http://example.com/a/b//";

        let (_, uri1) = Uri::parse(uri1).unwrap();
        let (_, uri2) = Uri::parse(uri2).unwrap();
        let (_, uri3) = Uri::parse(uri3).unwrap();
        let (_, uri4) = Uri::parse(uri4).unwrap();

        assert_eq!(uri1.path().collect::<Vec<&str>>(), vec!["a", "b"]);
        assert_eq!(uri2.path().collect::<Vec<&str>>(), vec!["a", "b"]);
        assert_eq!(uri3.path().collect::<Vec<&str>>(), vec!["a", "b"]);
        assert_eq!(uri4.path().collect::<Vec<&str>>(), vec!["a", "b"]);
    }
}
