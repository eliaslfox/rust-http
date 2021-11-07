use std::borrow::Cow;

// A C0 control is a code point in the range U+0000 NULL to U+001F INFORMATION SEPARATOR ONE, inclusive.
fn is_c0_control(c: char) -> bool {
    matches!(c, '\u{00}'..='\u{1F}')
}

// The C0 control percent-encode set are the C0 controls and all code points greater than U+007E (~).
fn is_c0_control_percent_encode(c: char) -> bool {
    is_c0_control(c) || c > '\u{7E}'
}

// The fragment percent-encode set is the C0 control percent-encode set and U+0020 SPACE, U+0022 ("), U+003C (<), U+003E (>), and U+0060 (`).
pub(crate) fn is_fragment_percent_encode(c: char) -> bool {
    is_c0_control_percent_encode(c) || c == ' ' || c == '"' || c == '<' || c == '>' || c == '`'
}

// The query percent-encode set is the C0 control percent-encode set and U+0020 SPACE, U+0022 ("), U+0023 (#), U+003C (<), and U+003E (>).
pub(crate) fn is_query_percent_encode(c: char) -> bool {
    is_c0_control_percent_encode(c)
        || c == ' '
        || c == '"'
        || c == '#'
        || c == '<'
        || c == '<'
        || c == '>'
}

// The special-query percent-encode set is the query percent-encode set and U+0027 (').
pub(crate) fn is_special_query_percent_encode(c: char) -> bool {
    is_query_percent_encode(c) || c == '\''
}

// The path percent-encode set is the query percent-encode set and U+003F (?), U+0060 (`), U+007B ({), and U+007D (}).
pub(crate) fn is_path_percent_encode(c: char) -> bool {
    is_query_percent_encode(c) || c == '?' || c == '`' || c == '{' || c == '}'
}

// The userinfo percent-encode set is the path percent-encode set and U+002F (/), U+003A (:), U+003B (;), U+003D (=), U+0040 (@), U+005B ([) to U+005E (^), inclusive, and U+007C (|).
pub(crate) fn is_userinfo_percent_encode(c: char) -> bool {
    is_path_percent_encode(c)
        || c == '/'
        || c == ':'
        || c == ';'
        || c == '='
        || c == '@'
        || matches!(c, '['..='^')
        || c == '|'
}

// The component percent-encode set is the userinfo percent-encode set and U+0024 ($) to U+0026 (&), inclusive, U+002B (+), and U+002C (,).
pub(crate) fn is_component_percent_encode(c: char) -> bool {
    is_userinfo_percent_encode(c) || matches!(c, '$'..='&') || c == '+' || c == ','
}

fn u8_to_hex(c: u8) -> char {
    match c {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'A',
        11 => 'B',
        12 => 'C',
        13 => 'D',
        14 => 'E',
        15 => 'F',
        _ => panic!(),
    }
}

fn u8_to_hex_pair(c: u8) -> (char, char) {
    let c_high = c >> 4;
    let c_low = c & 0x0F;
    (u8_to_hex(c_high), u8_to_hex(c_low))
}

pub(crate) fn percent_encode_char(
    c: char,
    mut out: String,
    space_as_plus: bool,
    percent_encode_set: impl Fn(char) -> bool,
) -> String {
    // C does not need to be encoded according to percent_encode_set
    if !percent_encode_set(c) {
        out.push(c);
        return out;
    }

    if space_as_plus {
        out.push('+');
        return out;
    }

    let mut buf = [0; 4];

    for byte in c.encode_utf8(&mut buf).bytes() {
        out.push('%');
        let (char_high, char_low) = u8_to_hex_pair(byte);
        out.push(char_high);
        out.push(char_low);
    }

    out
}

pub(crate) fn percent_encode(
    input: Cow<str>,
    space_as_plus: bool,
    percent_encode_set: impl Fn(char) -> bool,
) -> Cow<str> {
    // All characters are already valid
    if !input.chars().any(&percent_encode_set) {
        return input;
    }

    let mut out = String::with_capacity(input.len());

    for c in input.chars() {
        out = percent_encode_char(c, out, space_as_plus, &percent_encode_set);
    }

    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_no_alloc::assert_no_alloc;

    #[test]
    fn test_percent_encode() {
        assert_eq!(
            "%23",
            percent_encode(Cow::Borrowed("\u{23}"), false, |_| true)
        );

        assert_eq!(
            "%7F",
            percent_encode(Cow::Borrowed("\u{7F}"), false, |_| true)
        );
        assert_eq!(
            "%E2%89%A1",
            percent_encode(Cow::Borrowed("≡"), false, is_userinfo_percent_encode)
        );
        assert_eq!(
            "%E2%80%BD",
            percent_encode(Cow::Borrowed("‽"), false, is_userinfo_percent_encode)
        );
        assert_eq!(
            "Say%20what%E2%80%BD",
            percent_encode(
                Cow::Borrowed("Say what‽"),
                false,
                is_userinfo_percent_encode
            )
        );
    }

    #[test]
    fn percent_encode_fast_path() {
        assert_eq!(
            "Hello, World!",
            assert_no_alloc(|| percent_encode(
                Cow::Borrowed("Hello, World!"),
                false,
                is_c0_control_percent_encode
            ))
        );
    }
}
