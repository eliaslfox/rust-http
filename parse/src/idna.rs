/*
 * IDNA Processing
 *
 * The root IDNA document is RFC 5890 https://datatracker.ietf.org/doc/html/rfc5890
 * The IDNA protocol is defined in RFC 5891 https://datatracker.ietf.org/doc/html/rfc5891
 * The IDNA Bidi rules are in RFC 5893 https://datatracker.ietf.org/doc/html/rfc5893
 * The IDNA contextual code point rules are in https://datatracker.ietf.org/doc/html/rfc5892
 *
 * IDNA Compatabilty Processing is defined in tr46 https://www.unicode.org/reports/tr46
 */

#![allow(dead_code)]

use std::{borrow::Cow, str::Utf8Error};

use unic::{
    normal::StrNormalForm,
    ucd::{normal::is_combining_mark, BidiClass, CanonicalCombiningClass, CharBidiClass},
};
use unic_idna_mapping::Mapping;
use unicode_joining_type::{get_joining_type, JoiningType};
use unicode_script::{Script, UnicodeScript};

#[derive(Debug)]
pub(crate) enum IDNAProcessingError {
    Utf8(Utf8Error),
    InvalidCharacter(char),
    InvalidLabel(String),
    InvalidPunycode(String),
    InvalidLabelLength(String),
    InvalidDomainLength(String),
    InvalidDomain(String),
}

impl From<Utf8Error> for IDNAProcessingError {
    fn from(v: Utf8Error) -> Self {
        Self::Utf8(v)
    }
}

// Unicode IDNA Mapping as defined by https://www.unicode.org/reports/tr46/#ProcessingStepNormalize
//
// For each code point in the domain_name string, look up the status value in Section 5, IDNA Mapping Table, and take the following actions:
//     disallowed: Leave the code point unchanged in the string, and record that there was an error.
//     ignored: Remove the code point from the string. This is equivalent to mapping the code point to an empty string.
//     mapped: Replace the code point in the string by the value for the mapping in Section 5, IDNA Mapping Table.
//     deviation:
//     If Transitional_Processing, replace the code point in the string by the value for the mapping in Section 5, IDNA Mapping Table .
//     Otherwise, leave the code point unchanged in the string.
//     valid: Leave the code point unchanged in the string.
fn idna_mapping(
    domain_name: Cow<str>,
    transitional_processing: bool,
    use_std3_ascii_rules: bool,
) -> Result<Cow<str>, IDNAProcessingError> {
    // If every character in the string is a number, lowecase letter, "-", or "." then every character is valid
    // skip building a new string and return the original one
    if domain_name
        .chars()
        .all(|c| matches!(c, 'a'..='z') || c.is_ascii_digit() || c == '.' || c == '-')
    {
        return Ok(domain_name);
    }

    let mut out = String::with_capacity(domain_name.len());

    for c in domain_name.chars() {
        match Mapping::of(c) {
            Mapping::Valid => out.push(c),
            Mapping::Ignored => {}
            Mapping::Mapped(s) => out.push_str(s),
            Mapping::Deviation(s) => {
                if transitional_processing {
                    out.push_str(s);
                } else {
                    out.push(c);
                }
            }
            Mapping::Disallowed => return Err(IDNAProcessingError::InvalidCharacter(c)),
            Mapping::DisallowedStd3Valid => {
                if use_std3_ascii_rules {
                    return Err(IDNAProcessingError::InvalidCharacter(c));
                }
                out.push(c);
            }
            Mapping::DisallowedStd3Mapped(s) => {
                if use_std3_ascii_rules {
                    return Err(IDNAProcessingError::InvalidCharacter(c));
                }
                out.push_str(s);
            }
        }
    }

    Ok(Cow::Owned(out))
}

fn unicode_normalize_form_c(domain_name: Cow<str>) -> Cow<str> {
    // Note: Text exclusively containing ASCII characters (U+0000..U+007F) is left unaffected by all of the Normalization Forms.
    // https://unicode.org/reports/tr15/#Description_Norm
    if domain_name.is_ascii() {
        return domain_name;
    }

    Cow::Owned(domain_name.nfc().collect())
}

// Unicode codepoint contextual rules validation
// https://datatracker.ietf.org/doc/html/rfc5892#appendix-A
#[allow(clippy::too_many_lines)]
fn label_has_valid_joiners(label: &'_ str) -> bool {
    // If Canonical_Combining_Class(Before(cp)) .eq.  Virama Then True;
    // Or
    //  If RegExpMatch((Joining_Type:{L,D})(Joining_Type:T)*\u200C
    //   (Joining_Type:T)*(Joining_Type:{R,D})) Then True;
    fn valid_zero_width_non_joiner(
        c: char,
        before: Option<char>,
        _after: Option<char>,
        label: &'_ str,
        index: usize,
    ) -> bool {
        if c != '\u{200C}' {
            return true;
        }

        if let Some(before) = before {
            if CanonicalCombiningClass::of(before) == CanonicalCombiningClass::Virama {
                return true;
            };
        }

        let label: Vec<_> = label.chars().collect();

        if index == 0 {
            return false;
        }

        {
            let mut i = index - 1;

            while let Some(c) = label.get(i) {
                if get_joining_type(*c) == JoiningType::Transparent {
                    i -= i;
                    continue;
                }
                break;
            }

            if let Some(c) = label.get(i) {
                if !matches!(
                    get_joining_type(*c),
                    JoiningType::LeftJoining | JoiningType::DualJoining
                ) {
                    return false;
                }
            } else {
                return false;
            }
        }

        {
            let mut i = index + 1;

            while let Some(c) = label.get(i) {
                if get_joining_type(*c) == JoiningType::Transparent {
                    i += 1;
                    continue;
                }
                break;
            }

            if let Some(c) = label.get(i) {
                if !matches!(
                    get_joining_type(*c),
                    JoiningType::RightJoining | JoiningType::DualJoining
                ) {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    // If Canonical_Combining_Class(Before(cp)) .eq.  Virama Then True;
    fn valid_zero_width_joiner(c: char, before: Option<char>, _after: Option<char>) -> bool {
        if c != '\u{200D}' {
            return true;
        }

        if let Some(before) = before {
            return CanonicalCombiningClass::of(before) == CanonicalCombiningClass::Virama;
        }

        false
    }

    //  If Before(cp) .eq.  U+006C And
    //   After(cp) .eq.  U+006C Then True;
    fn valid_middle_dot(c: char, before: Option<char>, after: Option<char>) -> bool {
        if c != '\u{00b7}' {
            return true;
        }

        if matches!((before, after), (Some('\u{006C}'), Some('\u{006C}'))) {
            return true;
        }

        false
    }

    // If Script(After(cp)) .eq.  Greek Then True;
    fn valid_greek_lower_numeral_sign(c: char, _before: Option<char>, after: Option<char>) -> bool {
        if c != '\u{0375}' {
            return true;
        }

        if let Some(after) = after {
            return after.script() == Script::Greek;
        }

        false
    }

    // If Script(Before(cp)) .eq.  Hebrew Then True;
    fn valid_hebrew_punctuation_geresh(
        c: char,
        before: Option<char>,
        _after: Option<char>,
    ) -> bool {
        if c != '\u{05F3}' {
            return true;
        }

        if let Some(before) = before {
            return before.script() == Script::Hebrew;
        }

        false
    }

    // For All Characters:
    //    If Script(cp) .in. {Hiragana, Katakana, Han} Then True;
    // End For;
    fn valid_katakana_middle_dot(c: char, label: &'_ str) -> bool {
        if c != '\u{30FB}' {
            return true;
        }

        label.chars().any(|c| {
            matches!(
                c.script(),
                Script::Hiragana | Script::Katakana | Script::Han
            )
        })
    }

    // For All Characters:
    //     If cp .in. 06F0..06F9 Then False;
    // End For;
    fn valid_arabic_indic_digit(c: char, label: &'_ str) -> bool {
        if !matches!(c, '\u{0660}'..='\u{0669}') {
            return true;
        }

        !label.chars().any(|c| matches!(c, '\u{06F0}'..='\u{06F9}'))
    }

    fn valid_char(
        c: char,
        before: Option<char>,
        after: Option<char>,
        label: &'_ str,
        index: usize,
    ) -> bool {
        valid_zero_width_non_joiner(c, before, after, label, index)
            && valid_zero_width_joiner(c, before, after)
            && valid_middle_dot(c, before, after)
            && valid_greek_lower_numeral_sign(c, before, after)
            && valid_hebrew_punctuation_geresh(c, before, after)
            && valid_katakana_middle_dot(c, label)
            && valid_arabic_indic_digit(c, label)
    }

    // For All Characters:
    //     If cp .in. 0660..0669 Then False;
    // End For;
    //
    // This rule is checked by valid_arabic_indic_digit

    // Iterate across label tracking the next and previous elements
    let mut iter = label.chars();
    let mut prev = None;
    let mut cur = iter.next().unwrap();
    let mut next = iter.next();
    let mut index = 0;

    loop {
        if !valid_char(cur, prev, next, label, index) {
            return false;
        }

        prev = Some(cur);
        cur = match next {
            Some(x) => x,
            None => return true,
        };
        next = iter.next();

        index += 1;
    }
}

// A Bidi domain name is a domain name containing at least one character with Bidi_Class R, AL, or AN
// https://www.unicode.org/reports/tr46/#Notation
fn is_domain_bidi(label: &'_ str) -> bool {
    label.chars().any(|c| {
        matches!(
            c.bidi_class(),
            BidiClass::RightToLeft | BidiClass::ArabicLetter | BidiClass::ArabicNumber
        )
    })
}

// If CheckBidi, and if the domain name is a  Bidi domain name, then the label must satisfy all six of the numbered conditions in RFC 5893, Section 2.
// https://www.rfc-editor.org/rfc/rfc5893.html#section-2
fn valid_bidi_rtl(label: &'_ str) -> bool {
    // In an RTL label, if an EN is present, no AN may be present, and vice versa.
    let mut aribic_number = false;
    let mut european_number = false;

    // In an RTL label, only characters with the Bidi properties R, AL,
    // AN, EN, ES, CS, ET, ON, BN, or NSM are allowed.
    for c in label.chars() {
        match c.bidi_class() {
            BidiClass::RightToLeft
            | BidiClass::ArabicLetter
            | BidiClass::EuropeanSeparator
            | BidiClass::CommonSeparator
            | BidiClass::EuropeanTerminator
            | BidiClass::OtherNeutral
            | BidiClass::BoundaryNeutral
            | BidiClass::NonspacingMark => continue,
            BidiClass::ArabicNumber => {
                aribic_number = true;
                if european_number {
                    return false;
                }
            }
            BidiClass::EuropeanNumber => {
                european_number = true;
                if aribic_number {
                    return false;
                }
            }
            _ => return false,
        }
    }

    // In an RTL label, the end of the label must be a character with
    // Bidi property R, AL, EN, or AN, followed by zero or more
    // characters with Bidi property NSM
    for c in label.chars().rev() {
        if matches!(
            c.bidi_class(),
            BidiClass::RightToLeft
                | BidiClass::ArabicLetter
                | BidiClass::EuropeanNumber
                | BidiClass::ArabicNumber
        ) {
            break;
        }
        if c.bidi_class() == BidiClass::NonspacingMark {
            continue;
        }

        return false;
    }

    true
}

// If CheckBidi, and if the domain name is a  Bidi domain name, then the label must satisfy all six of the numbered conditions in RFC 5893, Section 2.
// https://www.rfc-editor.org/rfc/rfc5893.html#section-2
fn valid_bidi_ltr(label: &'_ str) -> bool {
    // In an LTR label, only characters with the Bidi properties L, EN,
    // ES, CS, ET, ON, BN, or NSM are allowed.
    for c in label.chars() {
        match c.bidi_class() {
            BidiClass::LeftToRight
            | BidiClass::EuropeanNumber
            | BidiClass::EuropeanSeparator
            | BidiClass::EuropeanTerminator
            | BidiClass::OtherNeutral
            | BidiClass::BoundaryNeutral
            | BidiClass::NonspacingMark => continue,
            _ => return false,
        }
    }

    // In an LTR label, the end of the label must be a character with
    // Bidi property L or EN, followed by zero or more characters with
    // Bidi property NSM.
    for c in label.chars().rev() {
        if matches!(
            c.bidi_class(),
            BidiClass::LeftToRight | BidiClass::EuropeanNumber
        ) {
            break;
        }
        if c.bidi_class() == BidiClass::NonspacingMark {
            continue;
        }
        return false;
    }

    true
}

fn valid_bidi(label: &'_ str) -> bool {
    match label.chars().next().unwrap().bidi_class() {
        BidiClass::RightToLeft | BidiClass::ArabicLetter => {
            if !valid_bidi_rtl(label) {
                return false;
            }
        }
        BidiClass::LeftToRight => {
            if !valid_bidi_ltr(label) {
                return false;
            }
        }
        _ => return false,
    }

    true
}

// IDNA Label Validation
// https://www.unicode.org/reports/tr46/#Validity_Criteria
//
// This function does not implement the additional checks described in
// https://www.unicode.org/reports/tr46/#UseSTD3ASCIIRules because UseSTD3ASCIIRules is always set
// for URLs as per https://url.spec.whatwg.org/#host-writing
//
// Bidi validation is checked seperately
#[allow(clippy::fn_params_excessive_bools)]
fn label_is_valid(
    label: &'_ str,
    check_hypnens: bool,
    check_joiners: bool,
    transitional_processing: bool,
) -> bool {
    // The label must be in Unicode Normalization Form NFC
    if label != unicode_normalize_form_c(Cow::Borrowed(label)) {
        return false;
    }

    // If CheckHyphens, the label must not contain a U+002D HYPHEN-MINUS character in both the third and fourth positions
    if check_hypnens
        && matches!(
            (label.chars().nth(2), label.chars().nth(3)),
            (Some('-'), Some('-'))
        )
    {
        return false;
    }

    // If CheckHyphens, the label must neither begin nor end with a U+002D HYPHEN-MINUS character.
    if check_hypnens && (label.starts_with('-') || label.chars().rev().next() == Some('-')) {
        return false;
    }

    // The label must not contain a U+002E ( . ) FULL STOP.
    if label.chars().any(|c| c == '.') {
        return false;
    }

    // The label must not begin with a combining mark, that is: General_Category=Mark.
    if let Some(first_char) = label.chars().next() {
        if is_combining_mark(first_char) {
            return false;
        }
    }

    // Each code point in the label must only have certain status values according to Section 5, IDNA Mapping Table:
    //     For Transitional Processing, each value must be valid.
    //     For Nontransitional Processing, each value must be either valid or deviation.
    for c in label.chars() {
        match Mapping::of(c) {
            Mapping::Valid => continue,
            Mapping::Deviation(_) => {
                if transitional_processing {
                    return false;
                }
            }
            _ => return false,
        }
    }

    // If CheckJoiners, the label must satisify the ContextJ rules from Appendix A, in RFC 5892 https://www.rfc-editor.org/rfc/rfc5892.html#appendix-A
    if check_joiners && !label.is_ascii() && !label_has_valid_joiners(label) {
        return false;
    }

    true
}

// IDNA Main Processing Steps
// https://www.unicode.org/reports/tr46/#Processing
#[allow(clippy::fn_params_excessive_bools)]
fn process_idna(
    domain_name: Cow<str>,
    use_std3_ascii_rules: bool,
    check_hypnens: bool,
    check_bidi: bool,
    check_joiners: bool,
    transitional_processing: bool,
) -> Result<Cow<str>, IDNAProcessingError> {
    if domain_name.is_empty() {
        return Err(IDNAProcessingError::InvalidDomain(domain_name.into_owned()));
    }

    // https://www.unicode.org/reports/tr46/#ProcessingStepMap
    let domain_name = idna_mapping(domain_name, transitional_processing, use_std3_ascii_rules)?;

    // Normalize the domain_name string to Unicode Normalization Form C.
    // https://www.unicode.org/reports/tr46/#ProcessingStepNormalize
    let mut domain_name = unicode_normalize_form_c(domain_name);

    // Because domains can be terminated with "." the last label can be empty
    let mut last_label = false;

    // If any labels are encoded with punycode then the label must be rebuilt with only NR-labels
    // and U-labels
    let mut out = String::new();
    let rebuild_domain_name = domain_name
        .split('.')
        .any(|label| label.starts_with("xn--"));

    let mut first_label = true;

    // Break the string into labels at U+002E ( . ) FULL STOP.
    // https://www.unicode.org/reports/tr46/#ProcessingStepBreak
    for label in domain_name.split('.') {
        if label.is_empty() {
            if last_label {
                return Err(IDNAProcessingError::InvalidLabel(label.to_owned()));
            }

            last_label = true;
            if rebuild_domain_name {
                out.push('.');
            }
            continue;
        }

        if first_label {
            first_label = false;
        } else if rebuild_domain_name {
            out.push('.');
        }

        if last_label {
            return Err(IDNAProcessingError::InvalidDomain(domain_name.into_owned()));
        }

        // If the label starts with “xn--”:
        //     Attempt to convert the rest of the label to Unicode according to Punycode
        //     Verify that the label meets the validity criteria in Section 4.1, Validity Criteria for Nontransitional Processing.
        // https://www.unicode.org/reports/tr46/#ProcessingStepPunycode
        if label.starts_with("xn--") {
            // Attempt to convert the rest of the label to Unicode according to Punycode
            let label: String = label.chars().skip(4).collect();
            let label = match punycode::decode(&label) {
                Ok(label) => label,
                Err(_) => return Err(IDNAProcessingError::InvalidPunycode(label)),
            };

            // Verify that the label meets the validity criteria in Section 4.1, Validity Criteria for Nontransitional Processing
            if !label_is_valid(&label, check_hypnens, check_joiners, false) {
                return Err(IDNAProcessingError::InvalidLabel(label));
            }

            out.push_str(&label);
            continue;
        }

        // If the label does not start with “xn--”:
        //     Verify that the label meets the validity criteria in Section 4.1, Validity Criteria for the input Processing choice (Transitional or Nontransitional)
        // https://www.unicode.org/reports/tr46/#ProcessingStepNonPunycode
        if !label_is_valid(label, check_hypnens, check_joiners, transitional_processing) {
            return Err(IDNAProcessingError::InvalidLabel(label.to_owned()));
        }
        if rebuild_domain_name {
            out.push_str(label);
        }
    }

    if rebuild_domain_name {
        domain_name = Cow::Owned(out);
    }

    // If CheckBidi, and if the domain name is a  Bidi domain name, then the label must satisfy all
    // six of the numbered conditions in RFC 5893, Section 2
    // https://datatracker.ietf.org/doc/html/rfc5893#section-2
    // The first character must be a character with Bidi property L, R, or AL.
    // If it has the R or AL property, it is an RTL label; if it has the L property, it is an LTR label.
    if check_bidi && is_domain_bidi(&domain_name) {
        for label in domain_name.split('.') {
            if !label.is_empty() && !valid_bidi(label) {
                return Err(IDNAProcessingError::InvalidLabel(label.to_owned()));
            }
        }
    }

    Ok(domain_name)
}

// IDNA ToASCII
// https://www.unicode.org/reports/tr46/#ToASCII
#[allow(clippy::fn_params_excessive_bools)]
pub(crate) fn idna_unicode_to_ascii(
    domain_name: &'_ str,
    check_hypnens: bool,
    check_bidi: bool,
    check_joiners: bool,
    use_std3_ascii_rules: bool,
    transitional_processing: bool,
    verify_dns_length: bool,
) -> Result<Cow<str>, IDNAProcessingError> {
    // To the input domain_name, apply the Processing Steps in Section 4, Processing, using the input boolean flags Transitional_Processing, CheckHyphens, CheckBidi, CheckJoiners, and UseSTD3ASCIIRules
    let domain_name = process_idna(
        Cow::Borrowed(domain_name),
        use_std3_ascii_rules,
        check_hypnens,
        check_bidi,
        check_joiners,
        transitional_processing,
    )?;

    // If the domain_name is ascii only skip punycode conversion
    let domain_name = if domain_name.is_ascii() {
        domain_name
    } else {
        let mut out = String::with_capacity(domain_name.len());
        let mut first = true;
        for label in domain_name.split('.') {
            // Place "." between each label
            if first {
                first = false;
            } else {
                out.push('.');
            }

            // If the label is ASCII convert append it
            // otherwise convert the label to punycode and append the result
            if label.is_ascii() {
                out.push_str(label);
            } else {
                out.push_str("xn--");
                out.push_str(&punycode::encode(label).unwrap()); // NOTE: this should never fail, the unicode in label was verified by process_idna
            }
        }
        Cow::Owned(out)
    };

    // If VerifyDnsLength flag is true, then verify DNS length restrictions. This may record an error. For more information, see [STD13] and [STD3].
    //     The length of the domain name, excluding the root label and its dot, is from 1 to 253.
    //     The length of each label is from 1 to 63.
    if verify_dns_length {
        let domain_name_len = if domain_name.ends_with('.') {
            domain_name.len() - 1
        } else {
            domain_name.len()
        };

        if !matches!(domain_name_len, 1..=253) {
            return Err(IDNAProcessingError::InvalidDomainLength(
                domain_name.into_owned(),
            ));
        }

        let mut last_label = false;
        for label in domain_name.split('.') {
            if last_label {
                return Err(IDNAProcessingError::InvalidDomain(domain_name.into_owned()));
            }

            if label.is_empty() {
                last_label = true;
                continue;
            }
            if !matches!(label.len(), 1..=63) {
                return Err(IDNAProcessingError::InvalidLabelLength(label.to_owned()));
            }
        }
    }

    Ok(domain_name)
}

// IDNA ToUnicode
// https://www.unicode.org/reports/tr46/#ToUnicode
#[cfg(test)]
#[allow(clippy::fn_params_excessive_bools)]
fn idna_ascii_to_unicode(
    domain_name: &'_ str,
    check_hypnens: bool,
    check_bidi: bool,
    check_joiners: bool,
    use_std3_ascii_rules: bool,
    transitional_processing: bool,
) -> Result<Cow<str>, IDNAProcessingError> {
    let domain_name = process_idna(
        Cow::Borrowed(domain_name),
        use_std3_ascii_rules,
        check_hypnens,
        check_bidi,
        check_joiners,
        transitional_processing,
    )?;

    Ok(domain_name)
}

#[cfg(test)]
mod test {
    use std::{
        fs::File,
        io::{BufRead, BufReader},
    };

    use assert_no_alloc::assert_no_alloc;

    use crate::idna::idna_unicode_to_ascii;

    use super::idna_ascii_to_unicode;

    // https://www.unicode.org/reports/tr46/#Conformance_Testing
    #[test]
    #[allow(clippy::similar_names)]
    fn idna_conformance() {
        let file = File::open("./tests/IdnaTestV2.txt").unwrap();
        let lines = BufReader::new(file).lines();

        for line in lines {
            let line = line.unwrap();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<_> = line.split("; ").collect();

            let input = parts[0];
            let to_unicode = parts[1];
            let to_unicode_status = parts[2];
            let to_ascii_n = parts[3];
            let to_ascii_n_status = parts[4];
            let to_ascii_t = parts[5];
            let to_ascii_t_status = parts[6];

            dbg!(&input);

            let to_unicode_expected = if to_unicode.is_empty() {
                input
            } else {
                to_unicode
            };

            let to_unicode_success = to_unicode_status.is_empty();

            let unicode_res = idna_ascii_to_unicode(input, true, true, true, true, false);
            if to_unicode_success {
                assert_eq!(to_unicode_expected, unicode_res.unwrap());
            } else {
                assert!(unicode_res.is_err());
            }

            let to_ascii_n_expected = if to_ascii_n.is_empty() {
                to_unicode_expected
            } else {
                to_ascii_n
            };

            let to_ascii_n_success = if to_ascii_n_status.is_empty() {
                to_unicode_success
            } else {
                to_ascii_n_status == "[]"
            };

            let to_ascii_n_res = idna_unicode_to_ascii(input, true, true, true, true, false, true);

            if to_ascii_n_success {
                assert_eq!(to_ascii_n_expected, to_ascii_n_res.unwrap());
            } else {
                assert!(to_ascii_n_res.is_err());
            }

            let to_ascii_t_expected = if to_ascii_t.is_empty() {
                to_ascii_n_expected
            } else {
                to_ascii_t
            };

            let to_ascii_t_success = if to_ascii_t_status.starts_with(" #") {
                to_ascii_n_success
            } else {
                to_ascii_t_status.starts_with("[]")
            };

            let to_ascii_t_res = idna_unicode_to_ascii(input, true, true, true, true, true, true);
            if to_ascii_t_success {
                assert_eq!(to_ascii_t_expected, to_ascii_t_res.unwrap());
            } else {
                assert!(to_ascii_t_res.is_err());
            }
        }
    }

    // Processing domain names comprised of only NR-labels should not require allocations
    #[test]
    fn test_idna_no_alloc() {
        assert_no_alloc(|| {
            let res = idna_unicode_to_ascii("example.com", true, true, true, true, false, true);
            assert!(res.is_ok());
        });
    }
}
