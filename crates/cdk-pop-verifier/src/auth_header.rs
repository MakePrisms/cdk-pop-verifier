//! Parser for the MPP-Cashu `Authorization: Payment` request header.
//!
//! Both the 402 challenge (`WWW-Authenticate: Payment method="cashu",
//! challenge="creqA…"`) and the retry credentials (`Authorization:
//! Payment method="cashu", token="cashuB…"`) ride the RFC 7235 auth
//! envelope. RFC 7235 §2.1 fixes the wire shape as:
//!
//! ```text
//!     credentials = auth-scheme 1*SP <auth-param>
//!     auth-param  = token BWS "=" BWS ( token / quoted-string )
//! ```
//!
//! This module parses the credentials side: given an
//! `Authorization` header value, extract the `token` parameter when the
//! scheme is `Payment` and `method="cashu"`.
//!
//! ## Parsing decisions (v1, MPP-Cashu shape pre-spec)
//!
//! - **Quoted-string values only.** RFC 7235 allows either `token` or
//!   `quoted-string` for auth-param values. Cashu tokens contain `=`
//!   padding and `creqA…` strings contain `+`/`/`/`=`, all of which are
//!   illegal in the RFC 7230 `token` production. Requiring quoted-strings
//!   eliminates the ambiguity and keeps the parser small. A future
//!   formalization of MPP-Cashu can relax this if needed.
//! - **Case-insensitive scheme + param names.** RFC 7235 says both are
//!   case-insensitive (§2.1, §2.2). Values stay case-sensitive — Cashu
//!   tokens are.
//! - **No support for the `token68` short form.** That form has no `=`-
//!   separated params, which can't carry both `method` and `token`.
//! - **Scheme mismatch is not an error here.** Returning
//!   [`AuthParseError::UnknownScheme`] lets the caller treat a non-
//!   `Payment` scheme as "no MPP-Cashu attempt" (→ 402) rather than a
//!   client error (→ 400). The middleware does exactly that.

use thiserror::Error;

/// HTTP auth-scheme for the MPP-Cashu envelope. Case-insensitive per
/// RFC 7235 §2.1.
pub const PAYMENT_SCHEME: &str = "Payment";

/// Required value for the `method` param on the MPP-Cashu envelope.
/// Identifies the method extension under MPP. Case-sensitive on the
/// wire (RFC 7235 only fixes the *key* as case-insensitive).
pub const CASHU_METHOD: &str = "cashu";

/// Param name carrying the `cashuB…` token on the retry request.
pub const TOKEN_PARAM: &str = "token";

/// Param name carrying the method discriminator on both the 402
/// challenge and the retry request.
pub const METHOD_PARAM: &str = "method";

/// Param name carrying the `creqA…` payment-request on the 402.
/// Defined here for completeness; the middleware uses it when building
/// `WWW-Authenticate`.
pub const CHALLENGE_PARAM: &str = "challenge";

/// Why an `Authorization: Payment …` header failed to parse.
///
/// Distinct variants exist so the caller (the middleware) can choose
/// the HTTP response: `UnknownScheme` means "client never attempted
/// Payment", which the middleware treats as no-auth (→ 402); every
/// other variant is "client tried to use MPP-Cashu but the header is
/// malformed" (→ 400).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthParseError {
    /// First whitespace-separated token is not `Payment`. Includes
    /// missing scheme (header empty or starts with `=`/etc.).
    #[error("auth scheme is not 'Payment'")]
    UnknownScheme,

    /// Header parses but `method=` is missing.
    #[error("Payment header missing 'method' parameter")]
    MissingMethod,

    /// `method=` is present but its value is not `cashu`.
    #[error("Payment header method must be 'cashu', got {0:?}")]
    WrongMethod(String),

    /// Header parses with `method="cashu"` but `token=` is missing.
    #[error("Payment header missing 'token' parameter")]
    MissingToken,

    /// Param section failed to parse: missing `=`, unterminated
    /// quoted-string, value is token-style instead of quoted, etc.
    #[error("malformed Payment auth params: {0}")]
    MalformedParams(String),
}

/// Parse an `Authorization: Payment method="cashu", token="cashuB…"`
/// header value and return the `token` value.
///
/// On success the returned slice borrows from the input — the caller
/// owns the lifetime. The slice is the unescaped contents of the
/// `token` quoted-string (backslash escapes resolved).
///
/// Errors map per the variants of [`AuthParseError`]. In particular:
/// - empty input or a non-`Payment` scheme → [`AuthParseError::UnknownScheme`]
/// - `Payment` scheme but missing/wrong `method=` →
///   [`AuthParseError::MissingMethod`] or [`AuthParseError::WrongMethod`]
/// - `method="cashu"` but missing `token=` → [`AuthParseError::MissingToken`]
/// - any structural failure (unterminated quotes, missing `=`,
///   token-style value) → [`AuthParseError::MalformedParams`]
pub fn parse_payment_authorization(header_value: &str) -> Result<String, AuthParseError> {
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return Err(AuthParseError::UnknownScheme);
    }

    // Split scheme off the first whitespace run. RFC 7235 mandates at
    // least one SP between scheme and params; we accept one-or-more
    // whitespace chars to be lenient with horizontal-tab proxies.
    // A header that is just `Payment` (no whitespace at all) is
    // structurally an attempted Payment with no params — we surface
    // that as MissingMethod rather than UnknownScheme so the client
    // gets a 400 telling them what to add.
    let (scheme, rest) = match trimmed.split_once(|c: char| c.is_ascii_whitespace()) {
        Some((s, r)) => (s, r.trim_start()),
        None => (trimmed, ""),
    };

    if !scheme.eq_ignore_ascii_case(PAYMENT_SCHEME) {
        return Err(AuthParseError::UnknownScheme);
    }

    if rest.is_empty() {
        // `Payment` (with or without trailing whitespace) — scheme is
        // recognized but the mandatory `method=` and `token=` are
        // absent. Surface the method one first so 400 messages stay
        // actionable.
        return Err(AuthParseError::MissingMethod);
    }

    let params = parse_params(rest)?;

    // RFC 7235 §2.2: param keys are case-insensitive. We compare
    // lowercase here; values stay case-sensitive (cashu tokens are
    // base64url which is case-sensitive).
    let method = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(METHOD_PARAM))
        .map(|(_, v)| v.as_str());
    let token = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(TOKEN_PARAM))
        .map(|(_, v)| v.as_str());

    let Some(method) = method else {
        return Err(AuthParseError::MissingMethod);
    };
    if method != CASHU_METHOD {
        return Err(AuthParseError::WrongMethod(method.to_string()));
    }

    let Some(token) = token else {
        return Err(AuthParseError::MissingToken);
    };

    Ok(token.to_string())
}

/// Parse the auth-param section of an `Authorization: Payment …`
/// header into `(key, value)` pairs.
///
/// Only quoted-string values are accepted (see module docs); a bare
/// token-style value surfaces as [`AuthParseError::MalformedParams`].
/// Backslash escapes inside quoted-strings are resolved per RFC 7230
/// §3.2.6 (`quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )`).
fn parse_params(input: &str) -> Result<Vec<(String, String)>, AuthParseError> {
    let mut out = Vec::new();
    let mut bytes = input.as_bytes();

    loop {
        bytes = skip_ows_and_commas(bytes);
        if bytes.is_empty() {
            break;
        }

        let (key, rest) = take_token(bytes)
            .ok_or_else(|| AuthParseError::MalformedParams("expected param name".into()))?;
        let rest = skip_ows(rest);
        let rest = match rest.split_first() {
            Some((b'=', tail)) => tail,
            _ => return Err(AuthParseError::MalformedParams("expected '=' after param name".into())),
        };
        let rest = skip_ows(rest);

        let (value, rest) = match rest.first() {
            Some(b'"') => take_quoted_string(rest)?,
            Some(_) => {
                return Err(AuthParseError::MalformedParams(
                    "value must be a quoted-string (v1 requires \"…\")".into(),
                ));
            }
            None => {
                return Err(AuthParseError::MalformedParams(
                    "missing value after '='".into(),
                ));
            }
        };

        out.push((key, value));
        bytes = rest;

        // After a value, the next non-OWS byte must be ',' or EOF.
        // Anything else is a structural error.
        let lookahead = skip_ows(bytes);
        match lookahead.first() {
            None => break,
            Some(b',') => {
                bytes = &lookahead[1..];
                continue;
            }
            Some(c) => {
                return Err(AuthParseError::MalformedParams(format!(
                    "expected ',' or end after value, got {:?}",
                    *c as char
                )));
            }
        }
    }

    Ok(out)
}

/// Eat optional whitespace (SP / HTAB) per RFC 7230 OWS.
fn skip_ows(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    &bytes[i..]
}

/// Eat any run of OWS + bare commas. RFC 7230 §7 allows empty list
/// elements (`#rule`): `a, , b` is a valid two-element list. We mirror
/// that by skipping commas + whitespace together at the top of the
/// param loop.
fn skip_ows_and_commas(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b',') {
        i += 1;
    }
    &bytes[i..]
}

/// Peel an RFC 7230 `token` off the front of `bytes`. Returns
/// `None` if the first byte isn't a tchar.
fn take_token(bytes: &[u8]) -> Option<(String, &[u8])> {
    let end = bytes.iter().position(|b| !is_tchar(*b)).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    // Safe: tchars are ASCII, so the slice is valid UTF-8.
    let key = std::str::from_utf8(&bytes[..end])
        .expect("tchars are ASCII")
        .to_string();
    Some((key, &bytes[end..]))
}

/// RFC 7230 §3.2.6 tchar set.
fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' |
        b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' |
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

/// Parse a `quoted-string` per RFC 7230 §3.2.6 starting at `bytes[0] ==
/// b'"'`. Returns the unescaped value plus the remaining bytes after
/// the closing quote.
fn take_quoted_string(bytes: &[u8]) -> Result<(String, &[u8]), AuthParseError> {
    debug_assert_eq!(bytes.first(), Some(&b'"'));
    let mut out = String::new();
    let mut i = 1; // skip opening quote
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                // Closing quote — done.
                return Ok((out, &bytes[i + 1..]));
            }
            b'\\' => {
                // quoted-pair: backslash escapes the next octet.
                // RFC 7230 limits the escapable set to HTAB / SP /
                // VCHAR / obs-text. We accept any next byte to stay
                // lenient with clients; downstream validation (token
                // shape) catches garbage.
                if i + 1 >= bytes.len() {
                    return Err(AuthParseError::MalformedParams(
                        "trailing backslash inside quoted-string".into(),
                    ));
                }
                out.push(bytes[i + 1] as char);
                i += 2;
            }
            c => {
                // qdtext: any VCHAR/SP/HTAB except '"' and '\'.
                // We don't enforce the VCHAR restriction strictly —
                // the value is opaque to us. Non-ASCII would already
                // be rejected by `HeaderValue::to_str` upstream.
                out.push(c as char);
                i += 1;
            }
        }
    }
    Err(AuthParseError::MalformedParams(
        "unterminated quoted-string".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_returns_token() {
        let token = parse_payment_authorization(
            r#"Payment method="cashu", token="cashuBabcdef==""#,
        )
        .expect("parses");
        assert_eq!(token, "cashuBabcdef==");
    }

    #[test]
    fn happy_path_params_in_any_order() {
        let token = parse_payment_authorization(
            r#"Payment token="cashuBxyz", method="cashu""#,
        )
        .expect("parses");
        assert_eq!(token, "cashuBxyz");
    }

    #[test]
    fn scheme_is_case_insensitive() {
        let token = parse_payment_authorization(
            r#"PAYMENT method="cashu", token="cashuBabc""#,
        )
        .expect("parses");
        assert_eq!(token, "cashuBabc");
        let token = parse_payment_authorization(
            r#"payment method="cashu", token="cashuBabc""#,
        )
        .expect("parses");
        assert_eq!(token, "cashuBabc");
    }

    #[test]
    fn param_keys_are_case_insensitive() {
        let token = parse_payment_authorization(
            r#"Payment Method="cashu", TOKEN="cashuBabc""#,
        )
        .expect("parses");
        assert_eq!(token, "cashuBabc");
    }

    #[test]
    fn missing_scheme_returns_unknown_scheme() {
        let err = parse_payment_authorization("").expect_err("empty header");
        assert_eq!(err, AuthParseError::UnknownScheme);
        let err = parse_payment_authorization("   ").expect_err("whitespace only");
        assert_eq!(err, AuthParseError::UnknownScheme);
        // A non-Payment bare token has no params either, but we
        // surface UnknownScheme because the scheme name itself fails
        // the equality check.
        let err =
            parse_payment_authorization("Bearer").expect_err("non-Payment bare scheme");
        assert_eq!(err, AuthParseError::UnknownScheme);
    }

    #[test]
    fn bearer_scheme_returns_unknown_scheme() {
        let err = parse_payment_authorization("Bearer abc123").expect_err("not Payment");
        assert_eq!(err, AuthParseError::UnknownScheme);
    }

    #[test]
    fn wrong_method_returns_wrong_method() {
        let err = parse_payment_authorization(
            r#"Payment method="tempo", token="abc""#,
        )
        .expect_err("method=tempo");
        assert_eq!(err, AuthParseError::WrongMethod("tempo".into()));
    }

    #[test]
    fn missing_method_returns_missing_method() {
        let err = parse_payment_authorization(r#"Payment token="cashuBabc""#)
            .expect_err("no method");
        assert_eq!(err, AuthParseError::MissingMethod);
        // Trailing whitespace after scheme, then nothing else.
        let err = parse_payment_authorization("Payment  ").expect_err("scheme only");
        assert_eq!(err, AuthParseError::MissingMethod);
    }

    #[test]
    fn missing_token_returns_missing_token() {
        let err = parse_payment_authorization(r#"Payment method="cashu""#)
            .expect_err("no token");
        assert_eq!(err, AuthParseError::MissingToken);
    }

    #[test]
    fn token_style_value_returns_malformed() {
        // Bare value (no quotes) — we explicitly require quoted-string
        // in v1 (see module docs).
        let err = parse_payment_authorization(r#"Payment method=cashu, token=cashuBabc"#)
            .expect_err("bare values rejected");
        assert!(
            matches!(err, AuthParseError::MalformedParams(_)),
            "expected MalformedParams, got {err:?}"
        );
    }

    #[test]
    fn missing_equals_returns_malformed() {
        let err = parse_payment_authorization(r#"Payment method "cashu""#)
            .expect_err("missing =");
        assert!(
            matches!(err, AuthParseError::MalformedParams(_)),
            "expected MalformedParams, got {err:?}"
        );
    }

    #[test]
    fn unterminated_quoted_string_returns_malformed() {
        let err = parse_payment_authorization(r#"Payment method="cashu"#)
            .expect_err("unterminated quote");
        assert!(
            matches!(err, AuthParseError::MalformedParams(_)),
            "expected MalformedParams, got {err:?}"
        );
    }

    #[test]
    fn escaped_quotes_inside_value_are_unescaped() {
        // `\"` inside the value should yield a literal `"` in the
        // returned string — and not terminate the quoted-string.
        let token = parse_payment_authorization(
            r#"Payment method="cashu", token="ca\"sh\"uBabc""#,
        )
        .expect("parses");
        assert_eq!(token, r#"ca"sh"uBabc"#);
    }

    #[test]
    fn extra_whitespace_around_separators_ok() {
        let token = parse_payment_authorization(
            "Payment   method = \"cashu\"  ,   token = \"cashuBxyz\"   ",
        )
        .expect("parses with BWS");
        assert_eq!(token, "cashuBxyz");
    }

    #[test]
    fn empty_list_elements_ok() {
        // RFC 7230 §7 list-rule allows `, ,` between elements.
        let token = parse_payment_authorization(
            r#"Payment method="cashu", , token="cashuBabc""#,
        )
        .expect("parses with empty list element");
        assert_eq!(token, "cashuBabc");
    }
}
