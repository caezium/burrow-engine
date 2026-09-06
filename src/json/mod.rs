//! Minimal zero-dep JSON reader.
//!
//! The engine writes JSON by hand (the envelope + each command's `to_json`), but several
//! commands must also *read* structured JSON from a tool's stdout — `dupes` parses fclones'
//! group report, and `status` will parse `system_profiler`'s GPU/Bluetooth JSON. Rather than
//! take a serde dependency (the crate is deliberately zero-dep), this is a small
//! recursive-descent parser over the full JSON grammar: objects, arrays, strings (with the
//! standard escapes and `\uXXXX`, including surrogate pairs), numbers, booleans, and null.
//!
//! Primarily a reader — most accessors return borrows/copies. It also carries a small
//! round-trip writer (`to_json_string` + `as_array_mut`/`get_mut`) so a caller can parse a
//! tool's report, edit it (e.g. drop protected files from an fclones group report), and
//! re-emit valid JSON to pipe back. Each command's own `to_json` still owns its output shape;
//! this writer exists for the parse→filter→re-emit round-trip.

use std::collections::BTreeMap;

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// All numbers are held as f64 (JSON has one numeric type). Use `as_u64`/`as_i64` for
    /// integer views.
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    /// Parse a JSON document. Errors on malformed input or trailing non-whitespace.
    pub fn parse(input: &str) -> Result<Json, String> {
        let mut p = Parser {
            chars: input.chars().collect(),
            pos: 0,
            depth: 0,
        };
        p.skip_ws();
        let v = p.parse_value()?;
        p.skip_ws();
        if p.pos != p.chars.len() {
            return Err(format!("trailing characters at position {}", p.pos));
        }
        Ok(v)
    }

    /// The value at `key` if this is an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.get(key),
            _ => None,
        }
    }

    /// The element at `index` if this is an array.
    pub fn at(&self, index: usize) -> Option<&Json> {
        match self {
            Json::Array(a) => a.get(index),
            _ => None,
        }
    }

    /// The array elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The string, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    /// The number as f64, if this is a number.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// The number as u64 (truncated toward zero), if this is a non-negative finite number.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(n) if n.is_finite() && *n >= 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    /// The number as i64 (truncated toward zero), if this is a finite number.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Number(n) if n.is_finite() => Some(*n as i64),
            _ => None,
        }
    }

    /// The boolean, if this is a bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The array elements for in-place editing, if this is an array. Lets a caller filter a
    /// parsed document (e.g. drop protected files from an fclones report) before re-serializing.
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Json>> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The value at `key` for in-place editing, if this is an object.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Json> {
        match self {
            Json::Object(m) => m.get_mut(key),
            _ => None,
        }
    }

    /// Serialize back to a compact JSON string (no insignificant whitespace). Integer-valued
    /// numbers emit without a fractional part (`5`, not `5.0`) so a round-tripped tool report
    /// stays byte-plausible to the tool that reads it back. Object keys are emitted in sorted
    /// order (BTreeMap) — JSON is order-independent, so a consumer parses the same document.
    pub fn to_json_string(&self) -> String {
        let mut out = String::new();
        self.write_to(&mut out);
        out
    }

    fn write_to(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Number(n) => out.push_str(&format_number(*n)),
            Json::String(s) => write_json_string(s, out),
            Json::Array(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write_to(out);
                }
                out.push(']');
            }
            Json::Object(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_string(k, out);
                    out.push(':');
                    v.write_to(out);
                }
                out.push('}');
            }
        }
    }
}

/// Format a JSON number: integer-valued finite numbers as integers (no `.0`), everything else
/// via the default f64 formatting. Non-finite values (which JSON can't represent) become `null`.
fn format_number(n: f64) -> String {
    if !n.is_finite() {
        return "null".to_string();
    }
    if n.fract() == 0.0 && n.abs() < 9.007_199_254_740_992e15 {
        return format!("{}", n as i64);
    }
    format!("{n}")
}

/// `s` as a quoted, escaped JSON string literal — THE crate's one string escaper. Every
/// hand-written `to_json` in this crate (there is no serde) goes through here, so an escaping
/// decision is made once: `"`, `\`, `\n`, `\r`, `\t` named, every other control character
/// `\u00XX`, everything else (including non-ASCII) verbatim. Nineteen byte-identical private
/// copies of this used to exist, one per module (BUR-124); the goldens prove the output did not
/// move when they were deleted.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    write_json_string(s, &mut out);
    out
}

/// Write `s` as a quoted, escaped JSON string literal onto `out` — [`escape`]'s in-place form.
pub(crate) fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        if self.depth >= 128 {
            return Err("JSON nesting exceeds 128 levels".into());
        }
        self.depth += 1;
        let result = match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => Ok(Json::String(self.parse_string()?)),
            Some('t') | Some('f') => self.parse_bool(),
            Some('n') => self.parse_null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            Some(c) => Err(format!(
                "unexpected character '{c}' at position {}",
                self.pos
            )),
            None => Err("unexpected end of input".into()),
        };
        self.depth -= 1;
        result
    }

    fn expect(&mut self, c: char) -> Result<(), String> {
        match self.bump() {
            Some(got) if got == c => Ok(()),
            Some(got) => Err(format!("expected '{c}' but found '{got}' at {}", self.pos)),
            None => Err(format!("expected '{c}' but hit end of input")),
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.expect('{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err(format!("expected object key string at {}", self.pos));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(':')?;
            self.skip_ws();
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some('}') => break,
                other => return Err(format!("expected ',' or '}}' but found {other:?}")),
            }
        }
        Ok(Json::Object(map))
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.expect('[')?;
        let mut arr = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(Json::Array(arr));
        }
        loop {
            self.skip_ws();
            arr.push(self.parse_value()?);
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some(']') => break,
                other => return Err(format!("expected ',' or ']' but found {other:?}")),
            }
        }
        Ok(Json::Array(arr))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut s = String::new();
        loop {
            match self.bump() {
                None => return Err("unterminated string".into()),
                Some('"') => break,
                Some('\\') => {
                    let esc = self.bump().ok_or("dangling escape in string")?;
                    match esc {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        '/' => s.push('/'),
                        'b' => s.push('\u{0008}'),
                        'f' => s.push('\u{000C}'),
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        'u' => s.push(self.parse_unicode_escape()?),
                        other => return Err(format!("invalid escape '\\{other}'")),
                    }
                }
                Some(c) if (c as u32) < 0x20 => {
                    return Err("unescaped control character in string".into())
                }
                Some(c) => s.push(c),
            }
        }
        Ok(s)
    }

    /// Parse the four hex digits after `\u`, decoding surrogate pairs into a single char.
    fn parse_unicode_escape(&mut self) -> Result<char, String> {
        let hi = self.parse_hex4()?;
        // High surrogate: a low surrogate must follow as `\uXXXX`.
        if (0xD800..=0xDBFF).contains(&hi) {
            if self.bump() != Some('\\') || self.bump() != Some('u') {
                return Err("expected low surrogate after high surrogate".into());
            }
            let lo = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return Err("invalid low surrogate".into());
            }
            let c = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
            return char::from_u32(c).ok_or_else(|| "invalid surrogate pair".into());
        }
        char::from_u32(hi).ok_or_else(|| format!("invalid \\u escape {hi:#06x}"))
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.bump().ok_or("truncated \\u escape")?;
            let d = c
                .to_digit(16)
                .ok_or_else(|| format!("bad hex digit '{c}'"))?;
            v = v * 16 + d;
        }
        Ok(v)
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        match self.peek() {
            Some('0') => {
                self.pos += 1;
            }
            Some('1'..='9') => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return Err("number requires an integer part".into()),
        }
        if self.peek() == Some('.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err("number requires digits after decimal point".into());
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        match text.parse::<f64>() {
            Ok(n) if n.is_finite() => Ok(Json::Number(n)),
            _ => Err(format!("invalid or out-of-range number '{text}'")),
        }
    }

    fn parse_bool(&mut self) -> Result<Json, String> {
        if self.consume_keyword("true") {
            Ok(Json::Bool(true))
        } else if self.consume_keyword("false") {
            Ok(Json::Bool(false))
        } else {
            Err(format!("invalid literal at position {}", self.pos))
        }
    }

    fn parse_null(&mut self) -> Result<Json, String> {
        if self.consume_keyword("null") {
            Ok(Json::Null)
        } else {
            Err(format!("invalid literal at position {}", self.pos))
        }
    }

    fn consume_keyword(&mut self, kw: &str) -> bool {
        let end = self.pos + kw.len();
        if end <= self.chars.len() && self.chars[self.pos..end].iter().copied().eq(kw.chars()) {
            self.pos = end;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scalars() {
        assert_eq!(Json::parse("null").unwrap(), Json::Null);
        assert_eq!(Json::parse("true").unwrap(), Json::Bool(true));
        assert_eq!(Json::parse("false").unwrap(), Json::Bool(false));
        assert_eq!(Json::parse("42").unwrap(), Json::Number(42.0));
        assert_eq!(Json::parse("-3.5e2").unwrap(), Json::Number(-350.0));
        assert_eq!(Json::parse("\"hi\"").unwrap().as_str(), Some("hi"));
    }

    #[test]
    fn whitespace_is_ignored_around_values() {
        assert_eq!(Json::parse("  \n\t 7 \r\n").unwrap(), Json::Number(7.0));
    }

    #[test]
    fn parses_nested_object_and_array() {
        let v = Json::parse(r#"{"a":1,"b":[true,null,"x"],"c":{"d":2}}"#).unwrap();
        assert_eq!(v.get("a").and_then(Json::as_u64), Some(1));
        assert_eq!(v.get("b").and_then(Json::as_array).map(<[_]>::len), Some(3));
        assert_eq!(
            v.get("b").and_then(|b| b.at(2)).and_then(Json::as_str),
            Some("x")
        );
        assert_eq!(
            v.get("c").and_then(|c| c.get("d")).and_then(Json::as_u64),
            Some(2)
        );
    }

    #[test]
    fn empty_containers() {
        assert_eq!(Json::parse("{}").unwrap(), Json::Object(Default::default()));
        assert_eq!(Json::parse("[]").unwrap(), Json::Array(vec![]));
        assert_eq!(Json::parse("[ ]").unwrap(), Json::Array(vec![]));
    }

    #[test]
    fn string_escapes_including_unicode_and_surrogates() {
        assert_eq!(
            Json::parse(r#""a\"b\\c\n\t\/""#).unwrap().as_str(),
            Some("a\"b\\c\n\t/")
        );
        // é = é
        assert_eq!(Json::parse(r#""café""#).unwrap().as_str(), Some("café"));
        // surrogate pair for 😀 (U+1F600)
        assert_eq!(Json::parse(r#""😀""#).unwrap().as_str(), Some("😀"));
    }

    #[test]
    fn integer_accessors() {
        assert_eq!(
            Json::parse("9007199254740992").unwrap().as_u64(),
            Some(9007199254740992)
        );
        assert_eq!(Json::parse("-5").unwrap().as_i64(), Some(-5));
        assert_eq!(
            Json::parse("-5").unwrap().as_u64(),
            None,
            "negative is not u64"
        );
        assert_eq!(
            Json::parse("3.9").unwrap().as_i64(),
            Some(3),
            "truncates toward zero"
        );
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(Json::parse("").is_err());
        assert!(Json::parse("{").is_err());
        assert!(Json::parse("[1,]").is_err()); // trailing comma
        assert!(Json::parse("{\"a\":1,}").is_err()); // trailing comma
        assert!(Json::parse("nul").is_err());
        assert!(Json::parse("1 2").is_err(), "trailing tokens rejected");
        assert!(Json::parse("\"unterminated").is_err());
        assert!(Json::parse("{\"a\" 1}").is_err(), "missing colon");
    }

    #[test]
    fn accessors_are_type_guarded() {
        let v = Json::parse("42").unwrap();
        assert_eq!(v.as_str(), None);
        assert_eq!(v.get("x"), None);
        assert_eq!(v.at(0), None);
        assert_eq!(Json::parse("\"s\"").unwrap().as_f64(), None);
    }

    #[test]
    fn round_trips_and_emits_integers_without_fraction() {
        // Integer-valued numbers must not gain a ".0" (a tool re-reading its report expects ints).
        assert_eq!(Json::parse("5").unwrap().to_json_string(), "5");
        assert_eq!(Json::parse("-42").unwrap().to_json_string(), "-42");
        assert_eq!(Json::parse("3.5").unwrap().to_json_string(), "3.5");
        // Object keys re-emit sorted (BTreeMap); JSON is order-independent.
        assert_eq!(
            Json::parse(r#"{"b":1,"a":[true,null,"x\ny"]}"#)
                .unwrap()
                .to_json_string(),
            r#"{"a":[true,null,"x\ny"],"b":1}"#
        );
    }

    #[test]
    fn round_trip_is_reparseable() {
        let src = r#"{"header":{"stats":{"redundant_file_size":10}},"groups":[{"file_len":5,"files":["/a","/b"]}]}"#;
        let parsed = Json::parse(src).unwrap();
        let reparsed = Json::parse(&parsed.to_json_string()).unwrap();
        assert_eq!(parsed, reparsed, "serialize->parse is identity");
    }

    #[test]
    fn mut_accessors_allow_in_place_filtering() {
        let mut v = Json::parse(r#"{"groups":[{"files":["/keep","/drop"]}]}"#).unwrap();
        let files = v
            .get_mut("groups")
            .and_then(Json::as_array_mut)
            .and_then(|g| g[0].get_mut("files"))
            .and_then(Json::as_array_mut)
            .unwrap();
        files.retain(|f| f.as_str() != Some("/drop"));
        assert_eq!(v.to_json_string(), r#"{"groups":[{"files":["/keep"]}]}"#);
    }

    #[test]
    fn duplicate_keys_take_the_last() {
        // BTreeMap insert semantics: last write wins (matches serde_json's default).
        assert_eq!(
            Json::parse(r#"{"k":1,"k":2}"#)
                .unwrap()
                .get("k")
                .and_then(Json::as_u64),
            Some(2)
        );
    }
}
