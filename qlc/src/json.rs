//! A small JSON value type and writer. The crate has no dependencies, so the
//! output of [`crate::Output::to_json`] is built from [`Json`] values and
//! serialised by [`Json::write`].
//!
//! Objects keep their fields in insertion order, which keeps the output
//! stable for the dashboard and for tests.

/// A JSON value. Numbers are unsigned integers because the compiler emits
/// nothing else (line numbers, column numbers and quantifier counts).
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Builds a string value from a `&str`.
    pub fn str(s: &str) -> Json {
        Json::Str(s.to_string())
    }

    /// Builds an array of strings.
    pub fn strs(items: &[String]) -> Json {
        Json::Arr(items.iter().map(|s| Json::str(s)).collect())
    }

    /// Builds an object from `(key, value)` pairs.
    pub fn obj(fields: Vec<(&str, Json)>) -> Json {
        Json::Obj(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// Looks up a field of an object. Returns `None` for other values.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Returns the string content if this value is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Serialises the value to compact JSON text.
    pub fn write(&self) -> String {
        let mut out = String::new();
        self.write_into(&mut out);
        out
    }

    fn write_into(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Num(n) => out.push_str(&n.to_string()),
            Json::Str(s) => write_string(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_into(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    v.write_into(out);
                }
                out.push('}');
            }
        }
    }
}

/// Writes a JSON string literal. Quotes, backslashes and control characters
/// are escaped. All other characters, including non-ASCII ones, are written
/// as UTF-8, which JSON allows. U+2028 and U+2029 are escaped as well so the
/// text can also be pasted into JavaScript source.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str("\\u");
                let code = c as u32;
                for shift in [12u32, 8, 4, 0] {
                    let digit = (code >> shift) & 0xF;
                    out.push(char::from_digit(digit, 16).unwrap_or('0'));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A strict JSON parser used only by the tests, to check that the writer
/// produces valid JSON and that strings round-trip.
#[cfg(test)]
pub mod validate {
    use super::Json;

    /// Parses a complete JSON document. Returns an error text with the byte
    /// offset when the input is not valid JSON.
    pub fn parse(text: &str) -> Result<Json, String> {
        let chars: Vec<char> = text.chars().collect();
        let mut p = Parser { chars, i: 0 };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != p.chars.len() {
            return Err(format!("trailing characters at {}", p.i));
        }
        Ok(v)
    }

    struct Parser {
        chars: Vec<char>,
        i: usize,
    }

    impl Parser {
        fn peek(&self) -> Option<char> {
            self.chars.get(self.i).copied()
        }

        fn ws(&mut self) {
            while matches!(self.peek(), Some(' ' | '\n' | '\r' | '\t')) {
                self.i += 1;
            }
        }

        fn expect(&mut self, c: char) -> Result<(), String> {
            if self.peek() == Some(c) {
                self.i += 1;
                Ok(())
            } else {
                Err(format!("expected '{}' at {}", c, self.i))
            }
        }

        fn word(&mut self, w: &str, v: Json) -> Result<Json, String> {
            for c in w.chars() {
                self.expect(c)?;
            }
            Ok(v)
        }

        fn value(&mut self) -> Result<Json, String> {
            match self.peek() {
                Some('n') => self.word("null", Json::Null),
                Some('t') => self.word("true", Json::Bool(true)),
                Some('f') => self.word("false", Json::Bool(false)),
                Some('"') => Ok(Json::Str(self.string()?)),
                Some('[') => {
                    self.i += 1;
                    let mut items = Vec::new();
                    self.ws();
                    if self.peek() == Some(']') {
                        self.i += 1;
                        return Ok(Json::Arr(items));
                    }
                    loop {
                        self.ws();
                        items.push(self.value()?);
                        self.ws();
                        match self.peek() {
                            Some(',') => self.i += 1,
                            Some(']') => {
                                self.i += 1;
                                return Ok(Json::Arr(items));
                            }
                            _ => return Err(format!("expected ',' or ']' at {}", self.i)),
                        }
                    }
                }
                Some('{') => {
                    self.i += 1;
                    let mut fields = Vec::new();
                    self.ws();
                    if self.peek() == Some('}') {
                        self.i += 1;
                        return Ok(Json::Obj(fields));
                    }
                    loop {
                        self.ws();
                        let k = self.string()?;
                        self.ws();
                        self.expect(':')?;
                        self.ws();
                        let v = self.value()?;
                        fields.push((k, v));
                        self.ws();
                        match self.peek() {
                            Some(',') => self.i += 1,
                            Some('}') => {
                                self.i += 1;
                                return Ok(Json::Obj(fields));
                            }
                            _ => return Err(format!("expected ',' or '}}' at {}", self.i)),
                        }
                    }
                }
                Some(c) if c.is_ascii_digit() => {
                    let start = self.i;
                    while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                        self.i += 1;
                    }
                    let s: String = self.chars[start..self.i].iter().collect();
                    if s.len() > 1 && s.starts_with('0') {
                        return Err(format!("leading zero at {}", start));
                    }
                    s.parse::<u64>().map(Json::Num).map_err(|e| e.to_string())
                }
                _ => Err(format!("unexpected input at {}", self.i)),
            }
        }

        fn string(&mut self) -> Result<String, String> {
            self.expect('"')?;
            let mut out = String::new();
            loop {
                let c = self.peek().ok_or("unterminated string")?;
                self.i += 1;
                match c {
                    '"' => return Ok(out),
                    '\\' => {
                        let e = self.peek().ok_or("unterminated escape")?;
                        self.i += 1;
                        match e {
                            '"' => out.push('"'),
                            '\\' => out.push('\\'),
                            '/' => out.push('/'),
                            'n' => out.push('\n'),
                            'r' => out.push('\r'),
                            't' => out.push('\t'),
                            'b' => out.push('\u{08}'),
                            'f' => out.push('\u{0C}'),
                            'u' => {
                                let mut code = 0u32;
                                for _ in 0..4 {
                                    let h = self.peek().and_then(|h| h.to_digit(16)).ok_or("bad \\u escape")?;
                                    self.i += 1;
                                    code = code * 16 + h;
                                }
                                out.push(char::from_u32(code).ok_or("surrogate in \\u escape")?);
                            }
                            other => return Err(format!("bad escape '\\{}'", other)),
                        }
                    }
                    c if (c as u32) < 0x20 => return Err(format!("raw control character at {}", self.i - 1)),
                    c => out.push(c),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_round_trip() {
        let nasty = "quote \" backslash \\ newline \n tab \t bell \u{07} ∀x∈S ¬ → é 𝔸 \u{2028}";
        let text = Json::str(nasty).write();
        assert!(!text.contains('\n'));
        assert!(text.contains("\\u0007"));
        assert_eq!(validate::parse(&text), Ok(Json::str(nasty)));
    }

    #[test]
    fn nested_values_round_trip() {
        let v = Json::obj(vec![
            ("a", Json::Arr(vec![Json::Num(1), Json::Null, Json::Bool(true)])),
            ("b", Json::obj(vec![("c", Json::str("d"))])),
            ("empty", Json::Arr(vec![])),
        ]);
        assert_eq!(v.write(), r#"{"a":[1,null,true],"b":{"c":"d"},"empty":[]}"#);
        assert_eq!(validate::parse(&v.write()), Ok(v));
    }

    #[test]
    fn validator_rejects_bad_json() {
        assert!(validate::parse("{\"a\":1,}").is_err());
        assert!(validate::parse("\"a\nb\"").is_err());
        assert!(validate::parse("[1] x").is_err());
    }
}
