//! The lexer. It turns source text into [`Token`]s with positions and accepts
//! both the ASCII and the Unicode spelling of every operator.

use crate::ast::Pos;
use crate::error::CompileError;

/// The token kinds of the surface syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    Ident(String),
    Nat(u64),
    Str(String),
    LParen,
    RParen,
    Comma,
    Dot,
    /// `!`, `¬` or `not`
    Not,
    /// `&`, `&&`, `∧` or `and`
    And,
    /// `|`, `||`, `∨` or `or`
    Or,
    /// `->` or `→`
    Arrow,
    /// `forall` or `∀`
    Forall,
    /// `exists` or `∃`
    Exists,
    AtLeast,
    AtMost,
    /// `in` or `∈`
    In,
    True,
    False,
    Eof,
}

impl Tok {
    /// How the token is shown in error messages.
    pub fn describe(&self) -> String {
        match self {
            Tok::Ident(s) => format!("identifier '{}'", s),
            Tok::Nat(n) => format!("number {}", n),
            Tok::Str(_) => "string literal".to_string(),
            Tok::LParen => "'('".to_string(),
            Tok::RParen => "')'".to_string(),
            Tok::Comma => "','".to_string(),
            Tok::Dot => "'.'".to_string(),
            Tok::Not => "negation".to_string(),
            Tok::And => "'&'".to_string(),
            Tok::Or => "'|'".to_string(),
            Tok::Arrow => "'->'".to_string(),
            Tok::Forall => "'forall'".to_string(),
            Tok::Exists => "'exists'".to_string(),
            Tok::AtLeast => "'atleast'".to_string(),
            Tok::AtMost => "'atmost'".to_string(),
            Tok::In => "'in'".to_string(),
            Tok::True => "'true'".to_string(),
            Tok::False => "'false'".to_string(),
            Tok::Eof => "end of input".to_string(),
        }
    }
}

/// A token with the position of its first character.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    pub pos: Pos,
}

/// Splits `src` into tokens. The result always ends with one [`Tok::Eof`]
/// token, whose position is one past the last character. Comments run from
/// `#` to the end of the line.
pub fn lex(src: &str) -> Result<Vec<Token>, CompileError> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut pos = Pos { line: 1, col: 1 };

    while let Some(&c) = chars.get(i) {
        let start = pos;
        // `advance` moves over one character and keeps line and column right.
        let advance = |i: &mut usize, pos: &mut Pos| {
            if chars.get(*i) == Some(&'\n') {
                pos.line += 1;
                pos.col = 1;
            } else {
                pos.col += 1;
            }
            *i += 1;
        };

        if c.is_whitespace() {
            advance(&mut i, &mut pos);
            continue;
        }
        if c == '#' {
            while chars.get(i).is_some_and(|&c| c != '\n') {
                advance(&mut i, &mut pos);
            }
            continue;
        }

        let next = chars.get(i + 1).copied();
        let simple = match c {
            '(' => Some((Tok::LParen, 1)),
            ')' => Some((Tok::RParen, 1)),
            ',' => Some((Tok::Comma, 1)),
            '.' => Some((Tok::Dot, 1)),
            '!' | '¬' => Some((Tok::Not, 1)),
            '&' => Some((Tok::And, if next == Some('&') { 2 } else { 1 })),
            '∧' => Some((Tok::And, 1)),
            '|' => Some((Tok::Or, if next == Some('|') { 2 } else { 1 })),
            '∨' => Some((Tok::Or, 1)),
            '→' => Some((Tok::Arrow, 1)),
            '-' if next == Some('>') => Some((Tok::Arrow, 2)),
            '∀' => Some((Tok::Forall, 1)),
            '∃' => Some((Tok::Exists, 1)),
            '∈' => Some((Tok::In, 1)),
            _ => None,
        };
        if let Some((tok, len)) = simple {
            for _ in 0..len {
                advance(&mut i, &mut pos);
            }
            out.push(Token { tok, pos: start });
            continue;
        }

        if c.is_ascii_digit() {
            let mut value: u64 = 0;
            while let Some(d) = chars.get(i).and_then(|c| c.to_digit(10)) {
                value = value
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(d as u64))
                    .ok_or_else(|| CompileError::at(src, start, "number is too large (the limit is 2^64 - 1)"))?;
                advance(&mut i, &mut pos);
            }
            out.push(Token { tok: Tok::Nat(value), pos: start });
            continue;
        }

        if c == '"' {
            advance(&mut i, &mut pos);
            let mut text = String::new();
            loop {
                match chars.get(i).copied() {
                    None | Some('\n') => {
                        return Err(CompileError::at(src, start, "string literal is not closed; add a closing '\"'"));
                    }
                    Some('"') => {
                        advance(&mut i, &mut pos);
                        break;
                    }
                    Some('\\') => {
                        let esc_pos = pos;
                        advance(&mut i, &mut pos);
                        let e = chars.get(i).copied();
                        let decoded = match e {
                            Some('"') => '"',
                            Some('\\') => '\\',
                            Some('n') => '\n',
                            Some('t') => '\t',
                            _ => {
                                return Err(CompileError::at(
                                    src,
                                    esc_pos,
                                    "unknown escape in string; the escapes are \\\" \\\\ \\n \\t",
                                ));
                            }
                        };
                        text.push(decoded);
                        advance(&mut i, &mut pos);
                    }
                    Some(other) => {
                        text.push(other);
                        advance(&mut i, &mut pos);
                    }
                }
            }
            out.push(Token { tok: Tok::Str(text), pos: start });
            continue;
        }

        if c.is_alphabetic() || c == '_' {
            let mut word = String::new();
            while let Some(&w) = chars.get(i) {
                if w.is_alphanumeric() || w == '_' {
                    word.push(w);
                    advance(&mut i, &mut pos);
                } else {
                    break;
                }
            }
            let tok = match word.as_str() {
                "forall" => Tok::Forall,
                "exists" => Tok::Exists,
                "atleast" => Tok::AtLeast,
                "atmost" => Tok::AtMost,
                "in" => Tok::In,
                "and" => Tok::And,
                "or" => Tok::Or,
                "not" => Tok::Not,
                "true" => Tok::True,
                "false" => Tok::False,
                _ => Tok::Ident(word),
            };
            out.push(Token { tok, pos: start });
            continue;
        }

        return Err(CompileError::at(src, start, format!("unexpected character '{}'", c)));
    }

    out.push(Token { tok: Tok::Eof, pos });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        lex(src).expect("lexes").into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn ascii_and_unicode_spellings_agree() {
        let ascii = toks("forall x in S. !Revoked(x) & true | false -> true");
        let unicode = toks("∀x∈S.¬Revoked(x) ∧ true ∨ false → true");
        assert_eq!(ascii, unicode);
        assert_eq!(toks("a and b or not c"), toks("a && b || !c"));
    }

    #[test]
    fn positions_count_characters_and_lines() {
        let t = lex("# comment\n∀x ∈ S").expect("lexes");
        assert_eq!(t[0].pos, Pos { line: 2, col: 1 });
        assert_eq!(t[1].pos, Pos { line: 2, col: 2 });
        assert_eq!(t[2].pos, Pos { line: 2, col: 4 });
        assert_eq!(t[4].tok, Tok::Eof);
        assert_eq!(t[4].pos, Pos { line: 2, col: 7 });
    }

    #[test]
    fn strings_decode_escapes() {
        assert_eq!(toks(r#""a\"b\\c é""#)[0], Tok::Str("a\"b\\c é".into()));
    }

    #[test]
    fn errors_have_positions() {
        let e = lex("Revoked(x) $").unwrap_err();
        assert_eq!((e.line, e.col), (1, 12));
        let e = lex("Sig(x, \"open").unwrap_err();
        assert!(e.message.contains("not closed"));
        assert_eq!(e.col, 8);
        assert!(lex("99999999999999999999999").is_err());
    }
}
