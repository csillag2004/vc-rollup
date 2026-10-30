//! The error type shared by the lexer and the parser.

use crate::ast::Pos;
use crate::json::Json;

/// A compile error with its source position and a two-line excerpt: the
/// offending source line and a caret under the offending column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    pub message: String,
    pub line: u32,
    pub col: u32,
    pub excerpt: String,
}

impl CompileError {
    /// Builds an error at `pos` and cuts the excerpt out of `src`.
    pub fn at(src: &str, pos: Pos, message: impl Into<String>) -> CompileError {
        CompileError {
            message: message.into(),
            line: pos.line,
            col: pos.col,
            excerpt: excerpt(src, pos),
        }
    }

    /// The JSON object `{message, line, col, excerpt}`.
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("message", Json::str(&self.message)),
            ("line", Json::Num(self.line as u64)),
            ("col", Json::Num(self.col as u64)),
            ("excerpt", Json::str(&self.excerpt)),
        ])
    }
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}\n{}", self.line, self.col, self.message, self.excerpt)
    }
}

/// Returns the source line of `pos` followed by a line with a caret under
/// column `pos.col`. Tabs in the source line are copied into the caret line
/// so the caret stays aligned.
fn excerpt(src: &str, pos: Pos) -> String {
    let line = src.lines().nth(pos.line.saturating_sub(1) as usize).unwrap_or("");
    let mut caret = String::new();
    for c in line.chars().take(pos.col.saturating_sub(1) as usize) {
        caret.push(if c == '\t' { '\t' } else { ' ' });
    }
    // A position one past the end of the line (end of input) still gets a caret.
    let have = caret.chars().count() as u32;
    for _ in have..pos.col.saturating_sub(1) {
        caret.push(' ');
    }
    caret.push('^');
    format!("{}\n{}", line, caret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excerpt_points_at_the_column() {
        let e = CompileError::at("a\nbcd e", Pos { line: 2, col: 5 }, "oops");
        assert_eq!(e.excerpt, "bcd e\n    ^");
    }

    #[test]
    fn excerpt_handles_end_of_input() {
        let e = CompileError::at("ab", Pos { line: 1, col: 3 }, "eof");
        assert_eq!(e.excerpt, "ab\n  ^");
    }
}
