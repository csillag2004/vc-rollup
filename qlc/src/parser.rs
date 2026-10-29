//! The recursive-descent parser. It follows the grammar in README.md, checks
//! atom names, arity and argument kinds against [`crate::ast::ATOMS`], and
//! rejects free and shadowed variables while it parses, so every [`Formula`]
//! it returns is well scoped.

use crate::ast::{Arg, ArgKind, Atom, AtomName, Formula, Pos, QuantKind, ATOMS};
use crate::error::CompileError;
use crate::lexer::{lex, Tok, Token};

/// The deepest recursion the parser accepts. One level of parentheses costs
/// two levels of recursion. The limit keeps the recursive
/// stages from exhausting the WebAssembly stack on hostile input.
pub const MAX_DEPTH: u32 = 200;

/// Parses a complete query. This is the entry point used by
/// [`crate::compile`].
pub fn parse(src: &str) -> Result<Formula, CompileError> {
    let tokens = lex(src)?;
    let mut p = Parser { src, tokens, i: 0, scope: Vec::new(), depth: 0 };
    let f = p.formula()?;
    match p.peek().tok {
        Tok::Eof => Ok(f),
        Tok::RParen => Err(p.error_here("unbalanced parenthesis: this ')' has no matching '('")),
        ref other => {
            let msg = format!("expected an operator or the end of the query, found {}", other.describe());
            Err(p.error_here(msg))
        }
    }
}

struct Parser<'a> {
    src: &'a str,
    tokens: Vec<Token>,
    i: usize,
    /// The variables bound by the enclosing quantifiers, innermost last.
    scope: Vec<String>,
    depth: u32,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> &Token {
        // `lex` always ends the list with `Eof` and `bump` never moves past
        // it, so the index is in range; the fallback keeps this total.
        static EOF: Token = Token { tok: Tok::Eof, pos: Pos { line: 1, col: 1 } };
        self.tokens.get(self.i).unwrap_or(&EOF)
    }

    fn bump(&mut self) -> Token {
        let t = self.peek().clone();
        if t.tok != Tok::Eof {
            self.i += 1;
        }
        t
    }

    fn error_at(&self, pos: Pos, msg: impl Into<String>) -> CompileError {
        CompileError::at(self.src, pos, msg)
    }

    fn error_here(&self, msg: impl Into<String>) -> CompileError {
        self.error_at(self.peek().pos, msg)
    }

    /// Consumes the token `want` or reports what was expected and why.
    fn expect(&mut self, want: Tok, context: &str) -> Result<Token, CompileError> {
        if self.peek().tok == want {
            Ok(self.bump())
        } else {
            let msg = format!("expected {} {}, found {}", want.describe(), context, self.peek().tok.describe());
            Err(self.error_here(msg))
        }
    }

    fn ident(&mut self, what: &str) -> Result<(String, Pos), CompileError> {
        match self.peek().tok.clone() {
            Tok::Ident(name) => {
                let pos = self.bump().pos;
                Ok((name, pos))
            }
            other => Err(self.error_here(format!("expected {}, found {}", what, other.describe()))),
        }
    }

    fn enter(&mut self) -> Result<(), CompileError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.error_here(format!("the query is nested more than {} levels deep", MAX_DEPTH)));
        }
        Ok(())
    }

    /// `formula := quant | impl`
    fn formula(&mut self) -> Result<Formula, CompileError> {
        self.enter()?;
        let f = if self.at_quantifier() { self.quant() } else { self.implication() };
        self.depth -= 1;
        f
    }

    fn at_quantifier(&self) -> bool {
        matches!(self.peek().tok, Tok::Forall | Tok::Exists | Tok::AtLeast | Tok::AtMost)
    }

    /// `quant := QUANTIFIER [NAT] VAR in DOMAIN '.' formula`. The body is a
    /// full formula, so it extends as far to the right as possible.
    fn quant(&mut self) -> Result<Formula, CompileError> {
        let head = self.bump();
        let kind = match head.tok {
            Tok::Forall => QuantKind::Forall,
            Tok::Exists => QuantKind::Exists,
            Tok::AtLeast | Tok::AtMost => {
                let k = match self.peek().tok {
                    Tok::Nat(k) => {
                        self.bump();
                        k
                    }
                    ref other => {
                        let msg = format!(
                            "expected a count after {}, as in 'atleast 2 x in S. ...', found {}",
                            head.tok.describe(),
                            other.describe()
                        );
                        return Err(self.error_here(msg));
                    }
                };
                if head.tok == Tok::AtLeast { QuantKind::AtLeast(k) } else { QuantKind::AtMost(k) }
            }
            _ => return Err(self.error_at(head.pos, "expected a quantifier")),
        };
        let (var, var_pos) = self.ident("a variable name after the quantifier")?;
        if self.scope.contains(&var) {
            let msg = format!("variable '{}' shadows an enclosing variable of the same name; rename one of them", var);
            return Err(self.error_at(var_pos, msg));
        }
        self.expect(Tok::In, "after the quantified variable")?;
        let (domain, _) = self.ident("a domain name (a group such as S, or Issued, or Presented)")?;
        self.expect(Tok::Dot, "between the domain and the quantifier body")?;
        self.scope.push(var.clone());
        let body = self.formula();
        self.scope.pop();
        Ok(Formula::Quant { kind, var, domain, body: Box::new(body?), pos: head.pos })
    }

    /// `impl := or ( '->' impl )?`, right associative.
    fn implication(&mut self) -> Result<Formula, CompileError> {
        let left = self.disjunction()?;
        if self.peek().tok == Tok::Arrow {
            self.bump();
            self.enter()?;
            let right = if self.at_quantifier() { self.quant() } else { self.implication() };
            self.depth -= 1;
            return Ok(Formula::Implies(Box::new(left), Box::new(right?)));
        }
        Ok(left)
    }

    /// `or := and ( '|' and )*`
    fn disjunction(&mut self) -> Result<Formula, CompileError> {
        let mut parts = vec![self.conjunction()?];
        while self.peek().tok == Tok::Or {
            self.bump();
            parts.push(self.conjunction()?);
        }
        Ok(Formula::or(parts))
    }

    /// `and := unary ( '&' unary )*`
    fn conjunction(&mut self) -> Result<Formula, CompileError> {
        let mut parts = vec![self.unary()?];
        while self.peek().tok == Tok::And {
            self.bump();
            parts.push(self.unary()?);
        }
        Ok(Formula::and(parts))
    }

    /// `unary := '!' unary | quant | atom | '(' formula ')' | 'true' | 'false'`
    fn unary(&mut self) -> Result<Formula, CompileError> {
        self.enter()?;
        let result = self.unary_inner();
        self.depth -= 1;
        result
    }

    fn unary_inner(&mut self) -> Result<Formula, CompileError> {
        match self.peek().tok.clone() {
            Tok::Not => {
                self.bump();
                Ok(Formula::not(self.unary()?))
            }
            Tok::True => {
                self.bump();
                Ok(Formula::True)
            }
            Tok::False => {
                self.bump();
                Ok(Formula::False)
            }
            Tok::LParen => {
                let open = self.bump().pos;
                let inner = self.formula()?;
                if self.peek().tok != Tok::RParen {
                    let msg = format!(
                        "unbalanced parenthesis: expected ')' to close the '(' opened at line {}, column {}, found {}",
                        open.line,
                        open.col,
                        self.peek().tok.describe()
                    );
                    return Err(self.error_here(msg));
                }
                self.bump();
                Ok(inner)
            }
            Tok::Forall | Tok::Exists | Tok::AtLeast | Tok::AtMost => self.quant(),
            Tok::Ident(_) => self.atom(),
            other => Err(self.error_here(format!(
                "expected a formula (an atom, a quantifier, a negation, 'true', 'false' or '('), found {}",
                other.describe()
            ))),
        }
    }

    /// `atom := NAME '(' args? ')'`, checked against the atom table.
    fn atom(&mut self) -> Result<Formula, CompileError> {
        let (name, pos) = self.ident("an atom name")?;
        let sig = match AtomName::lookup(&name) {
            Some(sig) => sig,
            None => {
                let known: Vec<&str> = ATOMS.iter().map(|s| s.text).collect();
                let msg = format!("unknown atom '{}'; the known atoms are {}", name, known.join(", "));
                return Err(self.error_at(pos, msg));
            }
        };
        self.expect(Tok::LParen, &format!("after the atom name, as in {}", sig.usage))?;

        let mut raw: Vec<(RawArg, Pos)> = Vec::new();
        if self.peek().tok != Tok::RParen {
            loop {
                raw.push(self.raw_arg(sig.usage)?);
                if self.peek().tok == Tok::Comma {
                    self.bump();
                } else {
                    break;
                }
            }
        }
        if self.peek().tok != Tok::RParen {
            let msg = format!(
                "unbalanced parenthesis: expected ')' or ',' in the argument list of {}, found {}",
                name,
                self.peek().tok.describe()
            );
            return Err(self.error_here(msg));
        }
        self.bump();

        if raw.len() != sig.args.len() {
            let plural = if sig.args.len() == 1 { "" } else { "s" };
            let msg = format!(
                "{} expects {} argument{}, as in {}, but {} were given",
                name,
                sig.args.len(),
                plural,
                sig.usage,
                raw.len()
            );
            return Err(self.error_at(pos, msg));
        }
        let mut args = Vec::new();
        for (index, ((arg, arg_pos), kind)) in raw.into_iter().zip(sig.args.iter()).enumerate() {
            args.push(self.check_arg(arg, arg_pos, *kind, &name, index + 1, sig.usage)?);
        }
        Ok(Formula::Atom(Atom { name: sig.name, args, pos }))
    }

    /// `arg := IDENT ('.' IDENT)? | NAT | STRING`. Whether an identifier is a
    /// variable or a name is decided later by [`Parser::check_arg`].
    fn raw_arg(&mut self, usage: &str) -> Result<(RawArg, Pos), CompileError> {
        let t = self.peek().clone();
        match t.tok {
            Tok::Nat(n) => {
                self.bump();
                Ok((RawArg::Nat(n), t.pos))
            }
            Tok::Str(s) => {
                self.bump();
                Ok((RawArg::Str(s), t.pos))
            }
            Tok::Ident(name) => {
                self.bump();
                if self.peek().tok == Tok::Dot {
                    self.bump();
                    let (attr, _) = self.ident("an attribute name after '.'")?;
                    Ok((RawArg::Ident(name, Some(attr)), t.pos))
                } else {
                    Ok((RawArg::Ident(name, None), t.pos))
                }
            }
            other => Err(self.error_here(format!("expected an argument, as in {}, found {}", usage, other.describe()))),
        }
    }

    /// Checks one argument against the kind its position requires and
    /// resolves identifiers to variables or names.
    fn check_arg(
        &self,
        arg: RawArg,
        pos: Pos,
        kind: ArgKind,
        atom: &str,
        index: usize,
        usage: &str,
    ) -> Result<Arg, CompileError> {
        let mismatch = |found: &str| {
            self.error_at(
                pos,
                format!("argument {} of {} must be {}, as in {}, but found {}", index, atom, kind.describe(), usage, found),
            )
        };
        let bound = |name: &str| -> Result<(), CompileError> {
            if self.scope.iter().any(|v| v == name) {
                Ok(())
            } else {
                Err(self.error_at(
                    pos,
                    format!(
                        "free variable '{}': every variable must be bound by an enclosing forall, exists, atleast or atmost",
                        name
                    ),
                ))
            }
        };
        match (kind, arg) {
            (ArgKind::Cred, RawArg::Ident(name, None)) => {
                bound(&name)?;
                Ok(Arg::Var { name, attr: None })
            }
            (ArgKind::Cred, RawArg::Ident(name, Some(_))) => {
                bound(&name)?;
                Err(mismatch("an attribute reference"))
            }
            (ArgKind::Attr, RawArg::Ident(name, Some(attr))) => {
                bound(&name)?;
                Ok(Arg::Var { name, attr: Some(attr) })
            }
            (ArgKind::Attr, RawArg::Ident(name, None)) => {
                bound(&name)?;
                Err(mismatch("a variable without an attribute"))
            }
            (ArgKind::Str, RawArg::Str(s)) | (ArgKind::StrOrName, RawArg::Str(s)) => Ok(Arg::Str(s)),
            (ArgKind::Bound, RawArg::Nat(n)) => Ok(Arg::Nat(n)),
            (ArgKind::Group | ArgKind::Key | ArgKind::Bound | ArgKind::StrOrName, RawArg::Ident(name, None)) => {
                Ok(Arg::Name(name))
            }
            (_, RawArg::Ident(_, Some(_))) => Err(mismatch("an attribute reference")),
            (_, RawArg::Ident(..)) => Err(mismatch("an identifier")),
            (_, RawArg::Nat(_)) => Err(mismatch("a number")),
            (_, RawArg::Str(_)) => Err(mismatch("a string literal")),
        }
    }
}

/// An argument as written, before it is checked against the atom signature.
enum RawArg {
    Ident(String, Option<String>),
    Nat(u64),
    Str(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pretty(src: &str) -> String {
        parse(src).expect("parses").pretty()
    }

    #[test]
    fn precedence_and_associativity() {
        assert_eq!(pretty("true | false & true"), "true ∨ false ∧ true");
        assert_eq!(pretty("(true | false) & true"), "(true ∨ false) ∧ true");
        assert_eq!(pretty("true -> false -> true"), "true → false → true");
        assert_eq!(pretty("(true -> false) -> true"), "(true → false) → true");
        assert_eq!(pretty("!true & false"), "¬true ∧ false");
    }

    #[test]
    fn quantifier_body_extends_right() {
        let implicit = parse("exists x in S. Revoked(x) & forall y in T. NotRevoked(y)").expect("parses");
        let explicit = parse("exists x in S. (Revoked(x) & (forall y in T. NotRevoked(y)))").expect("parses");
        assert_eq!(implicit.pretty(), explicit.pretty());
        assert_eq!(implicit.pretty(), "∃x∈S. Revoked(x) ∧ (∀y∈T. NotRevoked(y))");
    }

    #[test]
    fn unicode_syntax_parses() {
        assert_eq!(pretty("∀x∈S.¬Revoked(x) ∨ Sig(x, \"A\")"), "∀x∈S. ¬Revoked(x) ∨ Sig(x, \"A\")");
        assert_eq!(pretty("atleast 2 x in Presented. Commit(x.a)"), "∃≥2 x∈Presented. Commit(x.a)");
    }

    #[test]
    fn quantifier_after_arrow() {
        assert_eq!(pretty("true -> forall x in S. Revoked(x)"), "true → (∀x∈S. Revoked(x))");
    }

    #[test]
    fn unbalanced_parentheses() {
        let e = parse("forall x in S. (NotRevoked(x)").unwrap_err();
        assert!(e.message.contains("unbalanced parenthesis"), "{}", e.message);
        assert!(e.message.contains("line 1, column 16"), "{}", e.message);
        assert_eq!((e.line, e.col), (1, 30));
        assert!(e.excerpt.ends_with('^'));

        let e = parse("forall x in S. NotRevoked(x))").unwrap_err();
        assert!(e.message.contains("unbalanced parenthesis"), "{}", e.message);
        assert_eq!((e.line, e.col), (1, 29));
    }

    #[test]
    fn unknown_atom_lists_known_atoms() {
        let e = parse("forall x in S.\n  Revokd(x)").unwrap_err();
        assert!(e.message.contains("unknown atom 'Revokd'"));
        assert!(e.message.contains("NotRevoked") && e.message.contains("Prefix"));
        assert_eq!((e.line, e.col), (2, 3));
        assert_eq!(e.excerpt, "  Revokd(x)\n  ^");
    }

    #[test]
    fn free_and_shadowed_variables() {
        let e = parse("forall x in S. Revoked(y)").unwrap_err();
        assert!(e.message.contains("free variable 'y'"));
        assert_eq!((e.line, e.col), (1, 24));

        let e = parse("(exists x in S. Revoked(x)) & Revoked(x)").unwrap_err();
        assert!(e.message.contains("free variable 'x'"));

        let e = parse("forall x in S. exists x in T. Revoked(x)").unwrap_err();
        assert!(e.message.contains("shadows"));
        assert_eq!((e.line, e.col), (1, 23));
    }

    #[test]
    fn arity_and_argument_kinds() {
        let e = parse("forall x in S. Sig(x)").unwrap_err();
        assert!(e.message.contains("Sig expects 2 arguments"), "{}", e.message);
        assert!(e.message.contains("1 were given"));
        assert_eq!((e.line, e.col), (1, 16));

        let e = parse("forall x in S. Revoked(x.id)").unwrap_err();
        assert!(e.message.contains("must be a credential variable"), "{}", e.message);

        let e = parse("forall x in S. Range(x, 1, 2)").unwrap_err();
        assert!(e.message.contains("attribute reference such as x.age"), "{}", e.message);

        let e = parse("forall x in S. Sig(x, 5)").unwrap_err();
        assert!(e.message.contains("string literal"), "{}", e.message);
        assert_eq!(e.col, 23);
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_crash() {
        let src = format!("{}true{}", "(".repeat(5000), ")".repeat(5000));
        assert!(parse(&src).unwrap_err().message.contains("nested"));
        let src = format!("{}true", "!".repeat(5000));
        assert!(parse(&src).unwrap_err().message.contains("nested"));
    }

    #[test]
    fn missing_pieces_of_a_quantifier() {
        assert!(parse("forall x S. true").unwrap_err().message.contains("'in'"));
        assert!(parse("forall x in S true").unwrap_err().message.contains("'.'"));
        assert!(parse("atleast x in S. true").unwrap_err().message.contains("count"));
        assert!(parse("").unwrap_err().message.contains("expected a formula"));
    }
}
