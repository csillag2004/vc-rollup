//! Syntax tree of the query language, the table of known atoms, and the
//! pretty printer.
//!
//! Every later stage (desugaring, negation normal form, classification,
//! proof plan) works on [`Formula`]. The table [`ATOMS`] is the single place
//! that lists the atoms the language knows. To add an atom, add a variant to
//! [`AtomName`] and a row to [`ATOMS`]; the parser then accepts it and checks
//! its arguments without further changes.

use crate::json::Json;

/// A position in the source text. Lines and columns start at 1 and columns
/// count characters, not bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Pos {
    pub line: u32,
    pub col: u32,
}

/// The reserved domain name of the registry's issued set. This domain grows
/// with every issuance.
pub const DOMAIN_ISSUED: &str = "Issued";
/// The reserved domain name of the credentials the holder chooses to present.
pub const DOMAIN_PRESENTED: &str = "Presented";
/// The attribute that `SameHolder` compares (DESIGN.md 3.6, "Same holder").
pub const LINK_SECRET: &str = "link_secret";

/// What a quantifier ranges over. Use [`DomainKind::of`] to classify a
/// domain name taken from a [`Formula::Quant`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainKind {
    /// The registry's issued set, which grows.
    Issued,
    /// The holder-chosen set of presented credentials.
    Presented,
    /// A named group anchored by someone other than the prover.
    Group,
}

impl DomainKind {
    /// Classifies a domain name.
    pub fn of(domain: &str) -> DomainKind {
        match domain {
            DOMAIN_ISSUED => DomainKind::Issued,
            DOMAIN_PRESENTED => DomainKind::Presented,
            _ => DomainKind::Group,
        }
    }
}

/// The four quantifier forms of the surface syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuantKind {
    Forall,
    Exists,
    /// `atleast k x in D. body`: at least `k` distinct members satisfy the body.
    AtLeast(u64),
    /// `atmost k x in D. body`: at most `k` distinct members satisfy the body.
    AtMost(u64),
}

impl QuantKind {
    /// The Unicode prefix used by the pretty printer, for example `∀` or `∃≥2 `.
    pub fn symbol(&self) -> String {
        match self {
            QuantKind::Forall => "∀".to_string(),
            QuantKind::Exists => "∃".to_string(),
            QuantKind::AtLeast(k) => format!("∃≥{} ", k),
            QuantKind::AtMost(k) => format!("∃≤{} ", k),
        }
    }

    /// The keyword used in the JSON `kind` field of tree nodes.
    pub fn keyword(&self) -> &'static str {
        match self {
            QuantKind::Forall => "forall",
            QuantKind::Exists => "exists",
            QuantKind::AtLeast(_) => "atleast",
            QuantKind::AtMost(_) => "atmost",
        }
    }
}

/// The names of all atoms. Registry atoms depend on the registry state.
/// Credential atoms do not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomName {
    Revoked,
    NotRevoked,
    Issued,
    NotIssued,
    Active,
    Sig,
    Eq,
    Neq,
    SameHolder,
    In,
    NotIn,
    Commit,
    Range,
    Enc,
    EncDec,
    Hash,
    Prefix,
}

/// The kind of value an atom expects at one argument position. The parser
/// checks every argument against this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgKind {
    /// A bound credential variable, such as `x`.
    Cred,
    /// An attribute of a bound credential variable, such as `x.age`.
    Attr,
    /// A string literal.
    Str,
    /// The name of an anchored group or accumulator, such as `S`.
    Group,
    /// The name of a public key, such as `pk`.
    Key,
    /// A range bound: a natural number or a symbolic name such as `MAX`.
    Bound,
    /// A string literal or a name (used by `Hash` for the preimage).
    StrOrName,
}

impl ArgKind {
    /// A short description used in error messages.
    pub fn describe(&self) -> &'static str {
        match self {
            ArgKind::Cred => "a credential variable such as x",
            ArgKind::Attr => "an attribute reference such as x.age",
            ArgKind::Str => "a string literal",
            ArgKind::Group => "a group name such as S",
            ArgKind::Key => "a key name such as pk",
            ArgKind::Bound => "a natural number or a symbolic bound such as MAX",
            ArgKind::StrOrName => "a string literal or a name",
        }
    }
}

/// One row of the atom table: the surface name, the argument kinds, a usage
/// example for error messages, and whether the atom reads the registry.
pub struct AtomSig {
    pub name: AtomName,
    pub text: &'static str,
    pub args: &'static [ArgKind],
    pub usage: &'static str,
    pub registry: bool,
}

/// The table of all known atoms. The parser looks atoms up here by name.
pub const ATOMS: &[AtomSig] = &[
    AtomSig { name: AtomName::Revoked, text: "Revoked", args: &[ArgKind::Cred], usage: "Revoked(x)", registry: true },
    AtomSig { name: AtomName::NotRevoked, text: "NotRevoked", args: &[ArgKind::Cred], usage: "NotRevoked(x)", registry: true },
    AtomSig { name: AtomName::Issued, text: "Issued", args: &[ArgKind::Cred], usage: "Issued(x)", registry: true },
    AtomSig { name: AtomName::NotIssued, text: "NotIssued", args: &[ArgKind::Cred], usage: "NotIssued(x)", registry: true },
    AtomSig { name: AtomName::Active, text: "Active", args: &[ArgKind::Cred], usage: "Active(x)", registry: true },
    AtomSig { name: AtomName::Sig, text: "Sig", args: &[ArgKind::Cred, ArgKind::Str], usage: "Sig(x, \"issuer\")", registry: false },
    AtomSig { name: AtomName::Eq, text: "Eq", args: &[ArgKind::Attr, ArgKind::Attr], usage: "Eq(x.a, y.b)", registry: false },
    AtomSig { name: AtomName::Neq, text: "Neq", args: &[ArgKind::Attr, ArgKind::Attr], usage: "Neq(x.a, y.b)", registry: false },
    AtomSig { name: AtomName::SameHolder, text: "SameHolder", args: &[ArgKind::Cred, ArgKind::Cred], usage: "SameHolder(x, y)", registry: false },
    AtomSig { name: AtomName::In, text: "In", args: &[ArgKind::Attr, ArgKind::Group], usage: "In(x.a, G)", registry: false },
    AtomSig { name: AtomName::NotIn, text: "NotIn", args: &[ArgKind::Attr, ArgKind::Group], usage: "NotIn(x.a, G)", registry: false },
    AtomSig { name: AtomName::Commit, text: "Commit", args: &[ArgKind::Attr], usage: "Commit(x.a)", registry: false },
    AtomSig { name: AtomName::Range, text: "Range", args: &[ArgKind::Attr, ArgKind::Bound, ArgKind::Bound], usage: "Range(x.a, lo, hi)", registry: false },
    AtomSig { name: AtomName::Enc, text: "Enc", args: &[ArgKind::Attr, ArgKind::Key], usage: "Enc(x.a, pk)", registry: false },
    AtomSig { name: AtomName::EncDec, text: "EncDec", args: &[ArgKind::Attr, ArgKind::Key], usage: "EncDec(x.a, pk)", registry: false },
    AtomSig { name: AtomName::Hash, text: "Hash", args: &[ArgKind::Attr, ArgKind::StrOrName], usage: "Hash(x.a, \"preimage\")", registry: false },
    AtomSig { name: AtomName::Prefix, text: "Prefix", args: &[ArgKind::Attr, ArgKind::Str], usage: "Prefix(x.a, \"str\")", registry: false },
];

impl AtomName {
    /// Looks an atom up by its surface name. Returns `None` for unknown names.
    pub fn lookup(text: &str) -> Option<&'static AtomSig> {
        ATOMS.iter().find(|sig| sig.text == text)
    }

    /// Returns the table row of this atom.
    pub fn sig(&self) -> &'static AtomSig {
        // Every variant has a row; the unit test `every_atom_has_a_row`
        // guards this. The fallback keeps the function total.
        ATOMS.iter().find(|sig| sig.name == *self).unwrap_or(&ATOMS[0])
    }

    /// The surface name, for example `"NotRevoked"`.
    pub fn text(&self) -> &'static str {
        self.sig().text
    }

    /// True for atoms whose truth depends on the registry state.
    pub fn is_registry(&self) -> bool {
        self.sig().registry
    }

    /// The atom that is equivalent to the negation of this one, if the
    /// language has it. The negation normal form uses this at the leaves.
    pub fn dual(&self) -> Option<AtomName> {
        match self {
            AtomName::Revoked => Some(AtomName::NotRevoked),
            AtomName::NotRevoked => Some(AtomName::Revoked),
            AtomName::Issued => Some(AtomName::NotIssued),
            AtomName::NotIssued => Some(AtomName::Issued),
            AtomName::Eq => Some(AtomName::Neq),
            AtomName::Neq => Some(AtomName::Eq),
            AtomName::In => Some(AtomName::NotIn),
            AtomName::NotIn => Some(AtomName::In),
            _ => None,
        }
    }
}

/// One argument of an atom, after the parser has checked it against the
/// atom's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arg {
    /// A bound variable, with an attribute when written as `x.a`.
    Var { name: String, attr: Option<String> },
    Nat(u64),
    Str(String),
    /// A group name, a key name, or a symbolic bound such as `MAX`.
    Name(String),
}

impl Arg {
    /// The variable this argument mentions, if any.
    pub fn var(&self) -> Option<&str> {
        match self {
            Arg::Var { name, .. } => Some(name),
            _ => None,
        }
    }

    /// Renders the argument in surface syntax. Strings are quoted and escaped
    /// the same way the lexer reads them.
    pub fn pretty(&self) -> String {
        match self {
            Arg::Var { name, attr: None } => name.clone(),
            Arg::Var { name, attr: Some(a) } => format!("{}.{}", name, a),
            Arg::Nat(n) => n.to_string(),
            Arg::Name(n) => n.clone(),
            Arg::Str(s) => {
                let mut out = String::from("\"");
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\t' => out.push_str("\\t"),
                        c => out.push(c),
                    }
                }
                out.push('"');
                out
            }
        }
    }
}

/// An atom with its checked arguments and the position of its name in the
/// source. Atoms created by rewriting keep the position of the atom they
/// came from, so the UI can point back into the source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Atom {
    pub name: AtomName,
    pub args: Vec<Arg>,
    pub pos: Pos,
}

impl Atom {
    /// Renders the atom, for example `Sig(x, "CertBody")`.
    pub fn pretty(&self) -> String {
        let args: Vec<String> = self.args.iter().map(Arg::pretty).collect();
        format!("{}({})", self.name.text(), args.join(", "))
    }
}

/// A formula. The parser produces all variants. After desugaring there is no
/// `Implies`. After the negation normal form, `Not` wraps only atoms that
/// have no positive dual.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Formula {
    True,
    False,
    Atom(Atom),
    Not(Box<Formula>),
    /// A conjunction of two or more formulas. Build it with [`Formula::and`].
    And(Vec<Formula>),
    /// A disjunction of two or more formulas. Build it with [`Formula::or`].
    Or(Vec<Formula>),
    Implies(Box<Formula>, Box<Formula>),
    Quant {
        kind: QuantKind,
        var: String,
        domain: String,
        body: Box<Formula>,
        pos: Pos,
    },
}

impl Formula {
    /// Builds a conjunction and flattens nested conjunctions, so that
    /// `a ∧ (b ∧ c)` and `(a ∧ b) ∧ c` have the same tree. An empty list
    /// gives `True` and a single formula is returned unchanged.
    pub fn and(parts: Vec<Formula>) -> Formula {
        let mut flat = Vec::new();
        for p in parts {
            match p {
                Formula::And(inner) => flat.extend(inner),
                other => flat.push(other),
            }
        }
        match flat.len() {
            0 => Formula::True,
            1 => flat.remove(0),
            _ => Formula::And(flat),
        }
    }

    /// Builds a disjunction and flattens nested disjunctions. An empty list
    /// gives `False` and a single formula is returned unchanged.
    pub fn or(parts: Vec<Formula>) -> Formula {
        let mut flat = Vec::new();
        for p in parts {
            match p {
                Formula::Or(inner) => flat.extend(inner),
                other => flat.push(other),
            }
        }
        match flat.len() {
            0 => Formula::False,
            1 => flat.remove(0),
            _ => Formula::Or(flat),
        }
    }

    /// Wraps a formula in a negation.
    #[allow(clippy::should_implement_trait)]
    pub fn not(f: Formula) -> Formula {
        Formula::Not(Box::new(f))
    }

    /// Renders the formula with Unicode symbols. Parentheses are added only
    /// where the grammar needs them. A quantifier that is an operand of a
    /// binary operator is always parenthesised, because its body would
    /// otherwise extend to the right.
    pub fn pretty(&self) -> String {
        match self {
            Formula::True => "true".to_string(),
            Formula::False => "false".to_string(),
            Formula::Atom(a) => a.pretty(),
            Formula::Not(f) => format!("¬{}", f.pretty_at(4)),
            Formula::And(parts) => join(parts, " ∧ ", 3),
            Formula::Or(parts) => join(parts, " ∨ ", 2),
            Formula::Implies(a, b) => format!("{} → {}", a.pretty_at(2), b.pretty_at(1)),
            Formula::Quant { kind, var, domain, body, .. } => {
                format!("{}{}∈{}. {}", kind.symbol(), var, domain, body.pretty())
            }
        }
    }

    /// The binding strength of the top operator. Larger binds tighter.
    fn level(&self) -> u8 {
        match self {
            Formula::Quant { .. } => 0,
            Formula::Implies(..) => 1,
            Formula::Or(_) => 2,
            Formula::And(_) => 3,
            Formula::Not(_) => 4,
            _ => 5,
        }
    }

    /// Renders the formula as an operand of an operator with the given level.
    fn pretty_at(&self, min_level: u8) -> String {
        if self.level() < min_level {
            format!("({})", self.pretty())
        } else {
            self.pretty()
        }
    }

    /// Converts the formula to the JSON tree shape `{kind, label, children}`
    /// with extra fields per node kind (see README.md).
    pub fn to_tree(&self) -> Json {
        let mut fields: Vec<(String, Json)> = Vec::new();
        let kind: &str;
        let mut children: Vec<Json> = Vec::new();
        let mut extra: Vec<(String, Json)> = Vec::new();
        match self {
            Formula::True => kind = "true",
            Formula::False => kind = "false",
            Formula::Atom(a) => {
                kind = "atom";
                extra.push(("name".into(), Json::str(a.name.text())));
                extra.push(("args".into(), Json::Arr(a.args.iter().map(|x| Json::str(&x.pretty())).collect())));
                extra.push(("line".into(), Json::Num(a.pos.line as u64)));
                extra.push(("col".into(), Json::Num(a.pos.col as u64)));
            }
            Formula::Not(f) => {
                kind = "not";
                children.push(f.to_tree());
            }
            Formula::And(parts) => {
                kind = "and";
                children = parts.iter().map(Formula::to_tree).collect();
            }
            Formula::Or(parts) => {
                kind = "or";
                children = parts.iter().map(Formula::to_tree).collect();
            }
            Formula::Implies(a, b) => {
                kind = "implies";
                children.push(a.to_tree());
                children.push(b.to_tree());
            }
            Formula::Quant { kind: q, var, domain, body, pos } => {
                kind = q.keyword();
                extra.push(("var".into(), Json::str(var)));
                extra.push(("domain".into(), Json::str(domain)));
                if let QuantKind::AtLeast(k) | QuantKind::AtMost(k) = q {
                    extra.push(("k".into(), Json::Num(*k)));
                }
                extra.push(("line".into(), Json::Num(pos.line as u64)));
                extra.push(("col".into(), Json::Num(pos.col as u64)));
                children.push(body.to_tree());
            }
        }
        fields.push(("kind".into(), Json::str(kind)));
        fields.push(("label".into(), Json::str(&self.pretty())));
        fields.push(("children".into(), Json::Arr(children)));
        fields.extend(extra);
        Json::Obj(fields)
    }
}

/// Joins operands of an n-ary operator. Operands at the same level or lower
/// get parentheses, except that the flattened constructors never nest the
/// same operator.
fn join(parts: &[Formula], sep: &str, level: u8) -> String {
    let rendered: Vec<String> = parts.iter().map(|p| p.pretty_at(level + 1)).collect();
    rendered.join(sep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(name: AtomName, var: &str) -> Formula {
        Formula::Atom(Atom {
            name,
            args: vec![Arg::Var { name: var.into(), attr: None }],
            pos: Pos::default(),
        })
    }

    #[test]
    fn every_atom_has_a_row() {
        let all = [
            AtomName::Revoked, AtomName::NotRevoked, AtomName::Issued, AtomName::NotIssued,
            AtomName::Active, AtomName::Sig, AtomName::Eq, AtomName::Neq, AtomName::SameHolder,
            AtomName::In, AtomName::NotIn, AtomName::Commit, AtomName::Range, AtomName::Enc,
            AtomName::EncDec, AtomName::Hash, AtomName::Prefix,
        ];
        assert_eq!(all.len(), ATOMS.len());
        for name in all {
            assert_eq!(name.sig().name, name);
        }
    }

    #[test]
    fn duals_are_involutions() {
        for sig in ATOMS {
            if let Some(d) = sig.name.dual() {
                assert_eq!(d.dual(), Some(sig.name));
            }
        }
    }

    #[test]
    fn and_flattens() {
        let f = Formula::and(vec![
            atom(AtomName::Revoked, "x"),
            Formula::and(vec![atom(AtomName::Issued, "x"), atom(AtomName::NotRevoked, "x")]),
        ]);
        assert_eq!(f.pretty(), "Revoked(x) ∧ Issued(x) ∧ NotRevoked(x)");
    }

    #[test]
    fn pretty_adds_needed_parentheses() {
        let q = Formula::Quant {
            kind: QuantKind::Exists,
            var: "x".into(),
            domain: "S".into(),
            body: Box::new(atom(AtomName::Revoked, "x")),
            pos: Pos::default(),
        };
        let f = Formula::and(vec![q, Formula::or(vec![Formula::True, Formula::False])]);
        assert_eq!(f.pretty(), "(∃x∈S. Revoked(x)) ∧ (true ∨ false)");
        let n = Formula::not(Formula::and(vec![Formula::True, Formula::False]));
        assert_eq!(n.pretty(), "¬(true ∧ false)");
    }

    #[test]
    fn string_arguments_are_escaped() {
        assert_eq!(Arg::Str("a\"b\\".into()).pretty(), "\"a\\\"b\\\\\"");
    }
}
