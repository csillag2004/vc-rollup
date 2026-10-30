//! Negation normal form (DESIGN.md 3.3). Negation is never proved
//! cryptographically, so this stage pushes every `¬` inward until it meets
//! an atom and then replaces the negated atom by its positive dual.
//!
//! The input must be desugared (no `Implies`, `Active` or `SameHolder`).
//! In the result, `Not` wraps only credential atoms that have no dual; such
//! a leaf cannot be compiled and the stage emits a warning for it.
//!
//! Every rule application is recorded as a [`RewriteStep`] so the dashboard
//! can animate the rewriting.

use crate::ast::{Arg, Atom, AtomName, Formula, QuantKind};
use crate::json::Json;

/// One applied rewrite rule, with the affected subformula before and after,
/// rendered by [`Formula::pretty`]. The `after` string shows the result of
/// this one rule only; negations it introduces are handled by later steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewriteStep {
    pub rule: String,
    pub before: String,
    pub after: String,
}

impl RewriteStep {
    /// Records the rule `rule` that turned `before` into `after`.
    pub fn new(rule: &str, before: &Formula, after: &Formula) -> RewriteStep {
        RewriteStep { rule: rule.to_string(), before: before.pretty(), after: after.pretty() }
    }

    /// The JSON object `{rule, before, after}`.
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("rule", Json::str(&self.rule)),
            ("before", Json::str(&self.before)),
            ("after", Json::str(&self.after)),
        ])
    }
}

/// Converts a desugared formula to negation normal form. Applied rules go to
/// `steps` and problems with negated leaves go to `warnings`.
pub fn to_nnf(f: &Formula, steps: &mut Vec<RewriteStep>, warnings: &mut Vec<String>) -> Formula {
    match f {
        Formula::True | Formula::False | Formula::Atom(_) => f.clone(),
        Formula::Not(inner) => negate(inner, steps, warnings),
        Formula::And(parts) => Formula::and(parts.iter().map(|p| to_nnf(p, steps, warnings)).collect()),
        Formula::Or(parts) => Formula::or(parts.iter().map(|p| to_nnf(p, steps, warnings)).collect()),
        Formula::Implies(a, b) => {
            // Desugaring removes implications. Handling one here keeps the
            // function total for callers that skip that stage.
            let as_or = Formula::or(vec![Formula::not((**a).clone()), (**b).clone()]);
            steps.push(RewriteStep::new("desugar-implies", f, &as_or));
            to_nnf(&as_or, steps, warnings)
        }
        Formula::Quant { kind, var, domain, body, pos } => Formula::Quant {
            kind: *kind,
            var: var.clone(),
            domain: domain.clone(),
            body: Box::new(to_nnf(body, steps, warnings)),
            pos: *pos,
        },
    }
}

/// Returns the negation normal form of `¬inner`.
fn negate(inner: &Formula, steps: &mut Vec<RewriteStep>, warnings: &mut Vec<String>) -> Formula {
    let before = Formula::not(inner.clone());
    // `one_step` is the result of the single rule that applies at this node.
    // It may still contain negations, which the recursive call removes.
    let (rule, one_step): (&str, Formula) = match inner {
        Formula::True => ("not-true", Formula::False),
        Formula::False => ("not-false", Formula::True),
        Formula::Not(g) => ("double-negation", (**g).clone()),
        Formula::And(parts) => ("de-morgan-and", Formula::or(parts.iter().cloned().map(Formula::not).collect())),
        Formula::Or(parts) => ("de-morgan-or", Formula::and(parts.iter().cloned().map(Formula::not).collect())),
        Formula::Implies(a, b) => ("not-implies", Formula::and(vec![(**a).clone(), Formula::not((**b).clone())])),
        Formula::Quant { kind, var, domain, body, pos } => {
            let quant = |kind: QuantKind, body: Formula| Formula::Quant {
                kind,
                var: var.clone(),
                domain: domain.clone(),
                body: Box::new(body),
                pos: *pos,
            };
            let negated_body = Formula::not((**body).clone());
            match kind {
                QuantKind::Forall => ("not-forall", quant(QuantKind::Exists, negated_body)),
                QuantKind::Exists => ("not-exists", quant(QuantKind::Forall, negated_body)),
                // "Not at least k" is "at most k-1". The body keeps its sign.
                // "At least 0" is always true, so its negation is false.
                QuantKind::AtLeast(0) => ("not-atleast-zero", Formula::False),
                QuantKind::AtLeast(k) => ("not-atleast", quant(QuantKind::AtMost(k - 1), (**body).clone())),
                // "Not at most k" is "at least k+1".
                QuantKind::AtMost(k) => match k.checked_add(1) {
                    Some(k1) => ("not-atmost", quant(QuantKind::AtLeast(k1), (**body).clone())),
                    None => ("not-atmost-overflow", Formula::False),
                },
            }
        }
        Formula::Atom(atom) => return negate_atom(atom, steps, warnings),
    };
    steps.push(RewriteStep::new(rule, &before, &one_step));
    to_nnf(&one_step, steps, warnings)
}

/// Handles `¬atom`. Atoms with a dual are flipped. `Range` is rewritten to
/// the two intervals around it. Other credential atoms stay negated and
/// produce a warning, because no proof of their negation exists.
fn negate_atom(atom: &Atom, steps: &mut Vec<RewriteStep>, warnings: &mut Vec<String>) -> Formula {
    let before = Formula::not(Formula::Atom(atom.clone()));
    if let Some(dual) = atom.name.dual() {
        let after = Formula::Atom(Atom { name: dual, args: atom.args.clone(), pos: atom.pos });
        steps.push(RewriteStep::new("flip-atom", &before, &after));
        return after;
    }
    if atom.name == AtomName::Range {
        if let [attr, lo, hi] = atom.args.as_slice() {
            let range = |lo: Arg, hi: Arg| {
                Formula::Atom(Atom { name: AtomName::Range, args: vec![attr.clone(), lo, hi], pos: atom.pos })
            };
            let mut parts = Vec::new();
            // The interval below `lo`. It is empty when `lo` is 0.
            match lo {
                Arg::Nat(0) => {}
                Arg::Nat(n) => parts.push(range(Arg::Nat(0), Arg::Nat(n - 1))),
                other => parts.push(range(Arg::Nat(0), Arg::Name(format!("{}-1", other.pretty())))),
            }
            // The interval above `hi`. `MAX` stands for the largest value of
            // the numeric encoding; it is empty when `hi` is already `MAX`.
            let max = Arg::Name("MAX".to_string());
            match hi {
                Arg::Nat(n) => {
                    if let Some(n1) = n.checked_add(1) {
                        parts.push(range(Arg::Nat(n1), max));
                    }
                }
                Arg::Name(n) if n == "MAX" => {}
                other => parts.push(range(Arg::Name(format!("{}+1", other.pretty())), max)),
            }
            let after = Formula::or(parts);
            steps.push(RewriteStep::new("range-complement", &before, &after));
            warnings.push(format!(
                "negation of {} has no positive dual; the complement of an interval is a disjunction of two ranges, so it was rewritten to {}",
                atom.pretty(),
                after.pretty()
            ));
            return after;
        }
    }
    warnings.push(format!("negation of {} has no positive dual; it cannot be compiled", atom.pretty()));
    before
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desugar::desugar;
    use crate::parser::parse;

    fn run(src: &str) -> (String, Vec<RewriteStep>, Vec<String>) {
        let mut steps = Vec::new();
        let mut warnings = Vec::new();
        let mut notes = Vec::new();
        let d = desugar(&parse(src).expect("parses"), &mut steps, &mut notes);
        let n = to_nnf(&d, &mut steps, &mut warnings);
        (n.pretty(), steps, warnings)
    }

    #[test]
    fn negated_forall_becomes_exists() {
        let (p, steps, w) = run("!(forall x in S. NotRevoked(x))");
        assert_eq!(p, "∃x∈S. Revoked(x)");
        let rules: Vec<&str> = steps.iter().map(|s| s.rule.as_str()).collect();
        assert_eq!(rules, ["not-forall", "flip-atom"]);
        assert_eq!(steps[0].before, "¬(∀x∈S. NotRevoked(x))");
        assert_eq!(steps[0].after, "∃x∈S. ¬NotRevoked(x)");
        assert!(w.is_empty());
    }

    #[test]
    fn de_morgan_and_double_negation() {
        let (p, _, _) = run("forall x in S. !(Revoked(x) & !!Issued(x) | Eq(x.a, x.b))");
        assert_eq!(p, "∀x∈S. (NotRevoked(x) ∨ NotIssued(x)) ∧ Neq(x.a, x.b)");
    }

    #[test]
    fn implication_with_negated_quantifier() {
        let (p, _, _) = run("(exists x in S. Revoked(x)) -> (forall y in T. In(y.a, G))");
        assert_eq!(p, "(∀x∈S. NotRevoked(x)) ∨ (∀y∈T. In(y.a, G))");
    }

    #[test]
    fn counting_quantifiers() {
        assert_eq!(run("!(atleast 1 x in S. Revoked(x))").0, "∃≤0 x∈S. Revoked(x)");
        assert_eq!(run("!(atmost 2 x in S. Revoked(x))").0, "∃≥3 x∈S. Revoked(x)");
        assert_eq!(run("!(atleast 0 x in S. Revoked(x))").0, "false");
    }

    #[test]
    fn range_complement() {
        let (p, steps, w) = run("exists x in Presented. !Range(x.age, 18, 120)");
        assert_eq!(p, "∃x∈Presented. Range(x.age, 0, 17) ∨ Range(x.age, 121, MAX)");
        assert_eq!(steps.last().map(|s| s.rule.as_str()), Some("range-complement"));
        assert!(w[0].contains("disjunction of two ranges"));

        assert_eq!(run("exists x in S. !Range(x.a, 0, 9)").0, "∃x∈S. Range(x.a, 10, MAX)");
        assert_eq!(run("exists x in S. !Range(x.a, lo, MAX)").0, "∃x∈S. Range(x.a, 0, lo-1)");
    }

    #[test]
    fn atoms_without_dual_stay_negated() {
        let (p, _, w) = run("exists x in S. !Sig(x, \"A\")");
        assert_eq!(p, "∃x∈S. ¬Sig(x, \"A\")");
        assert_eq!(w, ["negation of Sig(x, \"A\") has no positive dual; it cannot be compiled"]);
    }
}
