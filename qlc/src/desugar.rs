//! Desugaring. This stage removes the three abbreviations of the surface
//! syntax so that later stages see only primitive connectives and atoms:
//!
//! - `φ → ψ` becomes `¬φ ∨ ψ`.
//! - `Active(x)` becomes `Issued(x) ∧ NotRevoked(x)`. When `x` ranges over a
//!   named anchored group or over `Presented`, its members are issued by
//!   construction, so `Active(x)` becomes `NotRevoked(x)` and a note records
//!   the simplification.
//! - `SameHolder(x, y)` becomes `Eq(x.link_secret, y.link_secret)`.

use crate::ast::{Arg, Atom, AtomName, DomainKind, Formula, LINK_SECRET};
use crate::nnf::RewriteStep;

/// Desugars `f`. Each applied rule is appended to `steps` and each
/// simplification of `Active` is appended to `notes`.
pub fn desugar(f: &Formula, steps: &mut Vec<RewriteStep>, notes: &mut Vec<String>) -> Formula {
    let mut env: Vec<(String, String)> = Vec::new();
    go(f, &mut env, steps, notes)
}

/// `env` maps each bound variable to the domain it ranges over.
fn go(f: &Formula, env: &mut Vec<(String, String)>, steps: &mut Vec<RewriteStep>, notes: &mut Vec<String>) -> Formula {
    match f {
        Formula::True | Formula::False => f.clone(),
        Formula::Not(inner) => Formula::not(go(inner, env, steps, notes)),
        Formula::And(parts) => Formula::and(parts.iter().map(|p| go(p, env, steps, notes)).collect()),
        Formula::Or(parts) => Formula::or(parts.iter().map(|p| go(p, env, steps, notes)).collect()),
        Formula::Implies(a, b) => {
            let a2 = go(a, env, steps, notes);
            let b2 = go(b, env, steps, notes);
            let before = Formula::Implies(Box::new(a2.clone()), Box::new(b2.clone()));
            let after = Formula::or(vec![Formula::not(a2), b2]);
            steps.push(RewriteStep::new("desugar-implies", &before, &after));
            after
        }
        Formula::Quant { kind, var, domain, body, pos } => {
            env.push((var.clone(), domain.clone()));
            let body2 = go(body, env, steps, notes);
            env.pop();
            Formula::Quant { kind: *kind, var: var.clone(), domain: domain.clone(), body: Box::new(body2), pos: *pos }
        }
        Formula::Atom(atom) => desugar_atom(atom, env, steps, notes),
    }
}

fn desugar_atom(atom: &Atom, env: &[(String, String)], steps: &mut Vec<RewriteStep>, notes: &mut Vec<String>) -> Formula {
    let before = Formula::Atom(atom.clone());
    match atom.name {
        AtomName::Active => {
            let var = atom.args.first().and_then(Arg::var).unwrap_or("");
            let domain = env.iter().rev().find(|(v, _)| v == var).map(|(_, d)| d.as_str()).unwrap_or("");
            let not_revoked = Formula::Atom(Atom { name: AtomName::NotRevoked, args: atom.args.clone(), pos: atom.pos });
            if DomainKind::of(domain) == DomainKind::Issued {
                let issued = Formula::Atom(Atom { name: AtomName::Issued, args: atom.args.clone(), pos: atom.pos });
                let after = Formula::and(vec![issued, not_revoked]);
                steps.push(RewriteStep::new("desugar-active", &before, &after));
                after
            } else {
                steps.push(RewriteStep::new("desugar-active-members-issued", &before, &not_revoked));
                notes.push(format!(
                    "Active({v}) was simplified to NotRevoked({v}): {v} ranges over {d}, whose members are issued by construction.",
                    v = var,
                    d = domain
                ));
                not_revoked
            }
        }
        AtomName::SameHolder => {
            let args = atom
                .args
                .iter()
                .map(|a| match a {
                    Arg::Var { name, .. } => Arg::Var { name: name.clone(), attr: Some(LINK_SECRET.to_string()) },
                    other => other.clone(),
                })
                .collect();
            let after = Formula::Atom(Atom { name: AtomName::Eq, args, pos: atom.pos });
            steps.push(RewriteStep::new("desugar-sameholder", &before, &after));
            after
        }
        _ => before,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn run(src: &str) -> (String, Vec<RewriteStep>, Vec<String>) {
        let mut steps = Vec::new();
        let mut notes = Vec::new();
        let f = desugar(&parse(src).expect("parses"), &mut steps, &mut notes);
        (f.pretty(), steps, notes)
    }

    #[test]
    fn implication() {
        let (p, steps, _) = run("forall x in S. Revoked(x) -> NotRevoked(x)");
        assert_eq!(p, "∀x∈S. ¬Revoked(x) ∨ NotRevoked(x)");
        assert_eq!(steps[0].rule, "desugar-implies");
    }

    #[test]
    fn active_depends_on_the_domain() {
        let (p, _, notes) = run("forall x in Issued. Active(x)");
        assert_eq!(p, "∀x∈Issued. Issued(x) ∧ NotRevoked(x)");
        assert!(notes.is_empty());

        let (p, _, notes) = run("forall x in S. Active(x)");
        assert_eq!(p, "∀x∈S. NotRevoked(x)");
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("ranges over S"));
    }

    #[test]
    fn same_holder() {
        let (p, _, _) = run("exists x in Presented. exists y in Presented. SameHolder(x, y)");
        assert_eq!(p, "∃x∈Presented. ∃y∈Presented. Eq(x.link_secret, y.link_secret)");
    }
}
