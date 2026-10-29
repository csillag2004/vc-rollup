//! Classification by polarity (DESIGN.md 3.5), the interference table, the
//! contract requirement (DESIGN.md 4) and the warnings about statements that
//! are vacuous or need no proof (DESIGN.md 3.6 and 3.7).
//!
//! The input is a formula in negation normal form. The classification is a
//! syntactic sufficient condition: a formula classified as monotone is
//! monotone in the semantic sense of DESIGN.md 3.5, and the same holds for
//! antitone. A formula classified as non-monotone may still be semantically
//! monotone or antitone (for example when it is a tautology); the atomic
//! test is then a safe, conservative choice.

use crate::ast::{Atom, AtomName, DomainKind, Formula, Pos, QuantKind};
use crate::json::Json;

/// The direction in which a registry-dependent part of the formula moves as
/// the registry grows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polarity {
    /// Can only switch from false to true.
    Up,
    /// Can only switch from true to false.
    Down,
}

impl Polarity {
    fn flipped(self) -> Polarity {
        match self {
            Polarity::Up => Polarity::Down,
            Polarity::Down => Polarity::Up,
        }
    }

    /// `"up"` or `"down"`, as used in the JSON output.
    pub fn text(self) -> &'static str {
        match self {
            Polarity::Up => "up",
            Polarity::Down => "down",
        }
    }
}

/// The registry update that can change the truth of an occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Issue,
    Revoke,
}

/// One registry-dependent place in the formula: a registry atom, or a
/// quantifier over the growing domain `Issued`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Occurrence {
    /// The atom or the quantifier head, pretty printed.
    pub atom: String,
    pub polarity: Polarity,
    /// Why the occurrence has this polarity.
    pub via: String,
    pub trigger: Trigger,
    pub pos: Pos,
}

impl Occurrence {
    /// The JSON object `{atom, polarity, via, line, col}`.
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("atom", Json::str(&self.atom)),
            ("polarity", Json::str(self.polarity.text())),
            ("via", Json::str(&self.via)),
            ("line", Json::Num(self.pos.line as u64)),
            ("col", Json::Num(self.pos.col as u64)),
        ])
    }
}

/// The four classes of DESIGN.md 3.5. `StateIndependent` covers formulas
/// without any registry-dependent part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Monotone,
    Antitone,
    NonMonotone,
    StateIndependent,
}

impl Class {
    /// The class name used in the JSON output.
    pub fn text(self) -> &'static str {
        match self {
            Class::Monotone => "monotone",
            Class::Antitone => "antitone",
            Class::NonMonotone => "non-monotone",
            Class::StateIndependent => "state-independent",
        }
    }

    /// The plain-language reading of the class.
    pub fn gloss(self) -> &'static str {
        match self {
            Class::Monotone => "persistent: once true, always true; may be proved against any authenticated historical registry value; no on-chain coordination",
            Class::Antitone => "fails permanently: once false, always false; needs the atomic test; a failure is itself a persistent, provable fact (the negation is monotone)",
            Class::NonMonotone => "needs the atomic test",
            Class::StateIndependent => "does not depend on the registry: no registry value is read, so no on-chain coordination is needed",
        }
    }
}

/// One row of the interference table for this formula.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interference {
    pub update: &'static str,
    pub can_falsify: bool,
    pub why: String,
}

/// The coordination the registry contract must provide for a guarded update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    /// `"none"`, `"cas-groups"` or `"cas-global"`.
    pub mode: &'static str,
    pub detail: String,
}

/// Everything the classification stage produces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classification {
    pub class: Class,
    pub explanation: String,
    pub occurrences: Vec<Occurrence>,
    /// The domains of the quantifiers whose body or domain depends on the
    /// registry, sorted and without duplicates.
    pub footprint: Vec<String>,
    pub interference: Vec<Interference>,
    pub contract: Contract,
}

/// Classifies a formula in negation normal form.
pub fn classify(nnf: &Formula) -> Classification {
    let mut occurrences = Vec::new();
    let mut footprint = Vec::new();
    collect(nnf, &mut Vec::new(), &mut occurrences, &mut footprint);
    footprint.sort();
    footprint.dedup();

    let up = occurrences.iter().filter(|o| o.polarity == Polarity::Up).count();
    let down = occurrences.len() - up;
    let class = match (up > 0, down > 0) {
        (true, false) => Class::Monotone,
        (false, true) => Class::Antitone,
        (true, true) => Class::NonMonotone,
        (false, false) => Class::StateIndependent,
    };
    let counts = format!("{} up occurrence{} and {} down occurrence{}", up, plural(up), down, plural(down));
    let reason = match class {
        Class::Monotone => "Every registry-dependent part can only switch from false to true as the registry grows, so the formula is monotone.",
        Class::Antitone => "Every registry-dependent part can only switch from true to false as the registry grows, so the formula is antitone.",
        Class::NonMonotone => "The formula mixes both directions, so neither argument applies and it is treated as non-monotone.",
        Class::StateIndependent => "No registry atom and no quantifier over Issued occurs, so the truth value does not depend on the registry state.",
    };
    let explanation = format!(
        "The negation normal form has {}. {} This is a syntactic sufficient condition for the semantic definitions (dashboard section 2.5): the verdicts monotone, antitone and state-independent are sound, while a formula reported as non-monotone may still be semantically monotone or antitone.",
        counts, reason
    );

    let interference = interference(&occurrences, &footprint);
    let contract = contract(class, &occurrences, &footprint);
    Classification { class, explanation, occurrences, footprint, interference, contract }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Walks the formula. `flips` holds the pretty heads of the enclosing
/// `atmost` quantifiers; an odd number of them flips the polarity.
fn collect(f: &Formula, flips: &mut Vec<String>, out: &mut Vec<Occurrence>, footprint: &mut Vec<String>) {
    match f {
        Formula::True | Formula::False => {}
        // After the negation normal form, `Not` wraps only credential atoms,
        // which are neutral. Recursing keeps this correct for any input.
        Formula::Not(inner) => collect(inner, flips, out, footprint),
        Formula::Implies(a, b) => {
            collect(a, flips, out, footprint);
            collect(b, flips, out, footprint);
        }
        Formula::And(parts) | Formula::Or(parts) => {
            for p in parts {
                collect(p, flips, out, footprint);
            }
        }
        Formula::Atom(atom) => {
            if let Some(o) = atom_occurrence(atom, flips) {
                out.push(o);
            }
        }
        Formula::Quant { kind, var, domain, body, pos } => {
            let before = out.len();
            let head = format!("{}{}∈{}", kind.symbol(), var, domain);
            let is_atmost = matches!(kind, QuantKind::AtMost(_));
            if is_atmost {
                flips.push(head.clone());
            }
            if DomainKind::of(domain) == DomainKind::Issued {
                // A growing domain adds members. For ∀ a new member can
                // break the statement (it hides NotIssued(x) ∨ φ). For ∃
                // and atleast a new member can only add a witness. For
                // atmost the enclosing flip turns that into a down.
                let (base, why) = match kind {
                    QuantKind::Forall => (Polarity::Down, "∀ over the growing domain Issued hides the down-atom NotIssued(x) in NotIssued(x) ∨ φ"),
                    _ => (Polarity::Up, "a quantifier that counts witnesses over the growing domain Issued hides the up-atom Issued(x) in Issued(x) ∧ φ"),
                };
                out.push(Occurrence {
                    atom: head.clone(),
                    polarity: apply(base, flips),
                    via: with_flips(why, flips),
                    trigger: Trigger::Issue,
                    pos: *pos,
                });
            }
            collect(body, flips, out, footprint);
            if is_atmost {
                flips.pop();
            }
            if out.len() > before {
                footprint.push(domain.clone());
            }
        }
    }
}

fn atom_occurrence(atom: &Atom, flips: &[String]) -> Option<Occurrence> {
    let (base, why, trigger) = match atom.name {
        AtomName::Revoked => (Polarity::Up, "Revoked is an up-atom: the revoked set only grows", Trigger::Revoke),
        AtomName::Issued => (Polarity::Up, "Issued is an up-atom: the issued set only grows", Trigger::Issue),
        AtomName::NotRevoked => (Polarity::Down, "NotRevoked is a down-atom: a revocation can end it", Trigger::Revoke),
        AtomName::NotIssued => (Polarity::Down, "NotIssued is a down-atom: an issuance can end it", Trigger::Issue),
        _ => return None,
    };
    Some(Occurrence {
        atom: atom.pretty(),
        polarity: apply(base, flips),
        via: with_flips(why, flips),
        trigger,
        pos: atom.pos,
    })
}

fn apply(base: Polarity, flips: &[String]) -> Polarity {
    if flips.len() % 2 == 1 { base.flipped() } else { base }
}

fn with_flips(why: &str, flips: &[String]) -> String {
    if flips.is_empty() {
        why.to_string()
    } else {
        format!("{}; flipped by {}", why, flips.join(" and by "))
    }
}

/// Builds the three rows of the interference table (DESIGN.md 3.5). Only a
/// down occurrence can turn a true formula false.
fn interference(occurrences: &[Occurrence], footprint: &[String]) -> Vec<Interference> {
    let down_on = |t: Trigger| -> Vec<&str> {
        occurrences
            .iter()
            .filter(|o| o.polarity == Polarity::Down && o.trigger == t)
            .map(|o| o.atom.as_str())
            .collect()
    };
    let issue_down = down_on(Trigger::Issue);
    let revoke_down = down_on(Trigger::Revoke);
    let covers_everything = footprint.iter().any(|d| DomainKind::of(d) == DomainKind::Issued);

    let issue = if issue_down.is_empty() {
        Interference {
            update: "issue",
            can_falsify: false,
            why: "No down occurrence depends on the issued set, so an issuance cannot turn the formula false.".to_string(),
        }
    } else {
        Interference {
            update: "issue",
            can_falsify: true,
            why: format!("An issuance can falsify the down occurrence {}.", issue_down.join(", ")),
        }
    };
    let inside = if revoke_down.is_empty() {
        Interference {
            update: "revoke inside footprint",
            can_falsify: false,
            why: "No down occurrence depends on the revoked set, so a revocation cannot turn the formula false.".to_string(),
        }
    } else {
        Interference {
            update: "revoke inside footprint",
            can_falsify: true,
            why: format!(
                "Revoking a member of {} can falsify the down occurrence {}.",
                footprint.join(", "),
                revoke_down.join(", ")
            ),
        }
    };
    let outside = Interference {
        update: "revoke outside footprint",
        can_falsify: false,
        why: if covers_everything {
            "The footprint contains Issued, so every credential is inside it and no revocation falls outside.".to_string()
        } else if footprint.is_empty() {
            "The formula does not read the registry.".to_string()
        } else {
            format!("The formula reads the registry only through {}, so a revocation elsewhere cannot change it.", footprint.join(", "))
        },
    };
    vec![issue, inside, outside]
}

/// Chooses the contract requirement (DESIGN.md 4).
fn contract(class: Class, occurrences: &[Occurrence], footprint: &[String]) -> Contract {
    match class {
        Class::Monotone | Class::StateIndependent => Contract {
            mode: "none",
            detail: "none: proof may bind to any authenticated historical registry value (verifier must authenticate it; if an ID is hidden, prove against the latest or a verifier-chosen value)".to_string(),
        },
        Class::Antitone => {
            let groups_only = footprint.iter().all(|d| DomainKind::of(d) == DomainKind::Group);
            let issue_sensitive = occurrences.iter().any(|o| o.trigger == Trigger::Issue);
            if groups_only && !issue_sensitive && !footprint.is_empty() {
                Contract {
                    mode: "cas-groups",
                    detail: format!(
                        "compare-and-swap, may be narrowed to the per-group version counters of {} (the groups must be public; a hidden group needs the global version)",
                        footprint.join(", ")
                    ),
                }
            } else {
                let reason = if issue_sensitive {
                    "the formula can be falsified by an issuance"
                } else {
                    "the formula ranges over Presented, whose credential IDs are hidden, so no per-group counter covers them"
                };
                Contract { mode: "cas-global", detail: format!("compare-and-swap on the global registry version ({})", reason) }
            }
        }
        Class::NonMonotone => Contract {
            mode: "cas-global",
            detail: "compare-and-swap on the global registry version (a formula with both up and down occurrences may change in either direction)".to_string(),
        },
    }
}

/// Warnings and notes about statements that are vacuous, publicly decidable,
/// or that carry no more weight than a signature. Returns `(warnings, notes)`.
pub fn lint(nnf: &Formula, classification: &Classification) -> (Vec<String>, Vec<String>) {
    let mut facts = Facts::default();
    scan(nnf, &mut facts);
    let mut warnings = Vec::new();
    let mut notes = Vec::new();

    if facts.universal_over_presented {
        warnings.push("the holder chooses what to present, so a universal statement over Presented is vacuous unless the issuer certifies completeness (numbered credentials or a portfolio credential)".to_string());
    }
    for group in &facts.forall_revoked_groups {
        warnings.push(format!(
            "∀ … Revoked over the public group {}: publicly decidable by intersecting the public revoked list with the group; a proof is needed only if the group is hidden or the verifier stores only accumulator values",
            group
        ));
    }
    if facts.not_issued {
        warnings.push("NotIssued(x) is a non-membership statement in the issued accumulator; the design issues no non-membership witnesses (dashboard section 2.4), so it cannot be compiled to a proof and is decided from public registry data only".to_string());
    }
    if !classification.occurrences.is_empty() && !facts.hidden_part {
        notes.push("This registry statement has no hidden part. If a single-trapdoor issuer makes it about its own registry, the proof carries no more weight than a signed statement; proofs matter when the prover is not the issuer or the verifier stores only accumulator values (dashboard section 2.7).".to_string());
    }
    for group in &facts.exists_groups {
        notes.push(format!(
            "∃ over the group {g}: the prover needs a receipt inside acc_{g}, which takes G1 powers of α up to |{g}|−1 or an issuer-published receipt. For a small group an |{g}|-branch OR proof avoids the SRS.",
            g = group
        ));
    }
    (warnings, notes)
}

#[derive(Default)]
struct Facts {
    universal_over_presented: bool,
    forall_revoked_groups: Vec<String>,
    exists_groups: Vec<String>,
    not_issued: bool,
    /// True when something stays hidden from the verifier: an existential
    /// witness, a presented credential, or a credential atom.
    hidden_part: bool,
}

fn scan(f: &Formula, facts: &mut Facts) {
    match f {
        Formula::True | Formula::False => {}
        Formula::Atom(a) => {
            if a.name == AtomName::NotIssued {
                facts.not_issued = true;
            }
            if !a.name.is_registry() {
                facts.hidden_part = true;
            }
        }
        Formula::Not(inner) => scan(inner, facts),
        Formula::Implies(a, b) => {
            scan(a, facts);
            scan(b, facts);
        }
        Formula::And(parts) | Formula::Or(parts) => parts.iter().for_each(|p| scan(p, facts)),
        Formula::Quant { kind, domain, body, .. } => {
            let domain_kind = DomainKind::of(domain);
            let universal = matches!(kind, QuantKind::Forall | QuantKind::AtMost(_));
            if domain_kind == DomainKind::Presented {
                facts.hidden_part = true;
                if universal {
                    facts.universal_over_presented = true;
                }
            }
            if !universal {
                facts.hidden_part = true;
                if domain_kind == DomainKind::Group && !facts.exists_groups.contains(domain) {
                    facts.exists_groups.push(domain.clone());
                }
            }
            if *kind == QuantKind::Forall
                && domain_kind == DomainKind::Group
                && mentions(body, AtomName::Revoked)
                && !facts.forall_revoked_groups.contains(domain)
            {
                facts.forall_revoked_groups.push(domain.clone());
            }
            scan(body, facts);
        }
    }
}

/// True when `f` contains the atom `name` outside nested quantifiers.
fn mentions(f: &Formula, name: AtomName) -> bool {
    match f {
        Formula::Atom(a) => a.name == name,
        Formula::And(parts) | Formula::Or(parts) => parts.iter().any(|p| mentions(p, name)),
        Formula::Not(inner) => mentions(inner, name),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desugar::desugar;
    use crate::nnf::to_nnf;
    use crate::parser::parse;

    fn nnf_of(src: &str) -> Formula {
        let (mut s, mut w, mut n) = (Vec::new(), Vec::new(), Vec::new());
        let d = desugar(&parse(src).expect("parses"), &mut s, &mut n);
        to_nnf(&d, &mut s, &mut w)
    }

    fn class_of(src: &str) -> Class {
        classify(&nnf_of(src)).class
    }

    #[test]
    fn the_four_monadic_forms() {
        assert_eq!(class_of("forall x in S. NotRevoked(x)"), Class::Antitone);
        assert_eq!(class_of("forall x in S. Revoked(x)"), Class::Monotone);
        assert_eq!(class_of("exists x in S. NotRevoked(x)"), Class::Antitone);
        assert_eq!(class_of("exists x in S. Revoked(x)"), Class::Monotone);
    }

    #[test]
    fn growing_domain() {
        let c = classify(&nnf_of("forall x in Issued. Revoked(x)"));
        assert_eq!(c.class, Class::NonMonotone);
        assert_eq!(c.occurrences.len(), 2);
        assert_eq!(c.occurrences[0].polarity, Polarity::Down);
        assert!(c.occurrences[0].via.contains("NotIssued"));
        assert!(c.interference[0].can_falsify);
        assert_eq!(class_of("exists x in Issued. Revoked(x)"), Class::Monotone);
        assert_eq!(class_of("forall x in Issued. NotRevoked(x)"), Class::Antitone);
        assert_eq!(class_of("atmost 3 x in Issued. Revoked(x)"), Class::Antitone);
        assert_eq!(class_of("atleast 3 x in Issued. Revoked(x)"), Class::Monotone);
    }

    #[test]
    fn atmost_flips_and_nests() {
        assert_eq!(class_of("atmost 0 x in S. Revoked(x)"), Class::Antitone);
        assert_eq!(class_of("atmost 0 x in S. NotRevoked(x)"), Class::Monotone);
        assert_eq!(class_of("atmost 0 x in S. atmost 0 y in T. Revoked(y)"), Class::Monotone);
        let c = classify(&nnf_of("atmost 0 x in S. Revoked(x)"));
        assert!(c.occurrences[0].via.contains("flipped by ∃≤0 x∈S"));
    }

    #[test]
    fn footprint_lists_only_registry_dependent_domains() {
        let c = classify(&nnf_of("exists x in S. Revoked(x) & forall y in T. NotRevoked(y)"));
        assert_eq!(c.footprint, ["S", "T"]);
        let c = classify(&nnf_of("exists x in S. Sig(x, \"A\") & forall y in T. NotRevoked(y)"));
        assert_eq!(c.footprint, ["S", "T"]);
        let c = classify(&nnf_of("(exists x in S. Sig(x, \"A\")) & forall y in T. NotRevoked(y)"));
        assert_eq!(c.footprint, ["T"]);
    }

    #[test]
    fn interference_rows() {
        let c = classify(&nnf_of("forall x in S. NotRevoked(x)"));
        let rows: Vec<(&str, bool)> = c.interference.iter().map(|r| (r.update, r.can_falsify)).collect();
        assert_eq!(rows, [("issue", false), ("revoke inside footprint", true), ("revoke outside footprint", false)]);
        let c = classify(&nnf_of("exists x in S. Revoked(x)"));
        assert!(c.interference.iter().all(|r| !r.can_falsify));
    }

    #[test]
    fn contract_modes() {
        assert_eq!(classify(&nnf_of("forall x in S. NotRevoked(x)")).contract.mode, "cas-groups");
        assert_eq!(classify(&nnf_of("forall x in Issued. NotRevoked(x)")).contract.mode, "cas-global");
        assert_eq!(classify(&nnf_of("forall x in S. NotIssued(x)")).contract.mode, "cas-global");
        assert_eq!(classify(&nnf_of("exists x in Presented. NotRevoked(x)")).contract.mode, "cas-global");
        assert_eq!(classify(&nnf_of("exists x in S. Revoked(x)")).contract.mode, "none");
    }

    #[test]
    fn lints() {
        let n = nnf_of("forall x in S. Revoked(x)");
        let (w, notes) = lint(&n, &classify(&n));
        assert!(w[0].contains("publicly decidable"));
        assert!(notes[0].contains("no more weight than a signed statement"));

        let n = nnf_of("exists x in S. Revoked(x)");
        let (w, notes) = lint(&n, &classify(&n));
        assert!(w.is_empty());
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("G1 powers of α up to |S|−1"));

        let n = nnf_of("!(exists x in Presented. Revoked(x))");
        let (w, _) = lint(&n, &classify(&n));
        assert!(w[0].contains("vacuous"));
    }
}
