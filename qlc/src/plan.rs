//! The proof plan (DESIGN.md 3.6). The plan is a tree that mirrors the
//! negation normal form. Each node names the compilation rule that applies,
//! with its construction, proof size, SRS need, assumption, and the way the
//! Fiat-Shamir challenge reaches it.
//!
//! The plan describes what a back end would have to build. This crate does
//! not produce proofs.

use crate::ast::{Atom, AtomName, DomainKind, Formula, QuantKind};
use crate::json::Json;
use crate::nnf::to_nnf;

/// The challenge text for the root of the plan.
pub const CHALLENGE_ROOT: &str = "root: c = H(statement, all commitments)";
/// The challenge text for a child of an AND node.
pub const CHALLENGE_AND: &str = "shared with siblings";
/// The challenge text for a child of an OR node.
pub const CHALLENGE_OR: &str = "share of parent challenge (CDS)";

const ASSUME_ACC: &str = "n-ISDH extended with the G2 powers of α (open problem, dashboard section 2.8)";
const ASSUME_SIGMA: &str = "soundness of the children; Fiat-Shamir in the random oracle model";
const SRS_NONE: &str = "none";

/// One node of the proof plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanNode {
    /// The node kind, for example `"atom"`, `"and"`, `"forall-aggregate"`.
    pub kind: String,
    /// The subformula this node proves, pretty printed.
    pub label: String,
    /// The rule identifier, for example `R-FORALL-NOTREVOKED`.
    pub rule_id: String,
    /// The construction in one or two sentences.
    pub rule: String,
    pub size: String,
    pub srs: String,
    pub assumption: String,
    pub challenge: String,
    pub children: Vec<PlanNode>,
}

impl PlanNode {
    /// The JSON tree node `{kind, label, children, rule_id, rule, size, srs,
    /// assumption, challenge}`.
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("kind", Json::str(&self.kind)),
            ("label", Json::str(&self.label)),
            ("children", Json::Arr(self.children.iter().map(PlanNode::to_json).collect())),
            ("rule_id", Json::str(&self.rule_id)),
            ("rule", Json::str(&self.rule)),
            ("size", Json::str(&self.size)),
            ("srs", Json::str(&self.srs)),
            ("assumption", Json::str(&self.assumption)),
            ("challenge", Json::str(&self.challenge)),
        ])
    }

    /// Returns the first node with the given rule identifier, searching the
    /// tree in pre-order. Tests use this to check the plan.
    pub fn find(&self, rule_id: &str) -> Option<&PlanNode> {
        if self.rule_id == rule_id {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find(rule_id))
    }
}

/// Builds the proof plan of a formula in negation normal form.
pub fn plan(nnf: &Formula) -> PlanNode {
    build(nnf, CHALLENGE_ROOT)
}

#[allow(clippy::too_many_arguments)]
fn node(
    kind: &str,
    f: &Formula,
    rule_id: &str,
    rule: &str,
    size: &str,
    srs: &str,
    assumption: &str,
    challenge: &str,
    children: Vec<PlanNode>,
) -> PlanNode {
    PlanNode {
        kind: kind.to_string(),
        label: f.pretty(),
        rule_id: rule_id.to_string(),
        rule: rule.to_string(),
        size: size.to_string(),
        srs: srs.to_string(),
        assumption: assumption.to_string(),
        challenge: challenge.to_string(),
        children,
    }
}

fn build(f: &Formula, challenge: &str) -> PlanNode {
    match f {
        Formula::True => node("const", f, "R-TRUE", "The constant true needs no proof.", "O(1): empty", SRS_NONE, "none", challenge, vec![]),
        Formula::False => node("const", f, "R-FALSE", "The constant false has no proof; a plan that needs this node cannot be carried out.", "none", SRS_NONE, "none", challenge, vec![]),
        Formula::Atom(atom) => build_atom(atom, f, challenge),
        Formula::Not(_) => node(
            "uncompilable",
            f,
            "R-NEG-UNSUPPORTED",
            "Negation is never proved cryptographically and this atom has no positive dual, so the leaf cannot be compiled. Rewrite the query so that the atom occurs positively.",
            "none",
            SRS_NONE,
            "none",
            challenge,
            vec![],
        ),
        Formula::And(parts) => node(
            "and",
            f,
            "R-AND",
            "Run all sub-proofs under one Fiat-Shamir challenge. A variable shared between sub-proofs uses the same random blinder, so one response must satisfy every equation and the values are forced to be equal.",
            "sum of children",
            SRS_NONE,
            ASSUME_SIGMA,
            challenge,
            parts.iter().map(|p| build(p, CHALLENGE_AND)).collect(),
        ),
        Formula::Or(parts) => node(
            "or",
            f,
            "R-OR",
            "Cramer-Damgård-Schoenmakers OR proof: simulate the false branches with self-chosen challenges and answer the true branch with the remaining share, so that the shares sum to the parent challenge. A public registry statement needs no cryptography here: publish the proof of a true side.",
            "sum of children (all branches are sent)",
            SRS_NONE,
            "special soundness and simulatability of every branch; keep the branches sigma protocols (a SNARK branch has no split challenge)",
            challenge,
            parts.iter().map(|p| build(p, CHALLENGE_OR)).collect(),
        ),
        // Desugaring removes implications, so this arm is not reached from
        // `compile`. It delegates to the desugared form to stay total.
        Formula::Implies(a, b) => build(&Formula::or(vec![Formula::not((**a).clone()), (**b).clone()]), challenge),
        Formula::Quant { kind, .. } => match kind {
            QuantKind::Forall => build_forall(f, challenge),
            QuantKind::Exists => build_exists(f, challenge),
            QuantKind::AtLeast(_) => build_atleast(f, challenge),
            QuantKind::AtMost(_) => build_atmost(f, challenge),
        },
    }
}

fn build_atom(atom: &Atom, f: &Formula, challenge: &str) -> PlanNode {
    let (rule, size, srs, assumption): (&str, &str, &str, &str) = match atom.name {
        AtomName::NotRevoked => (
            "Receipt C for the ID y against the active accumulator A, check e(C, g̃^y·Q̃) = e(A, g̃). With y hidden, blind the receipt and run the Schnorr-style proof of credx (vb20/proof.rs), reusing the response for y in the signature proof. The proof must use the current A.",
            "O(1): one G1 element, or a constant-size sigma proof when y is hidden",
            SRS_NONE,
            ASSUME_ACC,
        ),
        AtomName::Revoked => (
            "Receipt C̃ for y against the revoked-set accumulator R̃ with the groups swapped, check e(g^y·Q, C̃) = e(g, R̃). The receipt is the value of R̃ before the revocation of y, so anyone can derive and refresh it. Any authenticated historical R̃ may be used.",
            "O(1): one G2 element, or a constant-size sigma proof when y is hidden",
            SRS_NONE,
            ASSUME_ACC,
        ),
        AtomName::Issued => (
            "Membership of y in the issued-set accumulator I = [P_Iss]₁ with a receipt against I. There is no separate rule card; the construction follows the Revoked atom with I in place of R̃. Inside a quantifier over a group or over Presented the atom holds by construction.",
            "O(1): one group element",
            SRS_NONE,
            ASSUME_ACC,
        ),
        AtomName::NotIssued => (
            "Not compilable: this is a non-membership statement and the design issues no non-membership witnesses (dashboard section 2.4). It is decided from public registry data only.",
            "none",
            SRS_NONE,
            "none",
        ),
        AtomName::Sig => (
            "credx Signature statement: the holder proves knowledge of a valid BBS or PS signature of the named issuer over the claims. Every other credential atom on the same variable links to this statement.",
            "O(number of hidden claims)",
            SRS_NONE,
            "unforgeability of BBS or PS signatures",
        ),
        AtomName::Eq => (
            "credx Equality statement: the hidden claims share one Schnorr blinder, so a single response must fit both signature proofs. A revealed claim is rejected in an equality.",
            "O(1): no extra elements, the response is shared",
            SRS_NONE,
            "special soundness of the linked sigma protocols",
        ),
        AtomName::Neq => (
            "Inequality of two hidden claims: commit to both, then prove that the difference of the committed values is non-zero (proof of knowledge of its inverse). credx has no such statement; Dock's crypto library has an inequality protocol.",
            "O(1): two commitments and a sigma proof",
            SRS_NONE,
            "discrete logarithm (Pedersen binding)",
        ),
        AtomName::In => (
            "credx Membership statement: zero-knowledge membership of the hidden claim in the accumulator of the named group, sharing the response for the claim with the signature proof.",
            "O(1): constant-size sigma proof",
            "prover G1 powers up to |S|−1, or an issuer-published receipt",
            ASSUME_ACC,
        ),
        AtomName::NotIn => (
            "Not compilable in this design: a non-membership statement needs non-membership witnesses, which the design excludes to avoid the Biryukov-Udovenko-Vitto forgery attack (dashboard section 2.4). If the group is public and small, use a conjunction of Neq atoms.",
            "none",
            SRS_NONE,
            "none",
        ),
        AtomName::Commit => (
            "credx Commitment statement: K = g^m·h^ρ is a Pedersen commitment to the hidden signed claim, linked to the signature proof by a shared response. Other proof systems attach to K (commit-and-prove).",
            "O(1): one G1 element and two responses",
            SRS_NONE,
            "discrete logarithm (Pedersen binding)",
        ),
        AtomName::Range => (
            "credx Range statement: a Bulletproofs range proof over BLS12-381 on a linked Pedersen commitment to the claim. The compiler adds the Commit statement if the query has none.",
            "O(log n) group elements for an n-bit range",
            SRS_NONE,
            "discrete logarithm",
        ),
        AtomName::Enc => (
            "credx VerifiableEncryption statement: the ciphertext encrypts the hidden claim under the named key. The decryptor must search a known candidate set.",
            "O(1): one ciphertext and a sigma proof",
            SRS_NONE,
            "not fixed by the design; take it from the credx verifiable-encryption code",
        ),
        AtomName::EncDec => (
            "credx VerifiableEncryptionDecryption statement: as Enc, but the decryptor recovers the full scalar. The proof is larger than for Enc.",
            "larger than Enc (no figure is given in the sources)",
            SRS_NONE,
            "not fixed by the design; take it from the credx verifiable-encryption code",
        ),
        AtomName::Hash => (
            "The hidden signed claim is the hash of the given preimage. The algebraic variant (Poseidon or Pedersen hash) is cheap inside a proof; the SHA-256 variant needs a commit-and-prove SNARK such as LegoGroth16 attached to a Commit statement. Use it only under AND, not inside a hidden OR.",
            "O(1) with a SNARK, plus one commitment",
            "circuit-specific SNARK setup for the SHA-256 variant",
            "knowledge soundness of the SNARK; discrete logarithm for the commitment",
        ),
        AtomName::Prefix => (
            "Derived predicate. Under a fixed-radix numeric encoding a prefix test is a Range atom (GS1 company prefix); otherwise it is a circuit over the Hash preimage.",
            "as Range, or as Hash with a circuit",
            "none with the Range encoding; SNARK setup with the circuit",
            "as Range or Hash",
        ),
        // Desugaring removes these two; the arms keep the match total.
        AtomName::Active => ("Sugar for Issued(x) ∧ NotRevoked(x); desugar before planning.", "see NotRevoked", SRS_NONE, ASSUME_ACC),
        AtomName::SameHolder => ("Sugar for Eq on the link_secret claim; desugar before planning.", "see Eq", SRS_NONE, "see Eq"),
    };
    let text = atom.name.text().to_uppercase();
    let rule_id = if atom.name.is_registry() { format!("R-ATOM-{}", text) } else { format!("R-CRED-{}", text) };
    node("atom", f, &rule_id, rule, size, srs, assumption, challenge, vec![])
}

/// Rebuilds a quantifier with the same head and a new body or domain.
fn requantify(f: &Formula, new_domain: Option<String>, new_body: Formula) -> Formula {
    match f {
        Formula::Quant { kind, var, domain, pos, .. } => Formula::Quant {
            kind: *kind,
            var: var.clone(),
            domain: new_domain.unwrap_or_else(|| domain.clone()),
            body: Box::new(new_body),
            pos: *pos,
        },
        other => other.clone(),
    }
}

fn single_registry_atom(body: &Formula) -> Option<AtomName> {
    match body {
        Formula::Atom(a) if a.name.is_registry() => Some(a.name),
        _ => None,
    }
}

fn has_registry_atom(f: &Formula) -> bool {
    match f {
        Formula::Atom(a) => a.name.is_registry(),
        Formula::And(parts) | Formula::Or(parts) => parts.iter().any(has_registry_atom),
        Formula::Not(inner) => has_registry_atom(inner),
        Formula::Quant { body, .. } => has_registry_atom(body),
        _ => false,
    }
}

fn build_forall(f: &Formula, challenge: &str) -> PlanNode {
    let Formula::Quant { domain, body, .. } = f else { return build(f, challenge) };
    let domain_kind = DomainKind::of(domain);

    // ∀x∈S.(φ ∧ ψ) splits into (∀φ) ∧ (∀ψ).
    if let Formula::And(parts) = &**body {
        let children = parts.iter().map(|p| build_forall(&requantify(f, None, p.clone()), CHALLENGE_AND)).collect();
        return node(
            "and",
            f,
            "R-AND",
            "Split ∀x∈S.(φ ∧ ψ) into (∀x∈S.φ) ∧ (∀x∈S.ψ), then run the parts under one Fiat-Shamir challenge.",
            "sum of children",
            SRS_NONE,
            ASSUME_SIGMA,
            challenge,
            children,
        );
    }

    match (domain_kind, single_registry_atom(body)) {
        (DomainKind::Issued, Some(AtomName::Revoked)) => {
            return node("registry-check", f, "R-REGISTRY-ALL-REVOKED", "Whole-registry statement, no proof needed: compare published values with e(I, g̃) = e(g, R̃). The check binds values at α; it is sound for an honest issuer and not binding against one who knows α.", "O(1): nothing is sent", SRS_NONE, "honest issuer", challenge, vec![]);
        }
        (DomainKind::Issued, Some(AtomName::NotRevoked)) => {
            return node("registry-check", f, "R-REGISTRY-NONE-REVOKED", "Whole-registry statement, no proof needed: compare published values with A = V_0 (equivalently R̃ = g̃).", "O(1): nothing is sent", SRS_NONE, "honest issuer", challenge, vec![]);
        }
        (DomainKind::Group, Some(AtomName::NotRevoked)) => {
            return node(
                "forall-aggregate",
                f,
                "R-FORALL-NOTREVOKED",
                "Aggregate receipt W = A^{1/P_S(α)}, check e(W, [P_S]₂) = e(A, g̃). The issuer computes W with one exponentiation; a prover without α combines the receipts C_i by partial fractions, W = ∏ C_i^{λ_i} with λ_i = ∏_{j≠i} 1/(y_j − y_i). Inside a hidden OR, blind it as W^ρ and prove knowledge of ρ in GT.",
                "O(1): one G1 element",
                "verifier G2 powers up to |S|",
                ASSUME_ACC,
                challenge,
                vec![],
            );
        }
        (DomainKind::Group, Some(AtomName::Revoked)) => {
            return node(
                "forall-aggregate",
                f,
                "R-FORALL-REVOKED",
                "The same aggregate check against R̃. The revoked list is public, so the statement is publicly decidable and a batch receipt against R̃ is vacuous as a proof: anyone can build one for any subset of the revoked set. Use it only when the verifier stores accumulator values alone.",
                "O(1): one G2 element",
                "verifier G1 powers up to |S| (the groups are swapped)",
                ASSUME_ACC,
                challenge,
                vec![],
            );
        }
        _ => {}
    }

    // ∀x∈S.(x∈X₁ ∨ x∈X₂) does not split. The prover partitions S.
    if let Formula::Or(parts) = &**body {
        if has_registry_atom(body) {
            let children = parts
                .iter()
                .enumerate()
                .map(|(i, p)| build_forall(&requantify(f, Some(format!("{}_{}", domain, i + 1)), p.clone()), CHALLENGE_AND))
                .collect();
            return node(
                "forall-partition",
                f,
                "R-FORALL-MIXED",
                "The prover partitions S into disjoint parts, one per disjunct, and gives one subset proof per part. To hide the partition, commit to [P_{S₁}] and [P_{S₂}], prove e([P_{S₁}]₁, [P_{S₂}]₂) = e([P_S]₁, g̃), and give the subset proofs against the committed sets (Srinivasan et al., CCS 2022).",
                "sum of children, plus two commitments and one pairing equation when the partition is hidden",
                "verifier G2 powers up to |S|; a hidden partition needs the structured SRS of the committed-subset proof",
                "n-ISDH extended with G2 powers; a knowledge-type assumption when the partition is hidden",
                challenge,
                children,
            );
        }
    }

    let (rule, size) = if domain_kind == DomainKind::Presented {
        (
            "One sub-proof of the body per presented credential, all under one Fiat-Shamir challenge. The statement covers only what the holder chose to present.",
            "O(k) times the body, for k presented credentials",
        )
    } else {
        (
            "No aggregate rule covers this body, so the plan is one sub-proof of the body per member of the domain, all under one Fiat-Shamir challenge. The prover must hold a credential for every member.",
            "O(|S|) times the body",
        )
    };
    node("forall-each", f, "R-FORALL-EACH", rule, size, SRS_NONE, ASSUME_SIGMA, challenge, vec![build(body, CHALLENGE_AND)])
}

fn build_exists(f: &Formula, challenge: &str) -> PlanNode {
    let Formula::Quant { domain, body, .. } = f else { return build(f, challenge) };

    // ∃x∈S.(φ ∨ ψ) splits into (∃φ) ∨ (∃ψ).
    if let Formula::Or(parts) = &**body {
        let children = parts.iter().map(|p| build_exists(&requantify(f, None, p.clone()), CHALLENGE_OR)).collect();
        return node(
            "or",
            f,
            "R-OR",
            "Split ∃x∈S.(φ ∨ ψ) into (∃x∈S.φ) ∨ (∃x∈S.ψ), then combine the parts with a Cramer-Damgård-Schoenmakers OR proof.",
            "sum of children (all branches are sent)",
            SRS_NONE,
            "special soundness and simulatability of every branch",
            challenge,
            children,
        );
    }

    let (rule, size, srs, assumption) = match DomainKind::of(domain) {
        DomainKind::Group => (
            "One hidden y across all atoms of the body: a zero-knowledge membership proof of y in acc_S = [P_S]₁ (credx Membership statement), joined with the body's proofs by a shared response for y. The prover needs the receipt D = g^{P_S(α)/(y+α)}. For a small S an |S|-branch OR proof avoids the SRS.",
            "O(1) regardless of |S|, plus the body",
            "prover G1 powers up to |S|−1, or an issuer-published receipt inside acc_S",
            ASSUME_ACC,
        ),
        DomainKind::Presented => (
            "The holder picks one presented credential as the witness and proves the body for it. One hidden y is shared across all atoms of the body.",
            "the body",
            SRS_NONE,
            ASSUME_SIGMA,
        ),
        DomainKind::Issued => (
            "One hidden y across all atoms of the body, with membership of y in the issued-set accumulator I. A body that contains Revoked or NotRevoked already implies that y was issued, so the membership in I can be dropped.",
            "O(1), plus the body",
            SRS_NONE,
            ASSUME_ACC,
        ),
    };
    node("exists", f, "R-EXISTS", rule, size, srs, assumption, challenge, vec![build(body, CHALLENGE_AND)])
}

fn build_atleast(f: &Formula, challenge: &str) -> PlanNode {
    let Formula::Quant { domain, body, .. } = f else { return build(f, challenge) };
    let (rule, size, srs, assumption) = if DomainKind::of(domain) == DomainKind::Presented {
        (
            "The holder presents k credentials and proves the body for each under one challenge. Omitting credentials does not help the holder, so the statement is meaningful over Presented. Binding all k to one holder needs Eq on the link secret; distinctness of hidden IDs needs a further argument (dashboard section 2.6, distinctness).",
            "O(k) times the body",
            SRS_NONE,
            ASSUME_SIGMA,
        )
    } else {
        (
            "Two mechanisms. Threshold composition (CDS94 with challenges on a polynomial of degree m−n) works over distinct public statements with no SRS. The committed-subset proof (Srinivasan et al., CCS 2022, section 7) has constant size, needs a structured SRS with a second secret from the issuer, and shows k distinct IDs across whoever cooperated.",
            "O(|S|) or O(1) with committed subset",
            "none for threshold composition; structured SRS with a second secret for the committed subset",
            "standard assumptions for threshold composition; generic-group or algebraic-group argument for the committed subset",
        )
    };
    node("atleast", f, "R-ATLEAST", rule, size, srs, assumption, challenge, vec![build(body, CHALLENGE_AND)])
}

fn build_atmost(f: &Formula, challenge: &str) -> PlanNode {
    let Formula::Quant { kind, domain, body, .. } = f else { return build(f, challenge) };
    // "At most k satisfy φ" over a complete set S is "at least |S|−k satisfy
    // ¬φ". The child is therefore the plan of the dual body.
    let mut dual_warnings = Vec::new();
    let dual = to_nnf(&Formula::not((**body).clone()), &mut Vec::new(), &mut dual_warnings);
    let vacuous = if DomainKind::of(domain) == DomainKind::Presented {
        " Over Presented the statement is vacuous, because the holder can omit credentials."
    } else {
        ""
    };
    let child = if *kind == QuantKind::AtMost(0) {
        // "At most 0 satisfy φ" is exactly ∀x∈S.¬φ.
        let forall = match requantify(f, None, dual) {
            Formula::Quant { var, domain, body, pos, .. } => Formula::Quant { kind: QuantKind::Forall, var, domain, body, pos },
            other => other,
        };
        build_forall(&forall, CHALLENGE_AND)
    } else {
        build(&dual, CHALLENGE_AND)
    };
    let rule = format!(
        "An upper bound has no construction of its own. Over a complete, authenticated set S, at most k members satisfy φ exactly when at least |S|−k members satisfy the dual body ¬φ in negation normal form, so the plan is the at-least construction on the dual body; at most 0 is the ∀ rule.{}{}",
        vacuous,
        if dual_warnings.is_empty() { "" } else { " The dual body contains an atom without a positive dual, so this node cannot be compiled." }
    );
    node(
        "atmost",
        f,
        "R-ATMOST",
        &rule,
        "as the child for at most 0; otherwise O(|S|) or O(1) with committed subset",
        "as the child",
        "as the child; completeness of S must be authenticated",
        challenge,
        vec![child],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desugar::desugar;
    use crate::parser::parse;

    fn plan_of(src: &str) -> PlanNode {
        let (mut s, mut w, mut n) = (Vec::new(), Vec::new(), Vec::new());
        let d = desugar(&parse(src).expect("parses"), &mut s, &mut n);
        plan(&to_nnf(&d, &mut s, &mut w))
    }

    #[test]
    fn aggregate_rules() {
        let p = plan_of("forall x in S. NotRevoked(x)");
        assert_eq!(p.rule_id, "R-FORALL-NOTREVOKED");
        assert_eq!(p.srs, "verifier G2 powers up to |S|");
        assert!(p.rule.contains("1/(y_j − y_i)"));
        assert_eq!(plan_of("forall x in S. Revoked(x)").rule_id, "R-FORALL-REVOKED");
    }

    #[test]
    fn forall_and_splits() {
        let p = plan_of("forall x in S. NotRevoked(x) & Sig(x, \"A\")");
        assert_eq!(p.rule_id, "R-AND");
        assert_eq!(p.children[0].rule_id, "R-FORALL-NOTREVOKED");
        assert_eq!(p.children[1].rule_id, "R-FORALL-EACH");
        assert_eq!(p.children[1].children[0].rule_id, "R-CRED-SIG");
        assert_eq!(p.children[0].challenge, CHALLENGE_AND);
    }

    #[test]
    fn exists_or_splits_and_exists_and_shares_the_witness() {
        let p = plan_of("exists x in S. Revoked(x) | NotRevoked(x)");
        assert_eq!(p.rule_id, "R-OR");
        assert_eq!(p.children[0].rule_id, "R-EXISTS");
        assert_eq!(p.children[0].challenge, CHALLENGE_OR);

        let p = plan_of("exists x in S. Revoked(x) & Sig(x, \"A\")");
        assert_eq!(p.rule_id, "R-EXISTS");
        assert!(p.srs.contains("|S|−1"));
        assert_eq!(p.children[0].rule_id, "R-AND");
        assert_eq!(p.children[0].children[0].rule_id, "R-ATOM-REVOKED");
    }

    #[test]
    fn forall_or_uses_the_partition() {
        let p = plan_of("forall x in S. Revoked(x) | NotRevoked(x)");
        assert_eq!(p.rule_id, "R-FORALL-MIXED");
        assert_eq!(p.children[0].label, "∀x∈S_1. Revoked(x)");
        assert_eq!(p.children[1].rule_id, "R-FORALL-NOTREVOKED");
    }

    #[test]
    fn counting_rules() {
        let p = plan_of("atleast 2 x in S. NotRevoked(x)");
        assert_eq!(p.rule_id, "R-ATLEAST");
        assert_eq!(p.size, "O(|S|) or O(1) with committed subset");

        let p = plan_of("atmost 0 x in S. Revoked(x)");
        assert_eq!(p.rule_id, "R-ATMOST");
        assert_eq!(p.children[0].rule_id, "R-FORALL-NOTREVOKED");
    }

    #[test]
    fn whole_registry_checks_and_uncompilable_leaves() {
        assert_eq!(plan_of("forall x in Issued. Revoked(x)").rule_id, "R-REGISTRY-ALL-REVOKED");
        assert!(plan_of("exists x in S. !Sig(x, \"A\")").find("R-NEG-UNSUPPORTED").is_some());
    }
}
