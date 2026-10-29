//! End-to-end tests of [`crate::compile`]. The numbers in the test names
//! follow the list of required queries in the task description.

use crate::classify::Class;
use crate::json::{validate, Json};
use crate::{compile, Compiled};

const Q1: &str = "forall x in S. NotRevoked(x)";
const Q2: &str = "exists x in S. Revoked(x)";
const Q3: &str = "!(forall x in S. NotRevoked(x))";
const Q4: &str = "forall x in Issued. Revoked(x)";
const Q5: &str = "exists x in S. Revoked(x) & forall y in T. NotRevoked(y)";
const Q5_PARENS: &str = "(exists x in S. Revoked(x)) & (forall y in T. NotRevoked(y))";
const Q6: &str = "atleast 2 x in Presented. (Sig(x, \"CertBody\") & Active(x) & Range(x.expiry, 20260918, 99991231))";
const Q7: &str = "forall x in Presented. NotRevoked(x)";
const Q8: &str = "exists x in Presented. exists y in Presented. (SameHolder(x, y) & Neq(x.id, y.id))";
const Q9: &str = "exists x in Presented. !Range(x.age, 18, 120)";
const Q10: &str = "exists x in Presented. !Sig(x, \"A\")";
const Q13: &str = "atmost 0 x in S. Revoked(x)";
const Q13_NEG: &str = "!(atleast 1 x in S. Revoked(x))";

const ALL_VALID: &[&str] = &[Q1, Q2, Q3, Q4, Q5, Q5_PARENS, Q6, Q7, Q8, Q9, Q10, Q13, Q13_NEG];
const ALL_INVALID: &[&str] = &[
    "forall x in S. (NotRevoked(x)",
    "forall x in S. Revokd(x)",
    "forall x in S. Revoked(y)",
    "forall x in S. Sig(x)",
    "",
    "forall x in S. Sig(x, \"unterminated",
];

fn ok(src: &str) -> Compiled {
    match compile(src).result {
        Ok(c) => c,
        Err(e) => panic!("query {:?} failed: {}", src, e),
    }
}

#[test]
fn q01_flat_reservation_guard_is_antitone() {
    let c = ok(Q1);
    assert_eq!(c.classification.class, Class::Antitone);
    assert_eq!(c.classification.contract.mode, "cas-groups");
    assert!(c.classification.contract.detail.contains("per-group version counters of S"));
    assert_eq!(c.classification.footprint, ["S"]);
}

#[test]
fn q02_exists_revoked_is_monotone() {
    let c = ok(Q2);
    assert_eq!(c.classification.class, Class::Monotone);
    assert_eq!(c.classification.contract.mode, "none");
    assert!(c.classification.contract.detail.starts_with("none: proof may bind to any authenticated historical registry value"));
}

#[test]
fn q03_negated_guard_normalises_to_exists_revoked() {
    let c = ok(Q3);
    assert_eq!(c.nnf.pretty(), "∃x∈S. Revoked(x)");
    assert_eq!(c.classification.class, Class::Monotone);
    assert_eq!(c.rewrite_steps.len(), 2);
}

#[test]
fn q04_forall_over_issued_is_non_monotone() {
    let c = ok(Q4);
    assert_eq!(c.classification.class, Class::NonMonotone);
    let polarities: Vec<(&str, &str)> =
        c.classification.occurrences.iter().map(|o| (o.atom.as_str(), o.polarity.text())).collect();
    assert_eq!(polarities, [("∀x∈Issued", "down"), ("Revoked(x)", "up")]);
    assert_eq!(c.classification.footprint, ["Issued"]);
    assert_eq!(c.classification.contract.mode, "cas-global");
}

#[test]
fn q05_mixed_guard_and_precedence() {
    // Without parentheses the body of ∃ extends to the right and contains ∀.
    let c = ok(Q5);
    assert_eq!(c.nnf.pretty(), "∃x∈S. Revoked(x) ∧ (∀y∈T. NotRevoked(y))");
    assert_eq!(c.classification.class, Class::NonMonotone);
    assert_eq!(c.classification.footprint, ["S", "T"]);

    let c = ok(Q5_PARENS);
    assert_eq!(c.nnf.pretty(), "(∃x∈S. Revoked(x)) ∧ (∀y∈T. NotRevoked(y))");
    assert_eq!(c.classification.class, Class::NonMonotone);
    assert_eq!(c.classification.footprint, ["S", "T"]);
    assert_eq!(c.classification.contract.mode, "cas-global");
}

#[test]
fn q06_atleast_over_presented() {
    let c = ok(Q6);
    assert_eq!(c.classification.class, Class::Antitone);
    assert_eq!(
        c.nnf.pretty(),
        "∃≥2 x∈Presented. Sig(x, \"CertBody\") ∧ NotRevoked(x) ∧ Range(x.expiry, 20260918, 99991231)"
    );
    assert!(c.notes.iter().any(|n| n.contains("Active(x) was simplified to NotRevoked(x)")));
    assert!(!c.warnings.iter().any(|w| w.contains("vacuous")), "{:?}", c.warnings);
    assert_eq!(c.plan.rule_id, "R-ATLEAST");
}

#[test]
fn q07_forall_over_presented_is_vacuous() {
    let c = ok(Q7);
    assert!(c.warnings.iter().any(|w| w.contains("vacuous unless the issuer certifies completeness")));
}

#[test]
fn q08_same_holder_is_state_independent() {
    let c = ok(Q8);
    assert_eq!(c.classification.class, Class::StateIndependent);
    assert!(c.classification.footprint.is_empty());
    assert_eq!(c.classification.contract.mode, "none");
    assert!(c.nnf.pretty().contains("Eq(x.link_secret, y.link_secret)"));
}

#[test]
fn q09_negated_range_becomes_two_ranges() {
    let c = ok(Q9);
    assert_eq!(c.nnf.pretty(), "∃x∈Presented. Range(x.age, 0, 17) ∨ Range(x.age, 121, MAX)");
    assert!(c.rewrite_steps.iter().any(|s| s.rule == "range-complement"));
}

#[test]
fn q10_negated_signature_has_no_dual() {
    let c = ok(Q10);
    assert!(c.warnings.iter().any(|w| w == "negation of Sig(x, \"A\") has no positive dual; it cannot be compiled"));
    assert_eq!(c.nnf.pretty(), "∃x∈Presented. ¬Sig(x, \"A\")");
}

#[test]
fn q11_errors_carry_message_and_position() {
    let cases: [(&str, &str, (u32, u32)); 4] = [
        (ALL_INVALID[0], "unbalanced parenthesis", (1, 30)),
        (ALL_INVALID[1], "unknown atom 'Revokd'", (1, 16)),
        (ALL_INVALID[2], "free variable 'y'", (1, 24)),
        (ALL_INVALID[3], "Sig expects 2 arguments", (1, 16)),
    ];
    for (src, needle, (line, col)) in cases {
        let out = compile(src);
        let e = out.result.as_ref().expect_err("must fail");
        assert!(e.message.contains(needle), "{}: {}", src, e.message);
        assert_eq!((e.line, e.col), (line, col), "{}", src);
        assert!(e.excerpt.starts_with(src) && e.excerpt.ends_with('^'));

        let v = validate::parse(&out.to_json()).expect("valid JSON");
        assert_eq!(v.get("ok"), Some(&Json::Bool(false)));
        let err = v.get("error").expect("error object");
        assert_eq!(err.get("line"), Some(&Json::Num(line as u64)));
        assert_eq!(err.get("col"), Some(&Json::Num(col as u64)));
        assert_eq!(v.get("plan"), Some(&Json::Null));
    }
}

const KEYS: &[&str] = &[
    "ok", "error", "source_pretty", "ast", "desugared_pretty", "nnf_pretty", "nnf", "rewrite_steps", "class",
    "class_gloss", "explanation", "polarity", "footprint", "interference", "contract", "warnings", "notes", "plan",
];

fn check_tree(node: &Json) {
    assert!(node.get("kind").and_then(Json::as_str).is_some());
    assert!(node.get("label").and_then(Json::as_str).is_some());
    match node.get("children") {
        Some(Json::Arr(children)) => children.iter().for_each(check_tree),
        other => panic!("children must be an array, got {:?}", other),
    }
}

#[test]
fn q12_json_is_valid_and_has_the_documented_shape() {
    for src in ALL_VALID.iter().chain(ALL_INVALID) {
        let out = compile(src);
        let v = validate::parse(&out.to_json()).unwrap_or_else(|e| panic!("invalid JSON for {:?}: {}", src, e));
        let Json::Obj(fields) = &v else { panic!("top level must be an object") };
        let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, KEYS, "{}", src);
        // The writer and the validator agree on the whole document.
        assert_eq!(v, out.to_json_value());
        if out.ok() {
            for tree in ["ast", "nnf", "plan"] {
                check_tree(v.get(tree).expect("tree"));
            }
            assert!(v.get("explanation").and_then(Json::as_str).is_some_and(|e| e.contains("syntactic sufficient condition")));
        }
    }
}

#[test]
fn q12_strings_with_quotes_and_unicode_round_trip() {
    let src = "exists x in Presented. Sig(x, \"Tanúsító \\\"Kft\\\" \\\\ ∀ 𝔸\")";
    let out = compile(src);
    let v = validate::parse(&out.to_json()).expect("valid JSON");
    let label = v.get("nnf").and_then(|n| n.get("children")).expect("children");
    let Json::Arr(children) = label else { panic!("array") };
    let args = children[0].get("args").expect("args");
    assert_eq!(args, &Json::Arr(vec![Json::str("x"), Json::str("\"Tanúsító \\\"Kft\\\" \\\\ ∀ 𝔸\"")]));
}

#[test]
fn q13_atmost_zero_is_the_guard_again() {
    let c = ok(Q13);
    assert_eq!(c.classification.class, Class::Antitone);
    assert_eq!(c.classification.contract.mode, "cas-groups");
    // Its plan is the plan of query 1.
    assert_eq!(c.plan.children[0], {
        let mut guard = ok(Q1).plan;
        guard.challenge = crate::plan::CHALLENGE_AND.to_string();
        guard
    });

    let n = ok(Q13_NEG);
    assert_eq!(n.nnf.pretty(), c.nnf.pretty());
    assert_eq!(n.nnf.pretty(), "∃≤0 x∈S. Revoked(x)");
    assert_eq!(n.classification.class, Class::Antitone);
}

#[test]
fn wasm_abi_round_trip_on_the_host() {
    let src = Q1.as_bytes();
    unsafe {
        let input = crate::qlc_alloc(src.len());
        std::ptr::copy_nonoverlapping(src.as_ptr(), input, src.len());
        let result = crate::qlc_compile(input, src.len());
        let mut len = [0u8; 4];
        std::ptr::copy_nonoverlapping(result, len.as_mut_ptr(), 4);
        let len = u32::from_le_bytes(len) as usize;
        let json = std::str::from_utf8(std::slice::from_raw_parts(result.add(4), len)).expect("UTF-8").to_string();
        crate::qlc_result_free(result);
        crate::qlc_free(input, src.len());
        assert_eq!(json, compile(Q1).to_json());

        let bad = [0xFFu8, 0xFE];
        let result = crate::qlc_compile(bad.as_ptr(), bad.len());
        let mut len = [0u8; 4];
        std::ptr::copy_nonoverlapping(result, len.as_mut_ptr(), 4);
        let len = u32::from_le_bytes(len) as usize;
        let json = std::str::from_utf8(std::slice::from_raw_parts(result.add(4), len)).expect("UTF-8").to_string();
        crate::qlc_result_free(result);
        assert!(json.contains("not valid UTF-8"));
    }
}

#[test]
fn compile_never_panics_on_garbage() {
    for src in ["(((", ")))", "forall", "forall x in", "∀∀∀", "Sig(", "Sig(x,", "\"", "!", "a.b.c", "atleast 99999999999999999999 x in S. true", "x -> ", "#only a comment"] {
        let out = compile(src);
        assert!(!out.ok(), "{}", src);
        assert!(validate::parse(&out.to_json()).is_ok());
    }
}
