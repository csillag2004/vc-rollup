# qlc

`qlc` is the front end of the credential query language compiler from the design
record behind the query-language dashboard (`DESIGN.md`, sections 3 and 4; the
code cites its section numbers, and the record is not in this repository). It
parses a query, rewrites it to negation normal form, classifies it as monotone,
antitone, non-monotone or state-independent, derives the contract requirement
for a guarded registry update, and builds a proof plan. It does not produce
proofs.

The crate has no dependencies. It builds as a Rust library and as a
WebAssembly module (about 115 KB) that the offline dashboard loads without
wasm-bindgen.

## Build and test

```sh
cargo test
cargo build --release --target wasm32-unknown-unknown
node tests/wasm_smoke.mjs          # needs the wasm build
cargo run --example qlc -- 'forall x in S. NotRevoked(x)'
```

The wasm file is `target/wasm32-unknown-unknown/release/qlc.wasm`.

## Syntax

Every operator has an ASCII and a Unicode spelling.

```
formula  := quant | impl
quant    := ('forall' | '∀') VAR ('in' | '∈') DOMAIN '.' formula
          | ('exists' | '∃') VAR ('in' | '∈') DOMAIN '.' formula
          | 'atleast' NAT VAR ('in' | '∈') DOMAIN '.' formula
          | 'atmost'  NAT VAR ('in' | '∈') DOMAIN '.' formula
impl     := or ( ('->' | '→') impl )?            right associative
or       := and ( ('|' | '||' | '∨' | 'or') and )*
and      := unary ( ('&' | '&&' | '∧' | 'and') unary )*
unary    := ('!' | '¬' | 'not') unary | quant | atom | '(' formula ')' | 'true' | 'false'
atom     := NAME '(' args? ')'
arg      := VAR ('.' NAME)? | NAT | STRING | NAME
```

A quantifier body extends as far right as possible, so
`exists x in S. Revoked(x) & forall y in T. NotRevoked(y)` puts the `forall`
inside the body of the `exists`. Use parentheses to end a body early. Comments
run from `#` to the end of the line. Strings use double quotes and the escapes
`\"`, `\\`, `\n` and `\t`.

A domain is the name of an anchored group (`S`, `Shipment`, `Pool`) or one of
two reserved names. `Issued` is the registry's issued set, which grows.
`Presented` is the set of credentials the holder chooses to present.

Every variable must be bound by a quantifier. Binding a name that is already
bound is an error.

| Atom | Kind | Negation in normal form |
|---|---|---|
| `Revoked(x)`, `NotRevoked(x)` | registry | each is the dual of the other |
| `Issued(x)`, `NotIssued(x)` | registry | each is the dual of the other |
| `Active(x)` | registry, sugar | `Issued(x) & NotRevoked(x)`; only `NotRevoked(x)` when `x` ranges over a group or `Presented` |
| `Sig(x, "issuer")` | credential | none, warning |
| `Eq(x.a, y.b)`, `Neq(x.a, y.b)` | credential | each is the dual of the other |
| `SameHolder(x, y)` | credential, sugar | `Eq(x.link_secret, y.link_secret)` |
| `In(x.a, G)`, `NotIn(x.a, G)` | credential | each is the dual of the other |
| `Commit(x.a)` | credential | none, warning |
| `Range(x.a, lo, hi)` | credential | `Range(x.a, 0, lo-1) \| Range(x.a, hi+1, MAX)` |
| `Enc(x.a, pk)`, `EncDec(x.a, pk)` | credential | none, warning |
| `Hash(x.a, "preimage")` | credential | none, warning |
| `Prefix(x.a, "str")` | credential, derived | none, warning |

The pretty printer writes `atleast k` as `∃≥k` and `atmost k` as `∃≤k`.

## Pipeline

| Stage | Module | Result |
|---|---|---|
| lex and parse, check atoms and scopes | `lexer.rs`, `parser.rs` | `ast::Formula` |
| remove `->`, `Active`, `SameHolder` | `desugar.rs` | formula, rewrite steps, notes |
| negation normal form | `nnf.rs` | formula, rewrite steps, warnings |
| polarity, class, footprint, interference, contract, lints | `classify.rs` | `Classification`, warnings, notes |
| proof plan | `plan.rs` | `PlanNode` tree |
| serialise | `json.rs`, `lib.rs` | JSON text |

## Classification is a syntactic sufficient condition

DESIGN.md 3.5 defines the classes semantically, over registry states ordered
by inclusion of the issued and revoked sets. A formula is monotone when it
stays true as the state grows, and antitone when it stays false as the state
grows. Deciding that for an arbitrary formula means reasoning about all
states. `classify.rs` decides a sufficient condition from the syntax of the
negation normal form:

- `Revoked` and `Issued` are up-atoms. `NotRevoked` and `NotIssued` are
  down-atoms. Credential atoms are neutral.
- `forall x in Issued. φ` counts as a down occurrence, because it stands for
  `∀x. NotIssued(x) ∨ φ`. `exists` and `atleast` over `Issued` count as up.
- `atleast` keeps the polarity of its body. `atmost` flips everything below
  it, including an `Issued` domain of its own.
- `∧`, `∨` and quantifiers over fixed domains preserve direction.

Only up occurrences give `monotone`, only down occurrences give `antitone`,
none give `state-independent`, and a mix gives `non-monotone`. The first three
verdicts are sound: a structural induction over the normal form shows that a
formula with only up occurrences is semantically monotone, and dually. The
verdict `non-monotone` is conservative. `forall x in S. Revoked(x) |
NotRevoked(x)` is a tautology over an issued group and therefore semantically
monotone, yet the syntax mixes both directions. The cost of the conservative
verdict is an atomic test that was not strictly needed; it is never an unsound
proof against a stale registry value. The `explanation` field of the output
says this for every query.

The footprint lists the domains of the quantifiers that have a
registry-dependent part below them. `Presented` can appear in it. An antitone
formula whose footprint has only named groups, and that no issuance can
falsify, gets `cas-groups`. `Issued` or `Presented` in the footprint gives
`cas-global`, because no per-group counter covers those credentials.

## JSON output

`Output::to_json` and `qlc_compile` return one object. The keys and their
order are fixed. On an error, `ok` is `false`, `error` is set, strings are
empty, lists are empty, and the three trees are `null`.

```
{
  "ok": bool,
  "error": { "message": str, "line": int, "col": int, "excerpt": str } | null,
  "source_pretty": str,
  "ast": tree,
  "desugared_pretty": str,
  "nnf_pretty": str,
  "nnf": tree,
  "rewrite_steps": [ { "rule": str, "before": str, "after": str } ],
  "class": "monotone" | "antitone" | "non-monotone" | "state-independent",
  "class_gloss": str,
  "explanation": str,
  "polarity": [ { "atom": str, "polarity": "up" | "down", "via": str, "line": int, "col": int } ],
  "footprint": [ str ],
  "interference": [ { "update": str, "can_falsify": bool, "why": str } ],
  "contract": { "mode": "none" | "cas-groups" | "cas-global", "detail": str },
  "warnings": [ str ],
  "notes": [ str ],
  "plan": tree
}
```

Every tree node has `kind`, `label` (the pretty subformula) and `children`.

- Formula trees (`ast`, `nnf`) use the kinds `true`, `false`, `atom`, `not`,
  `and`, `or`, `implies`, `forall`, `exists`, `atleast`, `atmost`. Atoms add
  `name`, `args`, `line`, `col`. Quantifiers add `var`, `domain`, `line`,
  `col`, and `k` for the counting forms.
- Plan nodes add `rule_id`, `rule`, `size`, `srs`, `assumption` and
  `challenge`. The kinds are `atom`, `and`, `or`, `exists`,
  `forall-aggregate`, `forall-partition`, `forall-each`, `registry-check`,
  `atleast`, `atmost`, `const` and `uncompilable`.

`line` and `col` start at 1 and count characters. `excerpt` is the source line,
a newline, and a caret under the column. `rewrite_steps` lists the desugaring
steps first and the normal-form steps after them, in the order applied. The
`after` of a step shows the result of that one rule, so a later step may start
from a part of it. The `interference` list always has the three rows `issue`,
`revoke inside footprint` and `revoke outside footprint`.

Rule identifiers: `R-ATOM-<NAME>` for registry atoms, `R-CRED-<NAME>` for
credential atoms, `R-AND`, `R-OR`, `R-EXISTS`, `R-FORALL-NOTREVOKED`,
`R-FORALL-REVOKED`, `R-FORALL-MIXED`, `R-FORALL-EACH`, `R-ATLEAST`,
`R-ATMOST`, `R-REGISTRY-ALL-REVOKED`, `R-REGISTRY-NONE-REVOKED`, `R-TRUE`,
`R-FALSE`, `R-NEG-UNSUPPORTED`.

## WebAssembly ABI

The module imports nothing and exports `memory` and four functions.

| Export | Meaning |
|---|---|
| `qlc_alloc(len) -> ptr` | allocates `len` bytes for the UTF-8 query |
| `qlc_compile(ptr, len) -> ptr` | compiles; the result starts with a little-endian `u32` length, followed by that many bytes of UTF-8 JSON |
| `qlc_result_free(ptr)` | frees a result of `qlc_compile` |
| `qlc_free(ptr, len)` | frees a buffer of `qlc_alloc`, with the same `len` |

Errors in the query, including invalid UTF-8, come back as JSON with
`ok: false`. The parser limits nesting to 200 levels so that hostile input
cannot exhaust the stack.

```js
async function loadQlc(wasmBytes) {
  const { instance } = await WebAssembly.instantiate(wasmBytes, {});
  const { memory, qlc_alloc, qlc_free, qlc_compile, qlc_result_free } = instance.exports;
  return function compile(query) {
    const bytes = new TextEncoder().encode(query);
    const input = qlc_alloc(bytes.length);
    new Uint8Array(memory.buffer, input, bytes.length).set(bytes);
    const result = qlc_compile(input, bytes.length);
    const length = new DataView(memory.buffer).getUint32(result, true);
    const json = new TextDecoder().decode(new Uint8Array(memory.buffer, result + 4, length));
    qlc_result_free(result);
    qlc_free(input, bytes.length);
    return JSON.parse(json);
  };
}
```

Create the views on `memory.buffer` after `qlc_compile` returns. The call can
grow the memory, and growth detaches views made earlier. In a single-file
dashboard, embed the wasm as base64 and pass
`Uint8Array.from(atob(b64), c => c.charCodeAt(0))` to `loadQlc`.

## Adding an atom

1. In `src/ast.rs`, add a variant to `AtomName` and a row to `ATOMS` with the
   argument kinds, a usage example and the `registry` flag. Add the variant to
   the list in the test `every_atom_has_a_row`. The parser now accepts the atom
   and checks its arity and argument kinds. If the atom needs a new kind of
   argument, add a variant to `ArgKind` and an arm to `Parser::check_arg` in
   `src/parser.rs`.
2. If the language has an atom that means the negation, add both directions to
   `AtomName::dual`. Without a dual, the normal form keeps `¬atom` and warns.
3. If the atom is sugar, expand it in `desugar_atom` in `src/desugar.rs`.
4. If the atom reads the registry, give it a polarity and a trigger in
   `atom_occurrence` in `src/classify.rs`. Credential atoms need nothing here.
5. Add an arm to `build_atom` in `src/plan.rs` with the construction, size,
   SRS need and assumption. The compiler rejects a missing arm, because the
   `match` has no wildcard.
6. Add a row to the atom table in this file and a test.

## Decisions that go beyond DESIGN.md

- `NotIssued` and `NotIn` parse and classify, but their plan nodes say that
  they cannot be compiled, because the design issues no non-membership
  witnesses (DESIGN.md 3.3). `NotIssued` also produces a warning.
- DESIGN.md 3.6 has no rule for `atmost`. The plan reads it as `atleast |S|−k`
  on the dual body and `atmost 0` as the `forall` rule.
- `forall` over `Issued` with a single `Revoked` or `NotRevoked` body maps to
  the whole-registry checks of DESIGN.md 2.3.
- The plan texts for `Enc` and `EncDec` leave the assumption open, because
  DESIGN.md does not state it.
