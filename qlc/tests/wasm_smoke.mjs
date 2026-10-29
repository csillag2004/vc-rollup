// End-to-end check of the WebAssembly ABI with Node.
// Build first: cargo build --release --target wasm32-unknown-unknown
// Run:         node tests/wasm_smoke.mjs
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";

const path = new URL("../target/wasm32-unknown-unknown/release/qlc.wasm", import.meta.url);
const { instance } = await WebAssembly.instantiate(await readFile(path), {});
const { memory, qlc_alloc, qlc_free, qlc_compile, qlc_result_free } = instance.exports;

function compile(query) {
  const bytes = new TextEncoder().encode(query);
  const input = qlc_alloc(bytes.length);
  new Uint8Array(memory.buffer, input, bytes.length).set(bytes);
  const result = qlc_compile(input, bytes.length);
  // Take the views after the call, because the memory may have grown.
  const length = new DataView(memory.buffer).getUint32(result, true);
  const json = new TextDecoder().decode(new Uint8Array(memory.buffer, result + 4, length));
  qlc_result_free(result);
  qlc_free(input, bytes.length);
  return JSON.parse(json);
}

const cases = [
  ["forall x in S. NotRevoked(x)", "antitone"],
  ["¬(∀x∈S. NotRevoked(x))", "monotone"],
  ['atleast 2 x in Presented. (Sig(x, "CertBody") & Active(x) & Range(x.expiry, 20260918, 99991231))', "antitone"],
  ["forall x in Issued. Revoked(x)", "non-monotone"],
];
for (const [query, expected] of cases) {
  const out = compile(query);
  assert.equal(out.ok, true, query);
  assert.equal(out.class, expected, query);
}
assert.equal(compile("¬(∀x∈S. NotRevoked(x))").nnf_pretty, "∃x∈S. Revoked(x)");

const bad = compile("forall x in S. (NotRevoked(x)");
assert.equal(bad.ok, false);
assert.equal(bad.error.col, 30);

// Many calls must not leak or trap.
for (let i = 0; i < 2000; i++) compile(cases[i % cases.length][0]);
console.log(`wasm smoke test passed, memory ${memory.buffer.byteLength} bytes`);
