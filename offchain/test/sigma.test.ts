import { test } from 'node:test';
import assert from 'node:assert/strict';
import { g1, g2, inv, mul, randomScalar, utf8ToBytes, g1FromHex } from '../src/crypto/bls.ts';
import * as acc from '../src/crypto/accumulator.ts';
import * as L from '../src/crypto/leaves.ts';
import * as S from '../src/crypto/sigma.ts';
import * as bbs from '../src/crypto/bbs.ts';

function registry() {
  const { secret, pub } = acc.generateAccumulatorKeys();
  let v = acc.initialValues(pub);
  const ys = [1n, 2n, 3n].map(() => randomScalar());
  const rec: Record<string, any> = {};
  for (const y of ys) {
    const st = acc.issueStep(secret, v, y);
    rec[y.toString()] = { A: st.receiptA, I: st.receiptI };
    v = { ...v, I: st.newI, WIR: st.newWIR };
  }
  return { secret, pub, v, ys, rec };
}

test('NotRevoked leaf, Revoked leaf, OR with a simulated branch, threshold', () => {
  const { secret, pub, v: v0, ys, rec } = registry();
  const [ya, yb, yc] = ys as [bigint, bigint, bigint];
  // revoke yb
  const RtBefore = v0.Rtilde;
  const st = acc.revokeStep(secret, v0, yb);
  const v = { ...v0, A: st.newA, Rtilde: st.newRtilde, WIR: st.newWIR };
  assert.ok(acc.consistencyCheck(v, pub) && acc.subsetCheck(v));
  const Ca = acc.refreshReceiptA(rec[ya.toString()].A, v.A, ya, yb);
  assert.ok(acc.verifyReceiptG1(v.A, ya, Ca, pub.Qtilde));
  assert.ok(acc.verifyReceiptRtilde(v.Rtilde, yb, RtBefore, pub.Q));

  const oa = L.newOpening(ya), ob = L.newOpening(yb);
  const Ka = L.commit(oa), Kb = L.commit(ob);
  const nr = L.accLeafProver('R-ATOM-NOTREVOKED', v.A, pub.Qtilde, Ka, oa, Ca);
  const rv = L.revLeafProver(v.Rtilde, pub.Q, Kb, ob, RtBefore);
  // OR: "a is revoked" (false, simulated) or "a is not revoked" (true)
  const fake = L.revLeafVerifier(v.Rtilde, pub.Q, Ka, L.fakeRevLeafPublic(pub.Qtilde));
  const or: S.Node = { kind: 'thr', k: 1, children: [fake, nr.leaf] };
  const root: S.Node = { kind: 'and', children: [or, rv.leaf] };
  const w: S.Witnesses = new Map([[nr.leaf, nr.wit], [rv.leaf, rv.wit]]);
  const proof = S.prove(root, w, 'ctx');
  assert.equal(S.verify(root, proof, 'ctx'), true);
  assert.equal(S.verify(root, proof, 'other ctx'), false);

  // 2-of-3 threshold, one false
  const nr2 = L.accLeafProver('x', v.A, pub.Qtilde, Ka, oa, Ca);
  const fake2 = L.accLeafVerifier('y', v.A, pub.Qtilde, Kb, L.fakeAccLeafPublic(pub.Q));
  const thr: S.Node = { kind: 'thr', k: 2, children: [nr2.leaf, fake2, rv.leaf] };
  const p2 = S.prove(thr, new Map([[nr2.leaf, nr2.wit], [rv.leaf, rv.wit]]), 'c');
  assert.equal(S.verify(thr, p2, 'c'), true);
  // revoked credential cannot prove NotRevoked: no receipt against the new A
  assert.throws(() => acc.refreshReceiptA(rec[yb.toString()].A, v.A, yb, yb));
});

test('BBS leaf linked to a NotRevoked leaf, and distinctness', async () => {
  const { pub, v, ys, rec } = registry();
  const kp = await bbs.generateKeyPair();
  const header = utf8ToBytes('cd');
  const yMsg = utf8ToBytes('rid-1');
  const y = bbs.messageToScalar(yMsg);
  // issue y into a fresh registry so the receipt matches
  const { secret, pub: pub2 } = acc.generateAccumulatorKeys();
  const iv = acc.initialValues(pub2);
  const ist = acc.issueStep(secret, iv, y);
  const msgs = [yMsg, utf8ToBytes('Alice')];
  const sig = await bbs.sign(kp, header, msgs);
  const scalars = msgs.map(bbs.messageToScalar);
  const oy = L.newOpening(y);
  const spec = { pk: kp.publicKey, header, yIndex: 0 };
  const cred = L.bbsLeafProver(spec, sig, scalars, [1], oy);
  const K = g1FromHex(cred.pub.K);
  const nr = L.accLeafProver('R-ATOM-NOTREVOKED', iv.A, pub2.Qtilde, K, oy, ist.receiptA);
  const root: S.Node = { kind: 'and', children: [cred.leaf, nr.leaf] };
  const proof = S.prove(root, new Map([[cred.leaf, cred.wit], [nr.leaf, nr.wit]]), 'p');
  // verifier rebuilds from public data
  const vroot: S.Node = { kind: 'and', children: [L.bbsLeafVerifier(spec, cred.pub), L.accLeafVerifier('R-ATOM-NOTREVOKED', iv.A, pub2.Qtilde, K, nr.pub)] };
  assert.equal(S.verify(vroot, proof, 'p'), true);
  // tamper with a disclosed message
  const bad = { ...cred.pub, disclosed: { 1: bbs.messageToScalar(utf8ToBytes('Mallory')).toString(16) } };
  const vbad: S.Node = { kind: 'and', children: [L.bbsLeafVerifier(spec, bad), vroot.children[1]!] };
  assert.equal(S.verify(vbad, proof, 'p'), false);

  const o1 = L.newOpening(5n), o2 = L.newOpening(9n);
  const nq = L.neqLeafProver(L.commit(o1), L.commit(o2), o1, o2);
  assert.equal(S.verify(nq.leaf, S.prove(nq.leaf, new Map([[nq.leaf, nq.wit]]), 'n'), 'n'), true);
  void pub; void v; void ys; void rec; void mul; void g1;
});

test('aggregate receipt from individual receipts equals the trapdoor one (|S| = 2..5)', () => {
  const { secret, pub } = acc.generateAccumulatorKeys();
  const srs = acc.makeSrs(secret.alpha, 6);
  for (let n = 2; n <= 5; n++) {
    const members = Array.from({ length: n }, () => randomScalar());
    const A = pub.V0;
    const receipts = members.map((y) => mul(A, 1n) && acc.issueStep(secret, acc.initialValues(pub), y).receiptA);
    const W = acc.aggregateReceipt(members, receipts);
    assert.ok(W.equals(acc.aggregateReceiptWithTrapdoor(secret, A, members)), `n=${n}`);
    assert.ok(acc.verifyAggregate(A, W, members, srs));
    const D = acc.groupMemberReceipt(members, members[0]!, srs);
    assert.ok(acc.verifyReceiptG1(acc.groupAccumulator(members, srs), members[0]!, D, pub.Qtilde));
  }
});

// This is a counterexample, not a security claim: the accumulator trapdoor permits
// a false set-membership witness. Update guards therefore reject private clauses.
test('trapdoor holder can forge a revoked status witness for the empty set', () => {
  const alpha = 5n, y = 7n;
  const opening = L.newOpening(y);
  const Q = mul(g1, alpha);
  const forged = mul(g2, inv(alpha + y));
  const leaf = L.revLeafProver(g2, Q, L.commit(opening), opening, forged);
  const proof = S.prove(leaf.leaf, new Map([[leaf.leaf, leaf.wit]]), 'trapdoor-counterexample');
  const verifier = L.revLeafVerifier(g2, Q, L.commit(opening), leaf.pub);
  assert.equal(S.verify(verifier, proof, 'trapdoor-counterexample'), true);
});
