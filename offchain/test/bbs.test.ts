import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as bbs from '../src/crypto/bbs.ts';
import { utf8ToBytes, mod, randomScalar, pairingEq, g2, mul } from '../src/crypto/bls.ts';

test('our B and generators agree with the IETF library', async () => {
  const kp = await bbs.generateKeyPair();
  const header = utf8ToBytes('credDef:test');
  const msgs = ['revocation-id-bytes', 'Alice', 'flat-42'].map(utf8ToBytes);
  const sig = await bbs.sign(kp, header, msgs);
  assert.equal(await bbs.verifyWithLibrary(kp.publicKey, sig, header, msgs), true);
  const scalars = msgs.map(bbs.messageToScalar);
  assert.equal(bbs.verifyOwn(kp.publicKey, sig, header, scalars), true);
  scalars[1] = mod(scalars[1]! + 1n);
  assert.equal(bbs.verifyOwn(kp.publicKey, sig, header, scalars), false);
});

test('randomised signature passes e(Ā, W) = e(B̄, g̃)', async () => {
  const kp = await bbs.generateKeyPair();
  const header = new Uint8Array();
  const msgs = ['a', 'b'].map(utf8ToBytes);
  const sig = await bbs.sign(kp, header, msgs);
  const B = bbs.computeB(kp.publicKey, header, msgs.map(bbs.messageToScalar));
  const { Abar, Bbar } = bbs.randomise(sig, B, randomScalar());
  assert.equal(pairingEq(Abar, bbs.publicKeyPoint(kp.publicKey), Bbar, g2), true);
});
