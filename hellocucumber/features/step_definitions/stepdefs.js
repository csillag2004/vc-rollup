const { Given, When, Then } = require('@cucumber/cucumber');
const assert = require('node:assert/strict');

const ATTRS = ['Alice', 'University X', 'Computer Science', '2024'];
const MESSAGE_COUNT = 5;

When('the Issuer create an accumulator', async function () {
    this.accumulator = await this.issuer.createAccumulator();
});

Then('the accumulator is created successfully', function () {
    assert.ok(this.accumulator);
});

Then('the accumulator is not created successfully', function () {
    assert.ok(!this.accumulator);
});

Given('the Issuer has set up a schema and credential definition',
  async function () {
    this.schemaId  = await this.issuer.schemaId();
    this.credDefId = await this.issuer.credDefId(this.schemaId);
  },
);

Given('the Issuer has created a revocation registry',
  async function () {
    this.accumulator = await this.issuer.createAccumulator();
    this.registryId  = await this.issuer.revocationRegistry(this.accumulator, this.credDefId);
  },
);

When('the Issuer issues credential {string} to the Holder',
  async function (credId) {
    await this.issuer.addCredentials(credId, this.registryId);
    this.witness = await this.issuer.createWitness(credId);
    this.signedCred = this.issuer.signCredential(
      credId,
      [...ATTRS, credId],
      this.witness,
      MESSAGE_COUNT,
    );
  },
);

When('the Holder requests a witness for {string}',
  async function (credId) {
    this.witness = await this.issuer.createWitness(credId);
  },
);

When('the Holder builds a composite proof for {string}',
  async function (_credId) {
    const proof = this.holder.compositeProofForCredential(
      this.signedCred.sig1,
      this.signedCred.cred1Messages,
      this.signedCred.issuerPk,
      this.signedCred.sigParams,
      this.witness.witness,
      this.witness.w1,
      this.accumulator.params,
      this.issuer.getPublicKey(),
      this.accumulator,
    );

    const revealed = new Map([
      [2, this.signedCred.cred1Messages[2]],
      [3, this.signedCred.cred1Messages[3]],
    ]);

    this.lastVerificationResult = await this.verifier.buildCompositeProof(
      this.signedCred.sigParams,
      this.signedCred.issuerPk,
      revealed,
      this.issuer.getPublicKey(),
      this.holder.getProvingKey(),
      this.issuer.getAccumulator(),
      proof,
      this.holder.getNonce(),
      this.issuer.getAccumulator().params,
      this.signedCred.k_handler,
    );
  },
);

Then('the Verifier accepts the proof',
  function () {
    assert.equal(this.lastVerificationResult, true);
  },
);
