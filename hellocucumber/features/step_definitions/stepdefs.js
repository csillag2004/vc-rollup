const { Given, When, Then } = require('@cucumber/cucumber');
const assert = require('node:assert/strict');

const { uuidv7 } = require('uuidv7');

//const ATTRS = ['Alice', 'University X', 'Computer Science', '2024'];
//const MESSAGE_COUNT = 5;

//1
When('the Issuer create an accumulator', async function () {
    await this.issuer.createAccumulator();
});

Then('the accumulator is created successfully', function () {
    assert.ok(this.issuer.getOnChainAccumulator());
});

//2
Then('the accumulator is not created successfully', async function () {
    assert.ok(!(await this.issuer.getOnChainAccumulator()));
});

//3
When('the Issuer registers a schema with name {string}, version {string} and attributes {string}', async function (name, version, attributes) {
    const attrsArray = attributes.split(',').map(attr => attr.trim());
    const v = uuidv7();
    //const v = version + '-' + Math.floor(Math.random() * 100000); //minden futtatásnál új verzió, hogy ne ütközzön a már regisztrált sémákkal
    await this.issuer.schemaId(name, v, attrsArray);
});

Then('the schema is registered successfully', function () {
    assert.ok(this.issuer.getSchemaIds().length > 0);
});

//4
When('the Issuer creates a credential definition for the registered schema', async function () {
    const schemaId = this.issuer.getSchemaIds()[0];
    await this.issuer.credDefId(schemaId);
});

When ('the issuer creates a revocation registry for the credential definition', async function () {
    const credDefId = this.issuer.getCredDefIdsForSchema(this.issuer.getSchemaIds()[0])[0];
    await this.issuer.revocationRegistry(credDefId);
});

When ('the Issuer issues credential {string}', async function (credId) {
    const schemaId = this.issuer.getSchemaIds()[0];
    const credDefId = this.issuer.getCredDefIdsForSchema(schemaId)[0];
    const registryId = this.issuer.getRegistryIdsForCredDef(schemaId, credDefId)[0];
    await this.issuer.addCredentials(credId, registryId, this.holder);
});

Then('the {string} is issued successfully - is available in the map', function (credId) {
    assert.ok(this.issuer.findYByCredId(credId)); //ha van y, akkor benne vana cred is
});

Then('{string} is added to the accumulator', function (credId) {
    const registryId = this.issuer.getRegistryId();
    const credential = this.issuer.getCredentialById(credId);
    assert.ok(credential);
    assert.strictEqual(credential.registryId, registryId);
});

When('save the accumulator state', async function () {
    const acc = await this.issuer.getOnChainAccumulator();
    this.savedAccumulatorState = acc ? new Uint8Array(acc.accumulated) : null;
});

Then('the accumulator is changed', async function () {
    const current = await this.issuer.getOnChainAccumulator();
    const currentBytes = current ? new Uint8Array(current.accumulated) : null;
    assert.notDeepStrictEqual(currentBytes, this.savedAccumulatorState);
});
    
Then('state has {string}', async function (credId) {
    assert.ok(await this.issuer.stateHas(credId));
});

//6
Then('the Issuer issues credential {string} again', async function (credId) {
    const schemaId = this.issuer.getSchemaIds()[0];
    const credDefId = this.issuer.getCredDefIdsForSchema(schemaId)[0];
    const registryId = this.issuer.getRegistryIdsForCredDef(schemaId, credDefId)[0];
    await assert.rejects(
        async () => await this.issuer.addCredentials(credId, registryId),
        { message: /already present/ }
    );
});


//7
When('the Issuer revokes {string}', async function (credId) {
    const registryId = await this.issuer.findRegistryIdByCredId(credId);
    this.accumulator = await this.issuer.revokeCredentials(credId, registryId);
});

Then('the {string} is removed successfully - is not available in the map', async function (credId) { //nem szedem ki a mapból
    await assert.rejects(
        async () => await this.issuer.getCredentialById(credId),
        { message: /not found/ }
    );
});

Then('state does not have {string}', async function (credId) {
    /*await assert.rejects(
        async () => await this.issuer.stateHas(credId),
        { message: /not found/ }
    );*/
        assert.ok(!(await this.issuer.stateHas(credId)));
});

When('save the y {string}', function (credId) { //erre nem lesz szükség
    this.cred_y = this.issuer.getCredentialById(credId); //majd menjen mappbe
});

//8
When('the Issuer revokes {string} - not existing', async function (credId) {
    //const registryId = 
    assert.ok(!(await this.issuer.findRegistryIdByCredId(credId)));
    //assert.ok(!(await this.issuer.revokeCredentials(credId, registryId)));
});

Then('the accumulator is not changed', async function () {
    const current = await this.issuer.getOnChainAccumulator();
    const currentBytes = current ? new Uint8Array(current.accumulated) : null;
    assert.deepStrictEqual(currentBytes, this.savedAccumulatorState);
});

//9
When('the Issuer revokes {string} again', async function (credId) {
    const registryId = await this.issuer.findRegistryIdByCredId(credId);
    await assert.rejects(
        async () => await this.issuer.revokeCredentials(credId, registryId),
        { message: "Credential is not in the state, cannot revoke" }
    );
});

//10 
Then('the Issuer creates the first witness for {string}', async function (credId) {
    await this.issuer.createWitness(credId);
});

Then("the witness is valid for {string}", async function (credId) {
    const witness = this.issuer.getWitness(credId);
    assert.ok(witness, `Witness for ${credId} should exist`);
    const isValid = await this.issuer.verifyWitness(credId, witness);
    assert.ok(isValid, `Witness for ${credId} should be valid`);
});

//11
When('the Issuer creates a witness for {string} - after revocation', async function (credId) {
    await assert.rejects(
        async () => await this.issuer.createWitness(credId),
        { message: "credential is revoked, cannot generate witness" }
    );
});

Then('the witness is not created for {string}', async function (credId) {
    const witness = this.issuer.getWitness(credId);
    assert.ok(!witness, `Witness for ${credId} should not exist`);
});

//12
Then("the witness is invalid for {string}", async function (credId) {
    const witness = this.issuer.getWitness(credId);
    assert.ok(witness, `Witness for ${credId} should exist`);
    const isValid = await this.issuer.verifyWitness(credId, witness);
    assert.ok(!isValid, `Witness for ${credId} should be invalid`);
});

When('the Issuer updates witness for {string}', async function (credId) {
    await this.issuer.createWitness(credId);
});

//13
When("the Issuer signs credential {string} with messages {string}", async function (credId, messages) {
    const messageList = messages.split(", ").map(s => s.trim());
    witness = this.issuer.getWitness(credId);
    console.log("w1: ", witness.w1);
    await this.issuer.signCredential(credId, messageList, witness, messageList.length+1);
});

Then("the signature for {string} is valid for messages {string}", async function (credId, messages) {
    const messageList = messages.split(", ").map(s => s.trim());
    const signResult = await this.issuer.verifySignature(credId, messageList);
    assert.ok(signResult, `Signature for ${credId} should be valid for messages ${messages}`);
});

//14
Then("the signature for {string} is not valid for messages {string}", async function (credId, messages) {
    const messageList = messages.split(", ").map(s => s.trim());
    const signResult = await this.issuer.verifySignature(credId, messageList);
    assert.ok(!signResult, `Signature for ${credId} should not be valid for messages ${messages}`);
});

//16
Then("the Holder has credential {string}", async function (credId) {
    const schemaId = this.issuer.getSchemaIds()[0];
    const credDefId = this.issuer.getCredDefIdsForSchema(schemaId)[0];
    const registryId = this.issuer.getRegistryIdsForCredDef(schemaId, credDefId)[0];
    assert.ok(await this.holder.getCredential(credId), `Holder should have credential ${credId}`);
});

//17
Then("the proof is created successfully for {string}", async function (credId) {
    const proof = await this.holder.compositeProofForCredential(credId, [2, 3], this.verifier);
    assert.ok(proof, `Proof should be created successfully for ${credId}`);
});

//18
Then("the Holder's witness is valid for {string}", async function (credId) {
    const witness = this.holder.getWitness(credId);
    assert.ok(witness, `Witness for ${credId} should exist`);
    const isValid = await this.holder.verifyWitness(credId);
    assert.ok(isValid, `Witness for ${credId} should be valid`);
});

//20
Then("the Holder's witness is invalid for {string}", async function (credId) {
    const witness = this.holder.getWitness(credId);
    assert.ok(witness, `Witness for ${credId} should exist`);
    const isValid = await this.holder.verifyWitness(credId);
    assert.ok(!isValid, `Witness for ${credId} should be invalid`);
});

When("the Holder updates witness for {string}", async function (credId) {
    await this.holder.updateWitness(credId);
});

//21
Then("the Holder not has credential {string}", async function (credId) {
    const schemaId = this.issuer.getSchemaIds()[0];
    const credDefId = this.issuer.getCredDefIdsForSchema(schemaId)[0];
    const registryId = this.issuer.getRegistryIdsForCredDef(schemaId, credDefId)[0];
    assert.ok(!(await this.holder.getCredential(credId)), `Holder should have credential ${credId}`);
});

//22
When("the Holder cannot updates witness for {string}", async function (credId) {
    await assert.rejects(
        async () => await this.holder.updateWitness(credId),
        { message: "credential is revoked, cannot update witness" }
    );
});

//23
Then("the proof is not created successfully for {string}", async function (credId) {
    const proof = await this.holder.compositeProofForCredential(credId, [2, 3], this.verifier);
    assert.ok(proof, `Proof should be created successfully for ${credId}`);
});

//24.
Then("Verifier has proof for {string}", async function (credIs) {
   const proof = await this.verifier.getProof(credIs);
   assert.ok(proof, "Verifier should have proof.") 
});

//25.
Then("Verifier verifies proof successfully for {string}", async function (credId) {
    const isValid = await this.verifier.buildCompositeProof(credId);
    assert.ok(isValid, `Verifier should successfully verify proof for ${credId}`);
});

//26.
Then("Verifier does not verify proof successfully for {string}", async function (credId) {
    const isValid = await this.verifier.buildCompositeProof(credId);
    assert.ok(!isValid, `Verifier should not successfully verify proof for ${credId}`);
});
