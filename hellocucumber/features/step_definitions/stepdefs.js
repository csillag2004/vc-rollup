const { Given, When, Then } = require('@cucumber/cucumber');
const assert = require('node:assert/strict');

const ATTRS = ['Alice', 'University X', 'Computer Science', '2024'];
const MESSAGE_COUNT = 5;

//1
When('the Issuer create an accumulator', async function () {
    this.accumulator = await this.issuer.createAccumulator();
});

Then('the accumulator is created successfully', function () {
    assert.ok(this.accumulator);
});

//2
Then('the accumulator is not created successfully', function () {
    assert.ok(!this.accumulator);
});

//3
When('the Issuer registers a schema with name {string}, version {string} and attributes {string}', async function (name, version, attributes) {
    const attrsArray = attributes.split(',').map(attr => attr.trim());
    const v = version + '-' + Math.floor(Math.random() * 100000); //minden futtatásnál új verzió, hogy ne ütközzön a már regisztrált sémákkal
    await this.issuer.schemaId(name, v, attrsArray);
});

Then('the schema is registered successfully', function () {
    assert.ok(this.issuer.getSchemaId());
});

//4
When('the Issuer creates a credential definition for the registered schema', async function () {
    const schemaId = this.issuer.getSchemaId();
    await this.issuer.credDefId(schemaId);
});

When ('the issuer creates a revocation registry for the credential definition', async function () {
    const credDefId = this.issuer.getCredDefId();
    await this.issuer.revocationRegistry(this.accumulator, credDefId);
});

When ('the Issuer issues credential {string}', async function (credId) {
    const registryId = this.issuer.getRegistryId();
    this.accumulator = await this.issuer.addCredentials(credId, registryId);
});

Then('the {string} is issued successfully - is available in the map', function (credId) {
    assert.ok(this.issuer.getCredentialById(credId));
});

Then ('{string} is added to the accumulator"', function (credId) {
    const registryId = this.issuer.getRegistryId();
    const credential = this.issuer.getCredentialById(credId);
    assert.ok(credential);
    assert.strictEqual(credential.registryId, registryId);
});

When ('save the accumulator state', function () {
    this.savedAccumulatorState = new Uint8Array(this.accumulator.accumulated);
});

Then ('the accumulator is changed', function () {
    assert.notDeepStrictEqual(this.accumulator.accumulated, this.savedAccumulatorState);
});
    
Then ('state has {string}', async function (credId) {
    assert.ok(await this.issuer.stateHas(credId));
});

//6
Then ('the Issuer issues credential {string} again', async function (credId) {
    const registryId = this.issuer.getRegistryId();
    await assert.rejects(
        async () => await this.issuer.addCredentials(credId, registryId),
        { message: /already present/ }
    );
});
