const { Given, When, Then } = require('@cucumber/cucumber');
const assert = require('node:assert/strict');

const ATTRS = ['Alice', 'University X', 'Computer Science', '2024'];
const MESSAGE_COUNT = 5;

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
    const v = version + '-' + Math.floor(Math.random() * 100000); //minden futtatásnál új verzió, hogy ne ütközzön a már regisztrált sémákkal
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
    await this.issuer.addCredentials(credId, registryId);
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
