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


