Feature: Verifiable Credential issuance and proof verification
  A Holder with a valid credential can prove possession to a Verifier,
  while a Holder with a revoked credential cannot.


  Scenario: Create accumulator
    When the Issuer create an accumulator
    Then the accumulator is created successfully

 Scenario: Not create accumulator
    Then the accumulator is not created successfully

  Scenario: Create schema
    Given the Issuer create an accumulator
    When the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    Then the schema is registered successfully

  Scenario: Create credential
  