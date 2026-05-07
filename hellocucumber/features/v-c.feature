Feature: Verifiable Credential issuance and proof verification
  A Holder with a valid credential can prove possession to a Verifier,
  while a Holder with a revoked credential cannot.


  Scenario: 1. Create accumulator
    When the Issuer create an accumulator
    Then the accumulator is created successfully

 