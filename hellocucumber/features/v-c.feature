Feature: Verifiable Credential issuance and proof verification
  A Holder with a valid credential can prove possession to a Verifier,
  while a Holder with a revoked credential cannot.
  

  Scenario: 14. Verify sign with wrong messenge
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    Then the signature for "cred1" is not valid for messages "Alice, MIT, Bachelor's, 2024"

    

  Scenario: 15. Verify sign with wrong number of messages
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    Then the signature for "cred1" is not valid for messages "Alice, MIT, PhD"

    
