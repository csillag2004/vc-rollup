Feature: Verifiable Credential issuance and proof verification
  A Holder with a valid credential can prove possession to a Verifier,
  while a Holder with a revoked credential cannot.



  Scenario: 9. Revoke already revoked credential
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer issues credential "cred2"
    And the Issuer issues credential "cred3"
    
    When save the accumulator state
    And the Issuer revokes "cred2"
    Then the accumulator is changed
    And state does not have "cred2"

    When save the accumulator state
    And the Issuer revokes "cred2" again

    Then the accumulator is not changed
    And state does not have "cred2"
    And state has "cred1"
    And state has "cred3"

  Scenario: 10. Create witness
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    
    When the Issuer creates the first witness for "cred1"
    Then the witness is valid for "cred1"
    
    
