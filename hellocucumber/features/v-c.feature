Feature: Verifiable Credential issuance and proof verification
  A Holder with a valid credential can prove possession to a Verifier,
  while a Holder with a revoked credential cannot.


  Scenario: 1. Create accumulator
    When the Issuer create an accumulator
    Then the accumulator is created successfully

 Scenario: 2. Not create accumulator
    Then the accumulator is not created successfully

  Scenario: 3. Create schema
    Given the Issuer create an accumulator
    When the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    Then the schema is registered successfully

  Scenario: 4. Create credential
    Given the Issuer create an accumulator 
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear" 
    When the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And save the accumulator state
    And the Issuer issues credential "cred1"
    Then the "cred1" is issued successfully - is available in the map
    And the accumulator is changed
    And state has "cred1"

  Scenario: 5. Add more credentials
    Given the Issuer create an accumulator 
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear" 
    
    When the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And save the accumulator state
    And the Issuer issues credential "cred1"
    
    Then the accumulator is changed
    
    When save the accumulator state
    And the Issuer issues credential "cred2"
    
    Then the accumulator is changed
    
    When save the accumulator state
    And the Issuer issues credential "cred3"
    
    Then the accumulator is changed
    And  the "cred1" is issued successfully - is available in the map
    And  the "cred2" is issued successfully - is available in the map
    And  the "cred3" is issued successfully - is available in the map
    And state has "cred1"
    And state has "cred2"
    And state has "cred3"