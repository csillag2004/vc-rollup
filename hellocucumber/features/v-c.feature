Feature: Verifiable Credential issuance and proof verification
  A Holder with a valid credential can prove possession to a Verifier,
  while a Holder with a revoked credential cannot.
  
  @issuer
  Scenario: 1. Create accumulator
    When the Issuer create an accumulator
    Then the accumulator is created successfully

  @issuer
  Scenario: 3. Create schema
    Given the Issuer create an accumulator
    When the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    Then the schema is registered successfully
  
  @issuer @4
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

  @issuer @5
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

  @issuer @6
  Scenario: 6. duplicate credential
    Given the Issuer create an accumulator 
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear" 
    When the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And save the accumulator state
    And the Issuer issues credential "cred1"

    Then the "cred1" is issued successfully - is available in the map
    And state has "cred1"
    And the Issuer issues credential "cred1" again

  @issuer @7
  Scenario: 7. Revoke credential
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
    And state has "cred1"
    And state has "cred3"

  @issuer @8
  Scenario: 8. Revoke non-existing credential
    Given the Issuer create an accumulator 
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear" 
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer issues credential "cred2"
    And the Issuer issues credential "cred3"
    
    When save the accumulator state
    And the Issuer revokes "cred4" - not existing

    Then the accumulator is not changed
    And state has "cred1"
    And state has "cred2"
    And state has "cred3"

  @issuer @9
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

  @issuer @10
  Scenario: 10. Create witness
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    
    When the Issuer creates the first witness for "cred1"
    Then the witness is valid for "cred1"


  @issuer @11
  Scenario: 11. Create witness after revocation
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    
    When the Issuer revokes "cred1"
    And the Issuer creates a witness for "cred1" - after revocation

    Then the witness is not created for "cred1"

  @issuer @12
  Scenario: 12. Witness is invalid after accumulator change
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"

    When the Issuer issues credential "cred2"

    Then the witness is invalid for "cred1"
    
    When the Issuer updates witness for "cred1"

    Then the witness is valid for "cred1"

  @issuer @13
  Scenario: 13. Sign credential
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"

    When the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    Then the signature for "cred1" is valid for messages "Alice, MIT, PhD, 2024"
  

  @issuer @14
  Scenario: 14. Verify sign with wrong messenge
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    Then the signature for "cred1" is not valid for messages "Alice, MIT, Bachelor's, 2024"


  @issuer @15
  Scenario: 15. Verify sign with wrong number of messages
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    Then the signature for "cred1" is not valid for messages "Alice, MIT, PhD"



  @holder
  Scenario: 16. Holder get credential and verify signature
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    When the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    Then the Holder has credential "cred1"

  @holder
  Scenario: 17. Holder get 2 credentials and verify signature
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer issues credential "cred2"
    And the Issuer creates the first witness for "cred1"
    And the Issuer creates the first witness for "cred2"

    When the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"
    And the Issuer signs credential "cred2" with messages "Bob, Stanford, Master's, 2023"

    Then the Holder has credential "cred1"
    And the Holder has credential "cred2"

   @holder 
  Scenario: 18. Holder create proof for credential
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    When the Holder has credential "cred1"

    Then the proof is created successfully for "cred1"

  @holder 
  Scenario: 19. Holder verify witness from Issuer
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    Then the Holder's witness is valid for "cred1"

  @holder
  Scenario: 20. No error for witness update
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    When the Issuer issues credential "cred2"

    Then the Holder's witness is invalid for "cred1"

    And the Holder updates witness for "cred1"

    Then the Holder's witness is valid for "cred1"

  @holder @not
  Scenario: 21. Issuer give wrong witness with credential
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"

    When the Issuer issues credential "cred2"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    Then the Holder not has credential "cred1"

  @holder
  Scenario: 22. Update witness after revoke
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    When the Issuer issues credential "cred2"
    And the Issuer revokes "cred1"

    Then the Holder's witness is invalid for "cred1"

    And the Holder cannot updates witness for "cred1"

  @holder @not
  Scenario: 23. Holder create proof for credential after revoke
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    When the Holder has credential "cred1"
    And the Issuer revokes "cred1"

    Then the proof is not created successfully for "cred1"

  @24 @verifier
  Scenario: 24. Verifier get proof datas
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    When the Holder has credential "cred1"

    Then the proof is created successfully for "cred1"
    And Verifier has proof for "cred1"

  @verifier @25
  Scenario: 25. Verifier verify proof
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    When the Holder has credential "cred1"

    Then the proof is created successfully for "cred1"
    And Verifier has proof for "cred1"
    And Verifier verifies proof successfully for "cred1"

  @verifier @26
  Scenario: 26. Verifier verify proof for revoked credential
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    When the Holder has credential "cred1"

    Then the proof is created successfully for "cred1"
    And Verifier has proof for "cred1"
    And the Issuer revokes "cred1"
    And Verifier does not verify proof successfully for "cred1"


  @verifier @27
  Scenario: 27. Verifier verify proof with changed accumulator
    Given the Issuer create an accumulator
    And the Issuer registers a schema with name "Degree", version "first-version" and attributes "studentName, university, degree, graduationYear"
    And the Issuer creates a credential definition for the registered schema
    And the issuer creates a revocation registry for the credential definition
    And the Issuer issues credential "cred1"
    And the Issuer creates the first witness for "cred1"
    And the Issuer signs credential "cred1" with messages "Alice, MIT, PhD, 2024"

    When the Holder has credential "cred1"
    And the Holder updates witness for "cred1"

    Then the proof is created successfully for "cred1"
    And Verifier has proof for "cred1"
    And the Issuer issues credential "cred2"
    And Verifier does not verify proof successfully for "cred1"



    
