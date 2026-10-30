Feature: Verify on write
  The registry contract checks every write against the current state,
  so a wrong value never reaches the ledger.

  Background:
    Given a landlord with a BBS key published in its DID document

  Scenario: A CredDef needs an existing schema
    When the landlord registers a CredDef for an unknown schema
    Then the registration is rejected with "UnknownSchema"

  Scenario: The chain rejects a wrong revocation step
    Given a schema "Interest" version "1.0" with attributes "flat" and "name"
    And the landlord registers a CredDef for the schema "Interest"
    And a revocation registry for the CredDef with a published SRS
    And the landlord has issued interest credentials to Alice and Bob
    When the landlord submits a revocation of Alice with a wrong new A
    Then the revocation is rejected with "StepCheckFailed"
    And Alice's credential is not revoked

  Scenario: A group holds issued credentials only
    Given a schema "Interest" version "1.0" with attributes "flat" and "name"
    And the landlord registers a CredDef for the schema "Interest"
    And a revocation registry for the CredDef with a published SRS
    And the landlord has issued interest credentials to Alice and Bob
    When the landlord anchors a group of Alice and an ID that was never issued
    Then the group creation is rejected with "MemberNotIssued"
