Feature: Flat reservation with atomic guarded revocation
  The landlord books the flat by revoking the winner's interest credential,
  but only while no member of the interested group S has been revoked.
  The contract evaluates that guard itself when the revocation executes.

  Background:
    Given a landlord with a BBS key published in its DID document
    And a schema "Interest" version "1.0" with attributes "flat" and "name"
    And the landlord registers a CredDef for the schema "Interest"
    And a revocation registry for the CredDef with a published SRS
    And the landlord has issued interest credentials to Alice, Bob and Carol
    And the group S = {Alice, Bob, Carol} is anchored on chain
    And the guard policy "forall x in S. NotRevoked(x)" is registered

  Scenario: Without a bound policy the flat is booked twice
    Given the guard policy is not bound to Revoke
    And Alice and Bob both prove the guard against group version 0
    When the landlord revokes Alice's credential
    And the landlord revokes Bob's credential
    Then both revocations are accepted
    And the version of S is 2

  Scenario: With a bound policy the contract rejects the second booking
    Given the guard policy is bound to Revoke for the CredDef
    And Alice and Bob both prove the guard against group version 0
    When the landlord revokes Alice's credential with her guard
    Then the revocation is accepted
    And the version of S is 1
    And anyone can verify Alice's guard proof from the ledger
    When the landlord revokes Bob's credential with his guard
    Then the revocation is rejected with "GuardFalse"
    And Bob's credential is not revoked

  Scenario: A stale guard proof is valid but not fresh
    Given Alice's guarded revocation has been accepted
    When a verifier checks Bob's guard proof
    Then the proof is cryptographically valid
    But it is not fresh because S moved from version 0 to 1

  Scenario: A bound policy cannot be bypassed
    Given the guard policy is bound to Revoke for the CredDef
    When the landlord revokes Carol's credential without a guard
    Then the revocation is rejected with "PolicyRequired"
    And Carol's credential is not revoked

  Scenario: The issuer cannot reserve the flat twice
    Given Alice's guarded revocation has been accepted
    When the landlord revokes Bob's credential without a guard
    Then the revocation is rejected with "PolicyRequired"
    When the landlord revokes Bob's credential under the policy "exists x in S. Revoked(x)"
    Then the revocation is rejected with "WrongPolicy"
    When the landlord revokes Bob's credential with a made-up guard proof
    Then the revocation is rejected with "GuardFalse"
    And Bob's credential is not revoked
    And the version of S is 1

  Scenario: The loser's proof stays valid after later updates
    Given Alice's guarded revocation has been accepted
    When Bob proves "exists x in S. Revoked(x)"
    Then the proof is valid and its class is "stable"
    When the landlord issues a new credential to Dave
    Then Bob's proof is still valid and fresh

  Scenario: Alice proves the reservation without revealing who she is
    Given Alice's guarded revocation has been accepted
    When Alice proves 'exists x in S. Sig(x, "Landlord") & Revoked(x)'
    Then the verifier accepts the proof
    And the proof does not reveal which member of S she is
