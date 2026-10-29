Feature: The contract classifies a guard and decides what it checks
  The front end compiles a guard into a presented part, which the holder proves off-chain,
  and a public part over groups and Issued, which the contract evaluates when the update
  executes. The contract computes the class of both. Only a co-stable or volatile presented
  part makes it compare the registry version.

  Background:
    Given a landlord with a BBS key published in its DID document
    And a schema "Interest" version "1.0" with attributes "flat" and "name"
    And the landlord registers a CredDef for the schema "Interest"
    And a revocation registry for the CredDef with a published SRS
    And the landlord has issued interest credentials to Alice, Bob and Carol
    And the group S = {Alice, Bob, Carol} is anchored on chain

  Scenario Outline: <query>
    When the policy '<query>' is registered
    Then the contract classifies the presented part as "<presented>" and the public part as "<public>"
    And the front end computes the same classes
    And a guarded update <compares> the registry version

    Examples:
      | query                                                                                         | presented         | public            | compares           |
      | exists x in S. Revoked(x)                                                                     | state-independent | stable            | does not compare   |
      | atleast 2 x in S. Revoked(x)                                                                  | state-independent | stable            | does not compare   |
      | forall x in S. NotRevoked(x)                                                                  | state-independent | co-stable         | does not compare   |
      | atmost 1 x in S. Revoked(x)                                                                   | state-independent | co-stable         | does not compare   |
      | forall x in Issued. NotRevoked(x)                                                             | state-independent | co-stable         | does not compare   |
      | exists x in Issued. NotRevoked(x)                                                             | state-independent | volatile          | does not compare   |
      | exists x in Presented. Sig(x, "Interest") & Revoked(x)                                        | stable            | state-independent | does not compare   |
      | exists x in Presented. Sig(x, "Interest") & Active(x)                                         | co-stable         | state-independent | compares           |
      | (exists x in Presented. Sig(x, "Interest") & NotRevoked(x)) & atmost 1 y in Issued. NotRevoked(y) | co-stable     | volatile          | compares           |

  Scenario Outline: A query that does not split as presented ∧ public stays off-chain
    When the policy '<query>' is compiled for the chain
    Then it cannot be bound to an on-chain action

    Examples:
      | query                                                                                  |
      | exists x in S. Sig(x, "Landlord") & Revoked(x)                                         |
      | (exists x in Presented. Sig(x, "Interest") & Revoked(x)) or forall y in S. NotRevoked(y) |
