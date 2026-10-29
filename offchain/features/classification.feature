Feature: The class of a guard decides the CAS mode
  A stable guard needs no comparison, a co-stable one over groups compares
  the group versions, anything over Issued compares the registry version.

  Scenario Outline: <query>
    When the policy "<query>" is classified
    Then its class is "<class>" and its CAS mode is "<cas>"

    Examples:
      | query                             | class     | cas    |
      | exists x in S. Revoked(x)         | stable    | none   |
      | atleast 2 x in S. Revoked(x)      | stable    | none   |
      | forall x in S. NotRevoked(x)      | co-stable | group  |
      | atmost 1 x in S. Revoked(x)       | co-stable | group  |
      | forall x in Issued. NotRevoked(x) | co-stable | global |
      | exists x in Issued. NotRevoked(x) | volatile  | global |
