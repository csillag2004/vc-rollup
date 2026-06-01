@startuml
left to right direction
(*) --> "Initialise Accumulator"
--> "Register Schema"
--> "Register CredDef"
--> "Create Revocation Registry"
--> "Issue Credential"
--> "Create Witness"
--> "Sign Credential"
--> (*)
@enduml