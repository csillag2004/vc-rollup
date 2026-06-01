@startuml
skinparam backgroundColor #fbf9f4

title Initialise Accumulator — communication with contracts

actor "Issuer\n(off-chain)" as Issuer
participant "Accumulator\ncontract\n(Scroll Sepolia)" as Acc


Issuer -> Acc : set accumulator value
activate Acc
Acc --> Issuer : 
deactivate Acc

Issuer -> Acc : set accumulator params
activate Acc
Acc --> Issuer : 
deactivate Acc

Issuer -> Acc : set accumulator public key
activate Acc
Acc --> Issuer :
deactivate Acc


@enduml
