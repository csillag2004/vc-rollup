@startuml
skinparam backgroundColor #fbf9f4
title Generate Composite Proof (Holder) — communication with contracts

actor "Holder\n(off-chain)" as Holder
participant "SchemaRegistry\ncontract\n(Scroll Sepolia)" as Schema
participant "Accumulator\ncontract\n(Scroll Sepolia)" as Acc
participant "Verifier\n(off-chain)" as Verifier



Holder -> Acc : get params
activate Acc
Acc --> Holder : params
deactivate Acc

Holder -> Acc : get public key
activate Acc
Acc --> Holder : publicKey
deactivate Acc

Holder -> Acc : get accumulator value
activate Acc
Acc --> Holder : value
deactivate Acc

note over Holder : build BBS+ proof of knowledge +\naccumulator-membership ZKP,\nselected attributes revealed (off-chain)

Holder -> Verifier : composite proof, revealed messages,\nschemaId, credDefId, proving key
activate Verifier
Verifier --> Holder :
deactivate Verifier


@enduml
