@startuml
skinparam backgroundColor #fbf9f4
title Issue Credential — communication with contracts

actor "Issuer\n(off-chain)" as Issuer
participant "Accumulator\ncontract\n(Scroll Sepolia)" as Acc
participant "RevocationRegistry\ncontract\n(Scroll Sepolia)" as Rev


note over of Issuer : create random y (off-chain)

Issuer -> Acc : get accumulator value
activate Acc
Acc --> Issuer : value
deactivate Acc


Issuer -> Rev : update registry
Rev --> Issuer :
deactivate Rev

Issuer -> Acc : set accumulator value
activate Acc
Acc --> Issuer :
deactivate Acc


@enduml
