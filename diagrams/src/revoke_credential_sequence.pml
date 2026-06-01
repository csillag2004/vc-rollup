@startuml
skinparam backgroundColor #fbf9f4
title Revoke Credential — communication with contracts

actor "Issuer\n(off-chain)" as Issuer
participant "Accumulator\ncontract\n(Scroll Sepolia)" as Acc
participant "RevocationRegistry\ncontract\n(Scroll Sepolia)" as Rev



Issuer -> Acc : get accumulator value
activate Acc
Acc --> Issuer : value
deactivate Acc


Issuer -> Acc : set new accumulator value
activate Acc
Acc --> Issuer :
deactivate Acc

Issuer -> Rev : update registry\n(remove y)
activate Rev
Rev --> Issuer :
deactivate Rev


@enduml
