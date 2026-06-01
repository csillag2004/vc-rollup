@startuml
skinparam backgroundColor #fbf9f4
title Create Revocation Registry — communication with contracts

actor "Issuer\n(off-chain)" as Issuer
participant "RevocationRegistry\ncontract\n(Scroll Sepolia)" as Rev


Issuer -> Rev : create registry\n(credDefId, accumulator address)
activate Rev
Rev --> Issuer : registryId (event)
deactivate Rev


@enduml
