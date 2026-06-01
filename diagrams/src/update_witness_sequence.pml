@startuml
skinparam backgroundColor #fbf9f4
title Update Witness (Holder) — communication with contracts

actor "Holder\n(off-chain)" as Holder
participant "RevocationRegistry\ncontract\n(Scroll Sepolia)" as Rev
participant "Accumulator\ncontract\n(Scroll Sepolia)" as Acc


Holder -> Rev : get registry\n(current epoch)
activate Rev
Rev --> Holder : epoch
deactivate Rev

Holder -> Acc : query AccumulatorUpdated events\n(from last synced block)
activate Acc
Acc --> Holder : events 
deactivate Acc

note over Holder : replay events to bring the\nmembership witness to the\ncurrent epoch (off-chain)


@enduml
