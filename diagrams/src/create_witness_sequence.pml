@startuml
skinparam backgroundColor #fbf9f4

title Create Witness — communication with contracts

actor "Issuer\n(off-chain)" as Issuer
participant "Accumulator\ncontract\n(Scroll Sepolia)" as Acc


Issuer -> Acc : get accumulator value
activate Acc
Acc --> Issuer : value
deactivate Acc

note over of Issuer
  compute membership witness (off-chain)
end note


@enduml
