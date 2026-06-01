@startuml
skinparam backgroundColor #fbf9f4

title Sign Credential — communication

actor "Issuer\n(off-chain)" as Issuer
participant "Holder\n(off-chain)" as Holder


note over of Issuer
  BBS+ sign with issuer secret key (off-chain)
end note

Issuer -> Holder : signed credential, y, witness
activate Holder
Holder --> Issuer :
deactivate Holder



@enduml
