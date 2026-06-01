@startuml
skinparam backgroundColor #fbf9f4

title Register Schema — communication with contracts

actor "Issuer\n(off-chain)" as Issuer
participant "SchemaRegistry\ncontract\n(Scroll Sepolia)" as Schema


Issuer -> Schema : register schema\n(name, version, attributes)
activate Schema
Schema --> Issuer : schemaId (event)
deactivate Schema


@enduml
