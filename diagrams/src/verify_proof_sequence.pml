@startuml
skinparam backgroundColor #fbf9f4
title Verify Composite Proof (Verifier) — communication with contracts

actor "Verifier\n(off-chain)" as Verifier
participant "SchemaRegistry\ncontract\n(Scroll Sepolia)" as Schema
participant "CredDefRegistry\ncontract\n(Scroll Sepolia)" as CredDef
participant "EthereumDIDRegistry\ncontract\n(Scroll Sepolia)" as DID
participant "Accumulator\ncontract\n(Scroll Sepolia)" as Acc



Verifier -> CredDef : get credDef\n(issuer, keyId)
activate CredDef
CredDef --> Verifier : credDef
deactivate CredDef

Verifier -> DID : resolve issuer DID\n(read published BBS+ public key)
activate DID
DID --> Verifier : BBS+ public key
deactivate DID

note over Verifier : check keyId == keccak256(public key)

Verifier -> Acc : get params
activate Acc
Acc --> Verifier : params
deactivate Acc

Verifier -> Acc : get public key
activate Acc
Acc --> Verifier : publicKey
deactivate Acc

Verifier -> Acc : get accumulator value
activate Acc
Acc --> Verifier : value
deactivate Acc

note over Verifier : verify composite proof (off-chain)


@enduml
