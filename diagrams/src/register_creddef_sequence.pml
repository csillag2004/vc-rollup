@startuml
skinparam backgroundColor #fbf9f4
title Register CredDef — communication with contracts

actor "Issuer\n(off-chain)" as Issuer
participant "EthereumDIDRegistry\ncontract\n(Scroll Sepolia)" as DID
participant "CredDefRegistry\ncontract\n(Scroll Sepolia)" as CredDef



note over of Issuer : generate BBS+ keypair (off-chain)

Issuer -> DID : set attribute\n(BBS+ public key)
activate DID
DID --> Issuer :
deactivate DID

Issuer -> CredDef : register credDef\n(schemaId, tag, keyId)
activate CredDef
CredDef --> Issuer : credDefId (event)
deactivate CredDef


@enduml
