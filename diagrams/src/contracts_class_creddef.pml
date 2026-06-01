@startuml
skinparam backgroundColor #fbf9f4

skinparam classAttributeIconSize 0
hide circle
left to right direction

' + external/public   - private   # internal

class SchemaRegistry <<contract>> {
}


class CredDefRegistry <<contract>> {
  - creddefs : mapping(bytes32 => CredDef)
  + schemaRegistry : SchemaRegistry
  + didRegistry : IEthereumDIDRegistry <<immutable>>
  --
  + <<constructor>>(_didRegistry : address, _schemaRegistry : address)
  + registerCredDef(schemaId : bytes32, tag : string, keyId : bytes32) : bytes32 <<onlyDidOwner>>
  + getCredDef(credDefId : bytes32) : CredDef
  .. events ..
  CredDefRegistered(credDefId, issuer, schemaId, tag, keyId)
}

class CredDef <<struct>> {
  + issuer : address
  + schemaId : bytes32
  + tag : string
  + keyId : bytes32
  + createdAt : uint256
}


interface IEthereumDIDRegistry {
  + identityOwner(identity : address) : address
}

' ── structs owned by their registries ──
CredDefRegistry "1" *-- "0..*" CredDef : stores

' ── cross-contract references ──
CredDefRegistry "0..*" -- "1" SchemaRegistry 
CredDefRegistry "*" ..> "1" IEthereumDIDRegistry

@enduml
