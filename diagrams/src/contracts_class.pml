@startuml
skinparam backgroundColor #fbf9f4
title On-chain contracts (Scroll Sepolia)

skinparam classAttributeIconSize 0
hide circle
left to right direction

' + external/public   - private   # internal

class Accumulator <<contract>> {
  - accumulatorValue : bytes
  - publicKey : bytes
  - params : bytes
  - owner : address
  - witnessUpdateInfo : bytes
  - epoch : uint256
  --
  + <<constructor>>()
  + setAccumulator(newValue : bytes, additions : uint256[], removals : uint256[], witnessInfo : bytes) <<onlyOwner>>
  + getAccumulator() : bytes
  + setPublicKey(newPublicKey : bytes) <<onlyOwner>>
  + getPublicKey() : bytes
  + setParams(newParams : bytes) <<onlyOwner>>
  + getParams() : bytes
  + getOwner() : address
  .. events ..
  AccumulatorUpdated(value, additions, removals, witnessUpdateInfo, epoch)
}

class SchemaRegistry <<contract>> {
  - schemas : mapping(bytes32 => Schema)
  --
  + registerSchema(name : string, version : string, attributeNames : string[]) : bytes32
  + getSchema(schemaId : bytes32) : Schema
  .. events ..
  SchemaRegistered(schemaId, issuer, name, version)
}

class Schema <<struct>> {
  + issuer : address
  + name : string
  + version : string
  + attributeNames : string[]
  + createdAt : uint256
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

class RevocationRegistry <<contract>> {
  + lists : mapping(bytes32 => RevocationList)
  + credDefRegistry : CredDefRegistry
  --
  + <<constructor>>(_credDefRegistry : address)
  + createRegistry(credDefId : bytes32, accumulatorAddr : address) : bytes32
  + updateRegistry(registryId : bytes32, addedScalars : uint256[], revokedScalars : uint256[])
  + getRegistry(registryId : bytes32) : (bytes, uint256)
  .. events ..
  RegistryCreated(registryId, credDefId, issuer, accumulator, initialAccumulator)
  UpdatedRegistry(registryId, epoch, newAccumulator, addedScalars, revokedScalars)
}

class RevocationList <<struct>> {
  + credDefId : bytes32
  + issuer : address
  + currentAccumulator : Accumulator
  + currentEpoch : uint256
  + createdAt : uint256
}

interface IEthereumDIDRegistry {
  + identityOwner(identity : address) : address
}

class EthereumDIDRegistry <<contract>> {
  + owners : mapping(address => address)
  + delegates : mapping(address => mapping(bytes32 => mapping(address => uint)))
  + changed : mapping(address => uint)
  + nonce : mapping(address => uint)
  --
  + identityOwner(identity : address) : address
  + setAttribute(identity : address, name : bytes32, value : bytes, validity : uint)
  + revokeAttribute(identity : address, name : bytes32, value : bytes)
  + changeOwner(identity : address, newOwner : address)
  + addDelegate(identity : address, delegateType : bytes32, delegate : address, validity : uint)
  + validDelegate(identity : address, delegateType : bytes32, delegate : address) : bool
  .. events ..
  DIDAttributeChanged(identity, name, value, validTo, previousChange)
  DIDOwnerChanged(identity, owner, previousChange)
  DIDDelegateChanged(identity, delegateType, delegate, validTo, previousChange)
}

' ── structs owned by their registries ──
SchemaRegistry "1" *-- "0..*" Schema : stores
CredDefRegistry "1" *-- "0..*" CredDef : stores
RevocationRegistry "1" *-- "0..*" RevocationList : stores

' ── cross-contract references ──
CredDefRegistry "*" --> "1" SchemaRegistry : schemaRegistry\n(getSchema)
CredDefRegistry "*" ..> "1" IEthereumDIDRegistry : didRegistry\n(identityOwner)
EthereumDIDRegistry ..|> IEthereumDIDRegistry
RevocationRegistry "*" --> "1" CredDefRegistry : credDefRegistry\n(getCredDef)
RevocationList "*" --> "1" Accumulator : currentAccumulator\n(getAccumulator)

@enduml
