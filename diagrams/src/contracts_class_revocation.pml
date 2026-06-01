@startuml
skinparam backgroundColor #fbf9f4

skinparam classAttributeIconSize 0
hide circle
left to right direction

' + external/public   - private   # internal

class Accumulator <<contract>> {

}

class CredDefRegistry <<contract>> {
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

' ── structs owned by their registries ──
RevocationRegistry "1" *-- "0..*" RevocationList : stores

' ── cross-contract references ──
RevocationRegistry "0..*" -- "1" CredDefRegistry 
RevocationList "0..*" -- "1" Accumulator

@enduml
