@startuml
skinparam backgroundColor #fbf9f4

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



@enduml
