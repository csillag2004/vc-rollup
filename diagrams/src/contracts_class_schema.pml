@startuml
skinparam backgroundColor #fbf9f4

skinparam classAttributeIconSize 0
hide circle
left to right direction

' + external/public   - private   # internal

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



' ── structs owned by their registries ──
SchemaRegistry "1" *-- "0..*" Schema : stores



@enduml
