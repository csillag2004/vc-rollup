@startuml
skinparam backgroundColor #fbf9f4
title On-chain contracts (Scroll Sepolia)

skinparam classAttributeIconSize 0
hide circle
left to right direction

' + external/public   - private   # internal

class Accumulator <<contract>> {
 
}

class SchemaRegistry <<contract>> {
 
}

class CredDefRegistry <<contract>> {
 
}


class RevocationRegistry <<contract>> {

}


' ── structs owned by their registries ──

' ── cross-contract references ──
CredDefRegistry "0..*" -- "0..*" SchemaRegistry 
RevocationRegistry "0..*" -- "0..*" CredDefRegistry 
RevocationRegistry "0..*" -- "0..*" Accumulator

@enduml
