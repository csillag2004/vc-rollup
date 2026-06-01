@startuml
title Issuer – credential issuance

|Issuer (off-chain)|
start

:Initialise Accumulator;
|Scroll Sepolia (on-chain)|
:write accumulator value, params and publickey onchain;

|Issuer (off-chain)|
:Register Schema;
|Scroll Sepolia (on-chain)|
:write schema onchain;

|Issuer (off-chain)|
:Create BBS+ keypair;
:Upload publickey to DID attributes;
:Register CredDef;
|Scroll Sepolia (on-chain)|
:write credential definition onchain;

|Issuer (off-chain)|
:Create Revocation Registry;
|Scroll Sepolia (on-chain)|
:write revocation registry;

|Issuer (off-chain)|
:Issue Credential;
|Scroll Sepolia (on-chain)|
:add y to the accumulator;

|Issuer (off-chain)|
:Create Witness;

|Issuer (off-chain)|
:Sign Credential;

@enduml