pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {CredDefRegistry} from "../src/CredDefRegistry.sol";

contract Integrity is Test{
    SchemaRegistry public schemaRegistry;
    CredDefRegistry public credDefRegistry;
    bytes public pk = hex"aabbccdd1122334455";

    function setUp() public{
        //address didAddr = vm.envAddress("REGISTRY_ADDRESS");
        address schemaAddr = vm.envAddress("SCHEMA_REGISTRY_ADDR");
        address credDefAddr = vm.envAddress("CREDDEF_REGISTRY_ADDR");
        schemaRegistry = SchemaRegistry(schemaAddr);
        credDefRegistry = CredDefRegistry(credDefAddr);
    }

    function test_fullLifecycle() public{
        //Schema Registry
        string[] memory attributes = new string[](4);
        attributes[0] = "studentName";
        attributes[1] = "university";
        attributes[2] = "degree";
        attributes[3] = "graduationYear";
        string memory version = string(abi.encodePacked("v-", vm.toString(block.timestamp)));
        bytes32 schema_id = schemaRegistry.registerSchema("UniversityDegree", version, attributes);
        SchemaRegistry.Schema memory s = schemaRegistry.getSchema(schema_id);
        
        //CredDef Registry
        bytes32 creddef_id = credDefRegistry.registerCredDef(schema_id, "default", pk);
        CredDefRegistry.CredDef memory c = credDefRegistry.getCredDef(creddef_id);
        
        //ellenőrzés
        assertEq(s.name ,"UniversityDegree");
        assertEq(s.version, version);
        assertEq(s.attributeNames[0],"studentName");
        assertEq(s.attributeNames[1],"university");
        assertEq(s.attributeNames[2],"degree");
        assertEq(s.attributeNames[3],"graduationYear");
        assertEq(c.tag, "default");
        assertEq(keccak256(c.publicKeyMaterial), keccak256(pk));
        assertEq(c.schemaId, schema_id);

    }
}