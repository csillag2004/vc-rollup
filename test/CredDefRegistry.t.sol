/*pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {CredDefRegistry} from "../src/CredDefRegistry.sol";

contract CredDefRegistryTest is Test{
    SchemaRegistry public schemaRegistry;
    CredDefRegistry public credDefRegistry;
    bytes32 public schemaId;
    bytes public pk = hex"aabbccdd1122334455";

    function setUp() public{
        schemaRegistry = new SchemaRegistry();
        credDefRegistry = new CredDefRegistry(address(schemaRegistry));
        string[] memory attributes = new string[](4);
        attributes[0] = "studentName";
        attributes[1] = "university";
        attributes[2] = "degree";
        attributes[3] = "graduationYear";
        schemaId = schemaRegistry.registerSchema("UniversityDegree", "1.0", attributes);
    }

    function test_registerAndRead() public{
        bytes32 id = credDefRegistry.registerCredDef(schemaId, "default", pk);
        CredDefRegistry.CredDef memory c = credDefRegistry.getCredDef(id);
        assertEq(c.tag, "default");
        assertEq(keccak256(c.publicKeyMaterial), keccak256(pk));
    }

    function test_nonExistenetSchemaReverts() public{
        // nem létező schemaRegistry-vel próbálkozom
        bytes32 fake_id = keccak256(abi.encodePacked("fake"));
        vm.expectRevert();
        bytes32 id = credDefRegistry.registerCredDef(fake_id, "default", pk);
    }

    function test_duplicatdReverts() public{
        bytes32 id = credDefRegistry.registerCredDef(schemaId, "default", pk);

        vm.expectRevert();

        bytes32 id2 = credDefRegistry.registerCredDef(schemaId, "default", pk);
    }
}*/