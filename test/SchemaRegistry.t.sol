pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";

contract SchemaRegistryTest is Test {
    SchemaRegistry public sechmaRegistry;

    function setUp() public {
        sechmaRegistry = new SchemaRegistry();
    }

    function test_registerAndRead() public {
        // registerSchema hívás, majd getSchema, majd assertEq minden mezőre
        string[] memory attributes = new string[](4);
        attributes[0] = "studentName";
        attributes[1] = "university";
        attributes[2] = "degree";
        attributes[3] = "graduationYear";
        bytes32 id = sechmaRegistry.registerSchema("UniversityDegree", "1.0", attributes);
        SchemaRegistry.Schema memory s = sechmaRegistry.getSchema(id);
        //visszakatpott mezők ellenőrzése
        assertEq(s.name ,"UniversityDegree");
        assertEq(s.version, "1.0");
        assertEq(s.attributeNames[0],"studentName");
        assertEq(s.attributeNames[1],"university");
        assertEq(s.attributeNames[2],"degree");
        assertEq(s.attributeNames[3],"graduationYear");

    }

    function test_duplicateReverts() public {
        // első regisztráció OK, második vm.expectRevert(...)
        string[] memory attributes1 = new string[](4);
        attributes1[0] = "studentName";
        attributes1[1] = "university";
        attributes1[2] = "degree";
        attributes1[3] = "graduationYear";
        bytes32 id1 = sechmaRegistry.registerSchema("UniversityDegree", "1.0", attributes1);

        vm.expectRevert();
        bytes32 id2 = sechmaRegistry.registerSchema("UniversityDegree", "1.0", attributes1);
    }

    function test_immutability() public {
        // regisztráció, vm.warp, újraolvasás, assertEq
        string[] memory attributes = new string[](4);
        attributes[0] = "studentName";
        attributes[1] = "university";
        attributes[2] = "degree";
        attributes[3] = "graduationYear";
        bytes32 id = sechmaRegistry.registerSchema("UniversityDegree", "1.0", attributes);
        SchemaRegistry.Schema memory s = sechmaRegistry.getSchema(id);
        //lokális eltárolás
        string memory name = s.name;
        string memory version = s.version;
        string[] memory attributesFromRegister = new string[](4);
        attributesFromRegister[0] = s.attributeNames[0];
        attributesFromRegister[1] = s.attributeNames[1];
        attributesFromRegister[2] = s.attributeNames[2];
        attributesFromRegister[3] = s.attributeNames[3];
        //idő és blokk léptetés
        vm.warp(block.timestamp + 3600);
        vm.roll(block.number + 100);
        //ellenőrzés
        SchemaRegistry.Schema memory s2 = sechmaRegistry.getSchema(id);
        assertEq(s2.name , name);
        assertEq(s2.version, version);
        assertEq(s2.attributeNames[0],attributesFromRegister[0]);
        assertEq(s2.attributeNames[1],attributesFromRegister[1]);
        assertEq(s2.attributeNames[2],attributesFromRegister[2]);
        assertEq(s2.attributeNames[3],attributesFromRegister[3]);
    }
}
