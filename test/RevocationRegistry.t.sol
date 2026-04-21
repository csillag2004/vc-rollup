pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {CredDefRegistry} from "../src/CredDefRegistry.sol";
import {RevocationRegistry} from "../src/RevocationRegistry.sol";

contract RevocationRegistryTest is Test{
    SchemaRegistry public schemaRegistry;
    CredDefRegistry public credDefRegistry;
    RevocationRegistry public revocationRegistry;
    bytes32 public schemaId;
    bytes public pk = hex"aabbccdd1122334455";
    bytes public initialAccumulator = hex"12345678";
    uint256 public maxCredentials = 1000;

    function setUp() public{
        schemaRegistry = new SchemaRegistry();
        credDefRegistry = new CredDefRegistry(address(schemaRegistry));
        revocationRegistry = new RevocationRegistry(address(credDefRegistry));
        string[] memory attributes = new string[](4);
        attributes[0] = "studentName";
        attributes[1] = "university";
        attributes[2] = "degree";
        attributes[3] = "graduationYear";
        schemaId = schemaRegistry.registerSchema("UniversityDegree", "1.0", attributes);
    }

    function test_registerAndRead() public{
        bytes32 credDefId = credDefRegistry.registerCredDef(schemaId, "default", pk);
        bytes32 registryId = revocationRegistry.createRegistry(credDefId, initialAccumulator);
        (bytes memory acc, uint256 epoch) = revocationRegistry.getRegistry(registryId);
        assertEq(keccak256(acc), keccak256(initialAccumulator));
        assertEq(epoch, 0);
    }

    function test_nonExistenetCredDefReverts() public{
        // nem létező credDefRegistry-vel próbálkozom
        bytes32 fake_id = keccak256(abi.encodePacked("fake"));
        vm.expectRevert();
        bytes32 registryId = revocationRegistry.createRegistry(fake_id, initialAccumulator);
    }

    function test_updateAndRead() public{
        bytes32 credDefId = credDefRegistry.registerCredDef(schemaId, "default", pk);
        bytes32 registryId = revocationRegistry.createRegistry(credDefId, initialAccumulator);
        bytes memory newAccumulator = hex"87654321";
        revocationRegistry.updateRegistry(registryId, newAccumulator, new uint256[](2), new uint256[](3));
        (bytes memory acc, uint256 epoch) = revocationRegistry.getRegistry(registryId);
        assertEq(keccak256(acc), keccak256(newAccumulator));
        assertEq(epoch, 1);
    }

    function test_epochIncrements() public{
        bytes32 credDefId = credDefRegistry.registerCredDef(schemaId, "default", pk);
        bytes32 registryId = revocationRegistry.createRegistry(credDefId, initialAccumulator);
        revocationRegistry.updateRegistry(registryId, "acc1", new uint256[](2), new uint256[](3));
        revocationRegistry.updateRegistry(registryId, "acc2", new uint256[](4), new uint256[](5));
        (bytes memory acc, uint256 epoch) = revocationRegistry.getRegistry(registryId);
        assertEq(keccak256(acc), keccak256("acc2"));
        assertEq(epoch, 2);
    }

    function test_registryCreatedEvent() public {
        bytes32 credDefId = credDefRegistry.registerCredDef(schemaId, "default", pk);

        bytes32 expectedRegistryId = keccak256(abi.encodePacked(address(this), credDefId));

        vm.expectEmit(true, true, true, false);
        emit RevocationRegistry.RegistryCreated(expectedRegistryId, credDefId, address(this), initialAccumulator);

        revocationRegistry.createRegistry(credDefId, initialAccumulator);
    }

    function test_updatedRegistryEvent() public {
        bytes32 credDefId = credDefRegistry.registerCredDef(schemaId, "default", pk);
        bytes32 registryId = revocationRegistry.createRegistry(credDefId, initialAccumulator);

        bytes memory newAccumulator = "acc1";
        bytes memory delta = "delta1";

        vm.expectEmit(true, true, true, false);
        emit RevocationRegistry.UpdatedRegistry(registryId, 1, newAccumulator, new uint256[](2), new uint256[](3));

        revocationRegistry.updateRegistry(registryId, newAccumulator, new uint256[](2), new uint256[](3));
    }
}