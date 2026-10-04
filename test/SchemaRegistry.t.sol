pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";

contract SchemaRegistryTest is Test {
    SchemaRegistry public schemaRegistry;

    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");

    event SchemaRegistered(bytes32 indexed schemaId, address indexed author, string name, string version, bool holderBound);

    function setUp() public {
        schemaRegistry = new SchemaRegistry();
    }

    function _attributes() internal pure returns (string[] memory attributes) {
        attributes = new string[](4);
        attributes[0] = "studentName";
        attributes[1] = "university";
        attributes[2] = "degree";
        attributes[3] = "graduationYear";
    }

    function _expectedId(address author, string memory name, string memory version, bool holderBound)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(author, name, version, holderBound));
    }

    // ---------------------------------------------------------------------
    // Sikeres regisztráció
    // ---------------------------------------------------------------------

    function test_registerAndRead_notHolderBound() public {
        vm.prank(alice);
        bytes32 id = schemaRegistry.registerSchema("UniversityDegree", "1.0", false, _attributes());
        SchemaRegistry.Schema memory s = schemaRegistry.getSchema(id);

        assertEq(s.author, alice);
        assertEq(s.name, "UniversityDegree");
        assertEq(s.version, "1.0");
        assertFalse(s.holderBound);
        assertEq(s.createdAt, block.timestamp);

        // revocation_id elöl, link_secret nincs
        assertEq(s.attributeNames.length, 5);
        assertEq(s.attributeNames[0], "revocation_id");
        assertEq(s.attributeNames[1], "studentName");
        assertEq(s.attributeNames[2], "university");
        assertEq(s.attributeNames[3], "degree");
        assertEq(s.attributeNames[4], "graduationYear");
    }

    function test_registerAndRead_holderBound() public {
        vm.prank(alice);
        bytes32 id = schemaRegistry.registerSchema("UniversityDegree", "1.0", true, _attributes());
        SchemaRegistry.Schema memory s = schemaRegistry.getSchema(id);

        assertEq(s.author, alice);
        assertTrue(s.holderBound);

        // revocation_id elöl, link_secret a végén
        assertEq(s.attributeNames.length, 6);
        assertEq(s.attributeNames[0], "revocation_id");
        assertEq(s.attributeNames[1], "studentName");
        assertEq(s.attributeNames[2], "university");
        assertEq(s.attributeNames[3], "degree");
        assertEq(s.attributeNames[4], "graduationYear");
        assertEq(s.attributeNames[5], "link_secret");
    }

    function test_schemaIdDerivation() public {
        vm.prank(alice);
        bytes32 id = schemaRegistry.registerSchema("UniversityDegree", "1.0", true, _attributes());
        assertEq(id, _expectedId(alice, "UniversityDegree", "1.0", true));
    }

    function test_emitsSchemaRegistered() public {
        bytes32 expected = _expectedId(alice, "UniversityDegree", "1.0", true);

        vm.expectEmit(true, true, false, true, address(schemaRegistry));
        emit SchemaRegistered(expected, alice, "UniversityDegree", "1.0", true);

        vm.prank(alice);
        schemaRegistry.registerSchema("UniversityDegree", "1.0", true, _attributes());
    }

    function test_existsAndIsHolderBound() public {
        bytes32 idFree = schemaRegistry.registerSchema("UniversityDegree", "1.0", false, _attributes());
        bytes32 idBound = schemaRegistry.registerSchema("UniversityDegree", "1.0", true, _attributes());

        assertTrue(schemaRegistry.exists(idFree));
        assertTrue(schemaRegistry.exists(idBound));
        assertFalse(schemaRegistry.exists(keccak256("nope")));

        assertFalse(schemaRegistry.isHolderBound(idFree));
        assertTrue(schemaRegistry.isHolderBound(idBound));
    }

    // ---------------------------------------------------------------------
    // Egyediség / ütközés
    // ---------------------------------------------------------------------

    function test_duplicateReverts() public {
        bytes32 id = schemaRegistry.registerSchema("UniversityDegree", "1.0", false, _attributes());

        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.SchemaExists.selector, id));
        schemaRegistry.registerSchema("UniversityDegree", "1.0", false, _attributes());
    }

    function test_duplicateReverts_evenWithDifferentAttributes() public {
        bytes32 id = schemaRegistry.registerSchema("UniversityDegree", "1.0", false, _attributes());

        string[] memory other = new string[](1);
        other[0] = "somethingElse";

        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.SchemaExists.selector, id));
        schemaRegistry.registerSchema("UniversityDegree", "1.0", false, other);
    }

    function test_holderBoundFlagGivesDistinctId() public {
        bytes32 idFree = schemaRegistry.registerSchema("UniversityDegree", "1.0", false, _attributes());
        bytes32 idBound = schemaRegistry.registerSchema("UniversityDegree", "1.0", true, _attributes());
        assertTrue(idFree != idBound);
    }

    function test_differentAuthorsGetDistinctIds() public {
        vm.prank(alice);
        bytes32 idAlice = schemaRegistry.registerSchema("UniversityDegree", "1.0", false, _attributes());
        vm.prank(bob);
        bytes32 idBob = schemaRegistry.registerSchema("UniversityDegree", "1.0", false, _attributes());

        assertTrue(idAlice != idBob);
        assertEq(schemaRegistry.getSchema(idAlice).author, alice);
        assertEq(schemaRegistry.getSchema(idBob).author, bob);
    }

    function test_differentVersionGetsDistinctId() public {
        bytes32 id1 = schemaRegistry.registerSchema("UniversityDegree", "1.0", false, _attributes());
        bytes32 id2 = schemaRegistry.registerSchema("UniversityDegree", "2.0", false, _attributes());
        assertTrue(id1 != id2);
    }

    // Regresszió: a régi abi.encodePacked alapú id-nál ("ab","c") és ("a","bc") ütközött.
    function test_noEncodePackedCollision() public {
        vm.startPrank(alice);
        bytes32 id1 = schemaRegistry.registerSchema("ab", "c", false, _attributes());
        bytes32 id2 = schemaRegistry.registerSchema("a", "bc", false, _attributes());
        vm.stopPrank();

        assertTrue(id1 != id2);
        assertEq(schemaRegistry.getSchema(id1).name, "ab");
        assertEq(schemaRegistry.getSchema(id1).version, "c");
        assertEq(schemaRegistry.getSchema(id2).name, "a");
        assertEq(schemaRegistry.getSchema(id2).version, "bc");
    }

    // ---------------------------------------------------------------------
    // Bemenet-validáció
    // ---------------------------------------------------------------------

    function test_emptyNameReverts() public {
        vm.expectRevert(SchemaRegistry.EmptyName.selector);
        schemaRegistry.registerSchema("", "1.0", false, _attributes());
    }

    function test_emptyVersionReverts() public {
        vm.expectRevert(SchemaRegistry.EmptyVersion.selector);
        schemaRegistry.registerSchema("UniversityDegree", "", false, _attributes());
    }

    function test_noAttributesReverts() public {
        string[] memory empty = new string[](0);
        vm.expectRevert(SchemaRegistry.NoAttributes.selector);
        schemaRegistry.registerSchema("UniversityDegree", "1.0", false, empty);
    }

    function test_emptyAttributeNameReverts() public {
        string[] memory attributes = _attributes();
        attributes[2] = "";
        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.EmptyAttributeName.selector, uint256(2)));
        schemaRegistry.registerSchema("UniversityDegree", "1.0", false, attributes);
    }

    function test_reservedRevocationIdReverts() public {
        string[] memory attributes = _attributes();
        attributes[1] = "revocation_id";
        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.ReservedAttributeName.selector, uint256(1)));
        schemaRegistry.registerSchema("UniversityDegree", "1.0", false, attributes);
    }

    function test_reservedLinkSecretReverts() public {
        string[] memory attributes = _attributes();
        attributes[3] = "link_secret";
        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.ReservedAttributeName.selector, uint256(3)));
        schemaRegistry.registerSchema("UniversityDegree", "1.0", true, attributes);
    }

    function test_reservedLinkSecretReverts_evenIfNotHolderBound() public {
        string[] memory attributes = _attributes();
        attributes[0] = "link_secret";
        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.ReservedAttributeName.selector, uint256(0)));
        schemaRegistry.registerSchema("UniversityDegree", "1.0", false, attributes);
    }

    function test_duplicateAttributeReverts() public {
        string[] memory attributes = _attributes();
        attributes[3] = "university"; // ugyanaz, mint az [1]
        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.DuplicateAttribute.selector, uint256(3)));
        schemaRegistry.registerSchema("UniversityDegree", "1.0", false, attributes);
    }

    // A foglalt-név ellenőrzés pontos (kis/nagybetű-érzékeny) egyezés. Ez szándékos:
    // a protokoll-mezőket a pozíciójuk azonosítja (revocation_id az első, link_secret
    // az utolsó), nem a nevük, így pl. "Revocation_ID" egy közönséges attribútum.
    function test_reservedNameCheckIsCaseSensitive() public {
        string[] memory attributes = new string[](2);
        attributes[0] = "Revocation_ID";
        attributes[1] = "LINK_SECRET";

        bytes32 id = schemaRegistry.registerSchema("UniversityDegree", "1.0", true, attributes);
        SchemaRegistry.Schema memory s = schemaRegistry.getSchema(id);

        assertEq(s.attributeNames.length, 4);
        assertEq(s.attributeNames[0], "revocation_id");
        assertEq(s.attributeNames[1], "Revocation_ID");
        assertEq(s.attributeNames[2], "LINK_SECRET");
        assertEq(s.attributeNames[3], "link_secret");
    }

    function _manyAttributes(uint256 n) internal pure returns (string[] memory attributes) {
        attributes = new string[](n);
        for (uint256 i = 0; i < n; i++) {
            attributes[i] = string.concat("attr_", vm.toString(i));
        }
    }

    function test_maxAttributesAccepted() public {
        bytes32 id = schemaRegistry.registerSchema("Big", "1.0", true, _manyAttributes(64));
        assertEq(schemaRegistry.getSchema(id).attributeNames.length, 64 + 2);
    }

    // Akkor kell visszakapcsolni, ha a TooManyAttributes limit visszakerül a szerződésbe.
    // function test_tooManyAttributesReverts() public {
    //     vm.expectRevert(SchemaRegistry.TooManyAttributes.selector);
    //     schemaRegistry.registerSchema("Big", "1.0", true, _manyAttributes(65));
    // }

    function test_failedRegistrationLeavesNoSchema() public {
        string[] memory attributes = _attributes();
        attributes[1] = "revocation_id";
        bytes32 id = _expectedId(address(this), "UniversityDegree", "1.0", false);

        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.ReservedAttributeName.selector, uint256(1)));
        schemaRegistry.registerSchema("UniversityDegree", "1.0", false, attributes);

        assertFalse(schemaRegistry.exists(id));
    }

    // ---------------------------------------------------------------------
    // Olvasás nem létező sémára
    // ---------------------------------------------------------------------

    function test_getUnknownSchemaReverts() public {
        bytes32 fakeId = keccak256("fake");
        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.UnknownSchema.selector, fakeId));
        schemaRegistry.getSchema(fakeId);
    }

    function test_isHolderBoundUnknownSchemaReverts() public {
        bytes32 fakeId = keccak256("fake");
        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.UnknownSchema.selector, fakeId));
        schemaRegistry.isHolderBound(fakeId);
    }

    // ---------------------------------------------------------------------
    // Megváltoztathatatlanság
    // ---------------------------------------------------------------------

    function test_immutability() public {
        bytes32 id = schemaRegistry.registerSchema("UniversityDegree", "1.0", true, _attributes());
        SchemaRegistry.Schema memory before = schemaRegistry.getSchema(id);

        // idő és blokk léptetés
        vm.warp(block.timestamp + 3600);
        vm.roll(block.number + 100);

        SchemaRegistry.Schema memory afterwards = schemaRegistry.getSchema(id);
        assertEq(keccak256(abi.encode(afterwards)), keccak256(abi.encode(before)));
        assertEq(afterwards.createdAt, before.createdAt);
    }

    // ---------------------------------------------------------------------
    // Fuzz
    // ---------------------------------------------------------------------

    function testFuzz_attributeLayout(address author, bool holderBound, uint8 count) public {
        uint256 n = bound(count, 1, 20);
        string[] memory attributes = _manyAttributes(n);

        vm.prank(author);
        bytes32 id = schemaRegistry.registerSchema("Fuzz", "1.0", holderBound, attributes);
        SchemaRegistry.Schema memory s = schemaRegistry.getSchema(id);

        assertEq(id, _expectedId(author, "Fuzz", "1.0", holderBound));
        assertEq(s.author, author);
        assertEq(s.holderBound, holderBound);
        assertEq(s.attributeNames.length, n + 1 + (holderBound ? 1 : 0));
        assertEq(s.attributeNames[0], "revocation_id");
        for (uint256 i = 0; i < n; i++) {
            assertEq(s.attributeNames[i + 1], attributes[i]);
        }
        if (holderBound) {
            assertEq(s.attributeNames[n + 1], "link_secret");
        }
    }
}
