pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EthereumDIDRegistry} from "ethr-did-registry/EthereumDIDRegistry.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {CredDefRegistry} from "../src/CredDefRegistry.sol";

contract CredDefRegistryTest is Test {
    EthereumDIDRegistry public didRegistry;
    SchemaRegistry public schemaRegistry;
    CredDefRegistry public credDefRegistry;

    address public alice = makeAddr("alice"); // kibocsátó (issuer DID)
    address public bob = makeAddr("bob");
    address public schemaAuthor = makeAddr("schemaAuthor");

    bytes32 public schemaId;
    bytes32 public constant KEY_ID = keccak256("alice#bbs-key-1");

    event CredDefRegistered(
        bytes32 indexed credDefId, address indexed issuer, bytes32 indexed schemaId, string tag, bytes32 keyId
    );

    function setUp() public {
        didRegistry = new EthereumDIDRegistry();
        schemaRegistry = new SchemaRegistry();
        credDefRegistry = new CredDefRegistry(address(didRegistry), address(schemaRegistry));

        string[] memory attributes = new string[](4);
        attributes[0] = "studentName";
        attributes[1] = "university";
        attributes[2] = "degree";
        attributes[3] = "graduationYear";

        // a sémát más regisztrálja, mint aki a creddef-et
        vm.prank(schemaAuthor);
        schemaId = schemaRegistry.registerSchema("UniversityDegree", "1.0", true, attributes);
    }

    function _register(address caller, address issuer, bytes32 sId, string memory tag, bytes32 keyId)
        internal
        returns (bytes32)
    {
        vm.prank(caller);
        return credDefRegistry.registerCredDef(issuer, sId, tag, keyId);
    }

    function _expectedId(address issuer, bytes32 sId, string memory tag) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(issuer, sId, tag));
    }

    // ---------------------------------------------------------------------
    // Konstruktor
    // ---------------------------------------------------------------------

    function test_constructorStoresRegistries() public view {
        assertEq(address(credDefRegistry.didRegistry()), address(didRegistry));
        assertEq(address(credDefRegistry.schemaRegistry()), address(schemaRegistry));
    }

    function test_constructorRejectsZeroAddresses() public {
        vm.expectRevert(CredDefRegistry.ZeroAddress.selector);
        new CredDefRegistry(address(0), address(schemaRegistry));

        vm.expectRevert(CredDefRegistry.ZeroAddress.selector);
        new CredDefRegistry(address(didRegistry), address(0));
    }

    // ---------------------------------------------------------------------
    // Sikeres regisztráció
    // ---------------------------------------------------------------------

    function test_registerAndRead() public {
        bytes32 id = _register(alice, alice, schemaId, "default", KEY_ID);
        CredDefRegistry.CredDef memory c = credDefRegistry.getCredDef(id);

        assertEq(c.issuer, alice);
        assertEq(c.schemaId, schemaId);
        assertEq(c.tag, "default");
        assertEq(c.keyId, KEY_ID);
        assertEq(c.createdAt, block.timestamp);
    }

    function test_credDefIdDerivation() public {
        bytes32 id = _register(alice, alice, schemaId, "default", KEY_ID);
        assertEq(id, _expectedId(alice, schemaId, "default"));
    }

    function test_emitsCredDefRegistered() public {
        bytes32 expected = _expectedId(alice, schemaId, "default");

        vm.expectEmit(true, true, true, true, address(credDefRegistry));
        emit CredDefRegistered(expected, alice, schemaId, "default", KEY_ID);

        _register(alice, alice, schemaId, "default", KEY_ID);
    }

    function test_existsAndIssuerOf() public {
        bytes32 id = _register(alice, alice, schemaId, "default", KEY_ID);

        assertTrue(credDefRegistry.exists(id));
        assertFalse(credDefRegistry.exists(keccak256("nope")));
        assertEq(credDefRegistry.issuerOf(id), alice);
    }

    function test_anyIssuerMayUseAnySchema() public {
        // a séma szerzője schemaAuthor, a creddef-et mégis alice regisztrálhatja
        bytes32 id = _register(alice, alice, schemaId, "default", KEY_ID);
        assertEq(credDefRegistry.issuerOf(id), alice);
        assertEq(schemaRegistry.getSchema(schemaId).author, schemaAuthor);
    }

    // ---------------------------------------------------------------------
    // DID-tulajdonos ellenőrzés
    // ---------------------------------------------------------------------

    function test_nonOwnerCallerReverts() public {
        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.NotDidOwner.selector, alice, bob));
        _register(bob, alice, schemaId, "default", KEY_ID);
    }

    function test_changedOwnerCanRegisterForIssuer() public {
        // alice átadja a DID-je tulajdonjogát bob-nak
        vm.prank(alice);
        didRegistry.changeOwner(alice, bob);

        bytes32 id = _register(bob, alice, schemaId, "default", KEY_ID);

        // a kibocsátó továbbra is a DID (alice), nem a hívó
        assertEq(credDefRegistry.issuerOf(id), alice);
        assertEq(id, _expectedId(alice, schemaId, "default"));
    }

    function test_previousOwnerLosesRightAfterChangeOwner() public {
        vm.prank(alice);
        didRegistry.changeOwner(alice, bob);

        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.NotDidOwner.selector, alice, alice));
        _register(alice, alice, schemaId, "default", KEY_ID);
    }

    // ERC-1056 delegate != owner: csak az aktuális tulajdonos regisztrálhat.
    function test_delegateCannotRegister() public {
        vm.prank(alice);
        didRegistry.addDelegate(alice, "sigAuth", bob, 1 days);
        assertTrue(didRegistry.validDelegate(alice, "sigAuth", bob));

        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.NotDidOwner.selector, alice, bob));
        _register(bob, alice, schemaId, "default", KEY_ID);
    }

    // Az indexerek az eventet olvassák: az issuer ott is a DID legyen, ne a hívó.
    function test_eventIssuerIsDidNotCallerAfterOwnerChange() public {
        vm.prank(alice);
        didRegistry.changeOwner(alice, bob);

        vm.expectEmit(true, true, true, true, address(credDefRegistry));
        emit CredDefRegistered(_expectedId(alice, schemaId, "default"), alice, schemaId, "default", KEY_ID);
        _register(bob, alice, schemaId, "default", KEY_ID);
    }

    // alice -> bob -> carol: mindig csak az aktuális tulajdonos jogosult.
    function test_chainedOwnerChange() public {
        address carol = makeAddr("carol");
        vm.prank(alice);
        didRegistry.changeOwner(alice, bob);
        vm.prank(bob);
        didRegistry.changeOwner(alice, carol);

        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.NotDidOwner.selector, alice, bob));
        _register(bob, alice, schemaId, "default", KEY_ID);

        bytes32 id = _register(carol, alice, schemaId, "default", KEY_ID);
        assertEq(credDefRegistry.issuerOf(id), alice);
    }

    function test_zeroIssuerReverts() public {
        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.NotDidOwner.selector, address(0), alice));
        _register(alice, address(0), schemaId, "default", KEY_ID);
    }

    function test_ownerCheckRunsBeforeInputValidation() public {
        // üres tag + rossz hívó: a modifier fut előbb, ezért NotDidOwner jön
        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.NotDidOwner.selector, alice, bob));
        _register(bob, alice, schemaId, "", KEY_ID);
    }

    // ---------------------------------------------------------------------
    // Bemenet-validáció
    // ---------------------------------------------------------------------

    function test_emptyTagReverts() public {
        vm.expectRevert(CredDefRegistry.EmptyTag.selector);
        _register(alice, alice, schemaId, "", KEY_ID);
    }

    function test_emptyKeyIdReverts() public {
        vm.expectRevert(CredDefRegistry.EmptyKeyId.selector);
        _register(alice, alice, schemaId, "default", bytes32(0));
    }

    function test_unknownSchemaReverts() public {
        bytes32 fakeSchema = keccak256("fake");
        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.UnknownSchema.selector, fakeSchema));
        _register(alice, alice, fakeSchema, "default", KEY_ID);
    }

    function test_failedRegistrationLeavesNoCredDef() public {
        vm.expectRevert(CredDefRegistry.EmptyKeyId.selector);
        _register(alice, alice, schemaId, "default", bytes32(0));

        assertFalse(credDefRegistry.exists(_expectedId(alice, schemaId, "default")));
    }

    // ---------------------------------------------------------------------
    // Egyediség / ütközés
    // ---------------------------------------------------------------------

    function test_duplicateReverts() public {
        bytes32 id = _register(alice, alice, schemaId, "default", KEY_ID);

        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.CredDefExists.selector, id));
        _register(alice, alice, schemaId, "default", KEY_ID);
    }

    function test_duplicateReverts_evenWithDifferentKeyId() public {
        bytes32 id = _register(alice, alice, schemaId, "default", KEY_ID);

        // kulcscsere nem írhatja felül a meglévő creddef-et
        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.CredDefExists.selector, id));
        _register(alice, alice, schemaId, "default", keccak256("alice#bbs-key-2"));

        assertEq(credDefRegistry.getCredDef(id).keyId, KEY_ID);
    }

    function test_duplicateReverts_afterOwnerChange() public {
        bytes32 id = _register(alice, alice, schemaId, "default", KEY_ID);

        vm.prank(alice);
        didRegistry.changeOwner(alice, bob);

        // az id az issuer DID-ből képződik, nem a hívóból, így az új tulajdonos sem regisztrálhatja újra
        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.CredDefExists.selector, id));
        _register(bob, alice, schemaId, "default", KEY_ID);
    }

    function test_differentTagGetsDistinctId() public {
        bytes32 id1 = _register(alice, alice, schemaId, "default", KEY_ID);
        bytes32 id2 = _register(alice, alice, schemaId, "v2", KEY_ID);
        assertTrue(id1 != id2);
    }

    function test_differentIssuersGetDistinctIds() public {
        bytes32 idAlice = _register(alice, alice, schemaId, "default", KEY_ID);
        bytes32 idBob = _register(bob, bob, schemaId, "default", KEY_ID);

        assertTrue(idAlice != idBob);
        assertEq(credDefRegistry.issuerOf(idAlice), alice);
        assertEq(credDefRegistry.issuerOf(idBob), bob);
    }

    function test_differentSchemaGetsDistinctId() public {
        string[] memory attributes = new string[](1);
        attributes[0] = "name";
        bytes32 otherSchema = schemaRegistry.registerSchema("Other", "1.0", false, attributes);

        bytes32 id1 = _register(alice, alice, schemaId, "default", KEY_ID);
        bytes32 id2 = _register(alice, alice, otherSchema, "default", KEY_ID);
        assertTrue(id1 != id2);
    }

    // ---------------------------------------------------------------------
    // Olvasás nem létező creddef-re
    // ---------------------------------------------------------------------

    function test_getUnknownCredDefReverts() public {
        bytes32 fakeId = keccak256("fake");
        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.UnknownCredDef.selector, fakeId));
        credDefRegistry.getCredDef(fakeId);
    }

    function test_issuerOfUnknownCredDefReverts() public {
        bytes32 fakeId = keccak256("fake");
        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.UnknownCredDef.selector, fakeId));
        credDefRegistry.issuerOf(fakeId);
    }

    // ---------------------------------------------------------------------
    // Megváltoztathatatlanság
    // ---------------------------------------------------------------------

    function test_immutability() public {
        bytes32 id = _register(alice, alice, schemaId, "default", KEY_ID);
        CredDefRegistry.CredDef memory before = credDefRegistry.getCredDef(id);

        // idő és blokk léptetés, DID tulajdonosváltás
        vm.warp(block.timestamp + 3600);
        vm.roll(block.number + 100);
        vm.prank(alice);
        didRegistry.changeOwner(alice, bob);

        CredDefRegistry.CredDef memory afterwards = credDefRegistry.getCredDef(id);
        assertEq(keccak256(abi.encode(afterwards)), keccak256(abi.encode(before)));
    }

    // ---------------------------------------------------------------------
    // Fuzz
    // ---------------------------------------------------------------------

    function testFuzz_registerAndRead(address issuer, string calldata tag, bytes32 keyId) public {
        vm.assume(issuer != address(0));
        vm.assume(bytes(tag).length > 0);
        vm.assume(keyId != bytes32(0));

        bytes32 id = _register(issuer, issuer, schemaId, tag, keyId);
        CredDefRegistry.CredDef memory c = credDefRegistry.getCredDef(id);

        assertEq(id, _expectedId(issuer, schemaId, tag));
        assertEq(c.issuer, issuer);
        assertEq(c.schemaId, schemaId);
        assertEq(c.tag, tag);
        assertEq(c.keyId, keyId);
    }

    function testFuzz_nonOwnerAlwaysReverts(address caller) public {
        vm.assume(caller != alice);

        vm.expectRevert(abi.encodeWithSelector(CredDefRegistry.NotDidOwner.selector, alice, caller));
        _register(caller, alice, schemaId, "default", KEY_ID);
    }
}
