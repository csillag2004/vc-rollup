pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EthereumDIDRegistry} from "ethr-did-registry/EthereumDIDRegistry.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {CredDefRegistry} from "../src/CredDefRegistry.sol";
import {StateRegistry} from "../src/StateRegistry.sol";

contract StateRegistryTest is Test {
    EthereumDIDRegistry public didRegistry;
    SchemaRegistry public schemaRegistry;
    CredDefRegistry public credDefRegistry;
    StateRegistry public registry;

    address public alice = makeAddr("alice"); // kibocsátó (issuer DID)
    address public bob = makeAddr("bob");
    address public carol = makeAddr("carol"); // csoport létrehozó

    bytes32 public schemaId;
    bytes32 public credDefId;
    bytes32 public regId; // a setUp-ban létrehozott, inicializált (SRS-sel rendelkező) registry

    // A szerződés csak a pontok hosszát ellenőrzi, ezért elég determinisztikus álpontokkal tesztelni.
    bytes public v0;
    bytes public qTilde;
    bytes public q;

    bytes public constant G1_GEN =
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes public constant G2_GEN =
        hex"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

    uint32 public constant SRS_DEGREE = 4;

    // rendezett revocation id-k a csoportokhoz
    bytes32 public constant Y1 = bytes32(uint256(0x11));
    bytes32 public constant Y2 = bytes32(uint256(0x22));
    bytes32 public constant Y3 = bytes32(uint256(0x33));
    bytes32 public constant DIGEST = keccak256("guard");
    bytes32 public constant LABEL = keccak256("label");   // registry és csoport címke
    bytes32 public constant LABEL2 = keccak256("label2"); // második partíció ugyanahhoz a CredDefhez

    event RegistryCreated(bytes32 indexed registryId, bytes32 indexed credDefId, bytes32 label, bytes V0, bytes Qtilde, bytes Q);
    event SrsPublished(bytes32 indexed registryId, uint32 degree, bytes32 srsHash, bytes[] g1Powers, bytes[] g2Powers);
    event Issued(bytes32 indexed registryId, uint64 indexed version, bytes newI, bytes newWIR, bytes32 guardDigest);
    event Revoked(bytes32 indexed registryId, uint64 indexed version, bytes32 indexed y, bytes newA, bytes newRtilde, bytes newWIR, bytes32 guardDigest);
    event GroupCreated(bytes32 indexed groupId, bytes32 indexed registryId, address indexed creator, bytes32 label, bytes32[] members);

    function setUp() public {
        didRegistry = new EthereumDIDRegistry();
        schemaRegistry = new SchemaRegistry();
        credDefRegistry = new CredDefRegistry(address(didRegistry), address(schemaRegistry));

        string[] memory attributes = new string[](2);
        attributes[0] = "studentName";
        attributes[1] = "degree";
        schemaId = schemaRegistry.registerSchema("UniversityDegree", "1.0", true, attributes);

        vm.prank(alice);
        credDefId = credDefRegistry.registerCredDef(alice, schemaId, "default", keccak256("alice#bbs-key-1"));

        v0 = _g1("V0");
        qTilde = _g2("Qtilde");
        q = _g1("Q");

        registry = new StateRegistry(address(credDefRegistry));
        regId = _createRegistry(LABEL, q);
        _publishSrs(regId, SRS_DEGREE, q);
    }

    // ---------------------------------------------------------------------
    // Segédfüggvények
    // ---------------------------------------------------------------------

    function _g1(bytes memory seed) internal pure returns (bytes memory) {
        return bytes.concat(keccak256(abi.encode(seed, 1)), bytes16(keccak256(abi.encode(seed, 2))));
    }

    function _g2(bytes memory seed) internal pure returns (bytes memory) {
        return bytes.concat(keccak256(abi.encode(seed, 1)), keccak256(abi.encode(seed, 2)), keccak256(abi.encode(seed, 3)));
    }

    function _createRegistry(bytes32 label, bytes memory _q) internal returns (bytes32) {
        vm.prank(alice);
        return registry.createRegistry(credDefId, label, v0, qTilde, _q);
    }

    // Érvényes SRS: [g, g^α, g^α², ...], ahol g^α = Q (ha meg van adva) és g̃^α = Q̃.
    function _srs(uint256 degree, bytes memory _q) internal view returns (bytes[] memory g1, bytes[] memory g2) {
        g1 = new bytes[](degree + 1);
        g2 = new bytes[](degree + 1);
        g1[0] = G1_GEN;
        g2[0] = G2_GEN;
        g1[1] = _q.length != 0 ? _q : _g1("tau^1");
        g2[1] = qTilde;
        for (uint256 i = 2; i <= degree; i++) {
            g1[i] = _g1(abi.encode("g1", i));
            g2[i] = _g2(abi.encode("g2", i));
        }
    }

    function _publishSrs(bytes32 id, uint256 degree, bytes memory _q) internal {
        (bytes[] memory g1, bytes[] memory g2) = _srs(degree, _q);
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);
    }

    // Egy SRS nélküli, friss partíció ugyanazon a CredDefen.
    function _freshRegistry() internal returns (bytes32) {
        return _createRegistry(LABEL2, q);
    }

    function _one(bytes32 a) internal pure returns (bytes32[] memory arr) {
        arr = new bytes32[](1);
        arr[0] = a;
    }

    function _pair(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory arr) {
        arr = new bytes32[](2);
        arr[0] = a;
        arr[1] = b;
    }

    function _triple(bytes32 a, bytes32 b, bytes32 c) internal pure returns (bytes32[] memory arr) {
        arr = new bytes32[](3);
        arr[0] = a;
        arr[1] = b;
        arr[2] = c;
    }

    function _version(bytes32 id) internal view returns (uint64 v) {
        (,,,, v) = registry.getValues(id);
    }

    function _issue(bytes32 id, bytes32 tag) internal {
        vm.prank(alice);
        registry.issueUpdate(id, _g1(abi.encode("I", tag)), _g1(abi.encode("WIR-i", tag)));
    }

    function _guardedIssue(bytes32 id, uint64 expectedVersion, bytes32 tag) internal {
        vm.prank(alice);
        registry.guardedIssueUpdate(id, expectedVersion, _g1(abi.encode("I", tag)), _g1(abi.encode("WIR-i", tag)), DIGEST);
    }

    function _revoke(bytes32 id, bytes32 y) internal {
        vm.prank(alice);
        registry.revoke(id, y, _g1(abi.encode("A", y)), _g2(abi.encode("R", y)), _g1(abi.encode("WIR-r", y)));
    }

    function _guardedRevoke(bytes32 id, uint64 expectedVersion, bytes32 y) internal {
        vm.prank(alice);
        registry.guardedRevoke(
            id, expectedVersion, y, _g1(abi.encode("A", y)), _g2(abi.encode("R", y)), _g1(abi.encode("WIR-r", y)), DIGEST
        );
    }

    function _narrowedRevoke(bytes32 groupId, uint64 expectedVersion, uint64 expectedGroupVersion, bytes32 y) internal {
        vm.prank(alice);
        registry.guardedRevokeNarrowed(
            groupId,
            expectedVersion,
            expectedGroupVersion,
            y,
            _g1(abi.encode("A", y)),
            _g2(abi.encode("R", y)),
            _g1(abi.encode("WIR-r", y)),
            DIGEST
        );
    }

    function _createGroup(bytes32 id, bytes32[] memory members) internal returns (bytes32) {
        vm.prank(carol);
        return registry.createGroup(id, LABEL, members);
    }

    // ---------------------------------------------------------------------
    // Konstruktor
    // ---------------------------------------------------------------------

    function test_constructorStoresRegistries() public view {
        assertEq(address(registry.credDefRegistry()), address(credDefRegistry));
        assertEq(address(registry.didRegistry()), address(didRegistry));
    }

    function test_constructorRejectsZeroAddress() public {
        vm.expectRevert(StateRegistry.ZeroAddress.selector);
        new StateRegistry(address(0));
    }

    function test_generatorConstants() public view {
        assertEq(registry.G1_GENERATOR(), G1_GEN);
        assertEq(registry.G2_GENERATOR(), G2_GEN);
        assertEq(G1_GEN.length, 48);
        assertEq(G2_GEN.length, 96);
    }

    // ---------------------------------------------------------------------
    // Registry létrehozás
    // ---------------------------------------------------------------------

    function test_createRegistry() public {
        bytes32 expectedId = keccak256(abi.encode(credDefId, LABEL2));

        vm.expectEmit(true, true, true, true, address(registry));
        emit RegistryCreated(expectedId, credDefId, LABEL2, v0, qTilde, q);
        bytes32 id = _createRegistry(LABEL2, q);

        assertEq(id, expectedId);
        assertEq(registry.registryIdOf(credDefId, LABEL2), id);
        assertTrue(registry.exists(id));

        StateRegistry.Registry memory r = registry.getRegistry(id);
        assertEq(r.credDefId, credDefId);
        assertEq(r.label, LABEL2);
        assertEq(r.V0, v0);
        assertEq(r.Qtilde, qTilde);
        assertEq(r.Q, q);
        assertEq(r.A, v0);
        assertEq(r.Rtilde, G2_GEN);
        assertEq(r.I, G1_GEN);
        assertEq(r.WIR, G1_GEN);
        assertEq(r.version, 0);
        assertEq(r.srsHash, bytes32(0));
        assertEq(r.srsDegree, 0);
        assertEq(r.createdAt, block.timestamp);

        assertEq(registry.valuesHashAt(id, 0), keccak256(abi.encode(v0, G2_GEN, G1_GEN)));
    }

    function test_registriesOfListsPartitionsInOrder() public {
        bytes32 id2 = _createRegistry(LABEL2, q);
        assertEq(registry.registriesOf(credDefId), _pair(regId, id2));
        assertEq(registry.registriesOf(keccak256("other")).length, 0);
    }

    function test_createRegistryTwiceReverts() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.RegistryExists.selector, regId));
        _createRegistry(LABEL, q);
    }

    function test_createRegistryUnknownCredDefReverts() public {
        bytes32 fake = keccak256("fake");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownCredDef.selector, fake));
        vm.prank(alice);
        registry.createRegistry(fake, LABEL, v0, qTilde, q);
    }

    function test_createRegistryNotIssuerReverts() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        vm.prank(bob);
        registry.createRegistry(credDefId, LABEL2, v0, qTilde, q);
    }

    function test_createRegistryFollowsIssuerDidOwner() public {
        vm.prank(alice);
        didRegistry.changeOwner(alice, bob);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, alice));
        vm.prank(alice);
        registry.createRegistry(credDefId, LABEL2, v0, qTilde, q);

        vm.prank(bob);
        bytes32 id = registry.createRegistry(credDefId, LABEL2, v0, qTilde, q);
        assertTrue(registry.exists(id));
    }

    function test_createRegistryBadPointLengthsReverts() public {
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(96)));
        registry.createRegistry(credDefId, LABEL2, _g2("V0"), qTilde, q);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG2Length.selector, uint256(48)));
        registry.createRegistry(credDefId, LABEL2, v0, _g1("Qtilde"), q);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(1)));
        registry.createRegistry(credDefId, LABEL2, v0, qTilde, hex"01");
        vm.stopPrank();

        assertFalse(registry.exists(registry.registryIdOf(credDefId, LABEL2)));
    }

    function test_createRegistryAcceptsEmptyQ() public {
        bytes32 id = _createRegistry(LABEL2, "");
        assertEq(registry.getRegistry(id).Q.length, 0);
    }

    function test_unknownRegistryReadsRevert() public {
        bytes32 id = keccak256("no-such-registry");
        assertFalse(registry.exists(id));
        assertEq(registry.valuesHashAt(id, 0), bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownRegistry.selector, id));
        registry.getRegistry(id);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownRegistry.selector, id));
        registry.getValues(id);
    }

    // ---------------------------------------------------------------------
    // SRS publikálás
    // ---------------------------------------------------------------------

    function test_publishSrs() public {
        bytes32 id = _freshRegistry();
        (bytes[] memory g1, bytes[] memory g2) = _srs(3, q);
        bytes32 h = keccak256(abi.encode(g1, g2));

        vm.expectEmit(true, true, true, true, address(registry));
        emit SrsPublished(id, 3, h, g1, g2);
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);

        StateRegistry.Registry memory r = registry.getRegistry(id);
        assertEq(r.srsHash, h);
        assertEq(r.srsDegree, 3);
        // az SRS nem lépteti a versiont
        assertEq(r.version, 0);
    }

    function test_setUpPublishedSrs() public view {
        StateRegistry.Registry memory r = registry.getRegistry(regId);
        assertTrue(r.srsHash != bytes32(0));
        assertEq(r.srsDegree, SRS_DEGREE);
    }

    // Az SRS partíciónként külön van: a másik registry nem kapja meg.
    function test_publishSrsIsPerRegistry() public {
        bytes32 id = _freshRegistry();
        assertEq(registry.getRegistry(id).srsHash, bytes32(0));
    }

    function test_publishSrsOnlyIssuer() public {
        bytes32 id = _freshRegistry();
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, q);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        vm.prank(bob);
        registry.publishSrs(id, g1, g2);
    }

    function test_publishSrsUnknownRegistryReverts() public {
        bytes32 id = keccak256("no-such-registry");
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, q);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownRegistry.selector, id));
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);
    }

    function test_publishSrsTwiceReverts() public {
        (bytes[] memory g1, bytes[] memory g2) = _srs(SRS_DEGREE, q);
        vm.expectRevert(StateRegistry.SrsAlreadyPublished.selector);
        vm.prank(alice);
        registry.publishSrs(regId, g1, g2);
    }

    function test_publishSrsTooShortReverts() public {
        bytes32 id = _freshRegistry();
        bytes[] memory g1 = new bytes[](1);
        bytes[] memory g2 = new bytes[](1);
        g1[0] = G1_GEN;
        g2[0] = G2_GEN;

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadSrsLength.selector, uint256(1), uint256(1)));
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);
    }

    function test_publishSrsLengthMismatchReverts() public {
        bytes32 id = _freshRegistry();
        (bytes[] memory g1,) = _srs(2, q);
        (, bytes[] memory g2) = _srs(1, q);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadSrsLength.selector, uint256(3), uint256(2)));
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);
    }

    function test_publishSrsBadPointLengthReverts() public {
        bytes32 id = _freshRegistry();
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, q);

        g1[2] = hex"01";
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(1)));
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);

        (g1, g2) = _srs(2, q);
        g2[2] = _g1("not-g2");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG2Length.selector, uint256(48)));
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);
    }

    function test_publishSrsGeneratorMismatchReverts() public {
        bytes32 id = _freshRegistry();
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, q);

        g1[0] = _g1("fake-g");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.SrsMismatch.selector, uint256(0)));
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);

        (g1, g2) = _srs(2, q);
        g2[0] = _g2("fake-g~");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.SrsMismatch.selector, uint256(0)));
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);
    }

    function test_publishSrsKeyMismatchReverts() public {
        bytes32 id = _freshRegistry();
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, q);

        g2[1] = _g2("fake-Qtilde");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.SrsMismatch.selector, uint256(1)));
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);

        (g1, g2) = _srs(2, q);
        g1[1] = _g1("fake-Q");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.SrsMismatch.selector, uint256(1)));
        vm.prank(alice);
        registry.publishSrs(id, g1, g2);
    }

    // Ha Q nincs megadva, g1Powers[1] tetszőleges lehet.
    function test_publishSrsWithoutQ() public {
        bytes32 id = _createRegistry(LABEL2, "");
        _publishSrs(id, 2, "");
        assertEq(registry.getRegistry(id).srsDegree, 2);
    }

    function test_issueUpdateBeforeSrsReverts() public {
        bytes32 id = _freshRegistry();
        vm.expectRevert(StateRegistry.SrsNotPublished.selector);
        vm.prank(alice);
        registry.issueUpdate(id, _g1("I"), _g1("WIR"));
    }

    function test_createGroupBeforeSrsReverts() public {
        bytes32 id = _freshRegistry();
        vm.expectRevert(StateRegistry.SrsNotPublished.selector);
        vm.prank(carol);
        registry.createGroup(id, LABEL, _one(Y1));
    }

    // ---------------------------------------------------------------------
    // Kiadás (issueUpdate)
    // ---------------------------------------------------------------------

    function test_issueUpdate() public {
        bytes memory newI = _g1("I1");
        bytes memory newWIR = _g1("WIR1");

        vm.expectEmit(true, true, true, true, address(registry));
        emit Issued(regId, 1, newI, newWIR, bytes32(0));
        vm.prank(alice);
        registry.issueUpdate(regId, newI, newWIR);

        (bytes memory a, bytes memory r, bytes memory i, bytes memory w, uint64 v) = registry.getValues(regId);
        assertEq(v, 1);
        assertEq(i, newI);
        assertEq(w, newWIR);
        // a kiadás A-t és R̃-t nem érinti
        assertEq(a, v0);
        assertEq(r, G2_GEN);
        assertEq(registry.valuesHashAt(regId, 1), keccak256(abi.encode(v0, G2_GEN, newI)));
    }

    function test_issueUpdateSequentialVersions() public {
        _issue(regId, "1");
        _issue(regId, "2");

        assertEq(_version(regId), 2);
        assertTrue(registry.valuesHashAt(regId, 1) != registry.valuesHashAt(regId, 2));
    }

    function test_issueUpdateOnlyIssuer() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        vm.prank(bob);
        registry.issueUpdate(regId, _g1("I"), _g1("WIR"));
    }

    function test_issueUpdateUnknownRegistryReverts() public {
        bytes32 id = keccak256("no-such-registry");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownRegistry.selector, id));
        vm.prank(alice);
        registry.issueUpdate(id, _g1("I"), _g1("WIR"));
    }

    function test_issueUpdateBadPointLengthReverts() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(96)));
        vm.prank(alice);
        registry.issueUpdate(regId, _g2("I"), _g1("WIR"));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(0)));
        vm.prank(alice);
        registry.issueUpdate(regId, _g1("I"), "");

        assertEq(_version(regId), 0);
    }

    // ---------------------------------------------------------------------
    // Őrzött kiadás
    // ---------------------------------------------------------------------

    function test_guardedIssueUpdate() public {
        _revoke(regId, Y1);
        uint64 v = _version(regId);
        (bytes memory aBefore, bytes memory rBefore,,,) = registry.getValues(regId);
        bytes memory newI = _g1(abi.encode("I", bytes32("1")));
        bytes memory newWIR = _g1(abi.encode("WIR-i", bytes32("1")));

        vm.expectEmit(true, true, true, true, address(registry));
        emit Issued(regId, v + 1, newI, newWIR, DIGEST);
        _guardedIssue(regId, v, "1");

        (bytes memory a, bytes memory r, bytes memory i, bytes memory w, uint64 vAfter) = registry.getValues(regId);
        assertEq(vAfter, v + 1);
        assertEq(i, newI);
        assertEq(w, newWIR);
        // a kiadás A-t és R̃-t nem érinti
        assertEq(a, aBefore);
        assertEq(r, rBefore);
        assertEq(registry.valuesHashAt(regId, v + 1), keccak256(abi.encode(aBefore, rBefore, newI)));
    }

    function test_guardedIssueUpdateStaleVersionReverts() public {
        _issue(regId, "1");
        uint64 v = _version(regId);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v - 1, v));
        _guardedIssue(regId, v - 1, "2");

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v + 1, v));
        _guardedIssue(regId, v + 1, "2");

        assertEq(_version(regId), v);
    }

    // Két kiadás ugyanarra a versionre: a második már elavult állapotra hivatkozik.
    function test_guardedIssueUpdateStaleAfterOtherIssuance() public {
        uint64 v = _version(regId);
        _guardedIssue(regId, v, "1");

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v, v + 1));
        _guardedIssue(regId, v, "2");

        _guardedIssue(regId, v + 1, "2");
        assertEq(_version(regId), v + 2);
    }

    // A revokálás is lépteti a versiont, így az őrzött kiadást is érvényteleníti.
    function test_guardedIssueUpdateStaleAfterRevocation() public {
        uint64 v = _version(regId);
        _revoke(regId, Y1);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v, v + 1));
        _guardedIssue(regId, v, "1");
    }

    function test_guardedIssueUpdateOnlyIssuer() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        vm.prank(bob);
        registry.guardedIssueUpdate(regId, 0, _g1("I"), _g1("WIR"), DIGEST);
    }

    function test_guardedIssueUpdateUnknownRegistryReverts() public {
        bytes32 id = keccak256("no-such-registry");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownRegistry.selector, id));
        _guardedIssue(id, 0, "1");
    }

    function test_guardedIssueUpdateBeforeSrsReverts() public {
        bytes32 id = _freshRegistry();
        vm.expectRevert(StateRegistry.SrsNotPublished.selector);
        _guardedIssue(id, 0, "1");
    }

    function test_guardedIssueUpdateBadPointLengthReverts() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(96)));
        vm.prank(alice);
        registry.guardedIssueUpdate(regId, 0, _g2("I"), _g1("WIR"), DIGEST);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(0)));
        vm.prank(alice);
        registry.guardedIssueUpdate(regId, 0, _g1("I"), "", DIGEST);

        assertEq(_version(regId), 0);
    }

    // ---------------------------------------------------------------------
    // Feltétel nélküli revokálás
    // ---------------------------------------------------------------------

    function test_revoke() public {
        _issue(regId, "1");
        (,, bytes memory iBefore,,) = registry.getValues(regId);
        bytes memory newA = _g1("A1");
        bytes memory newR = _g2("R1");
        bytes memory newWIR = _g1("WIR-r1");

        vm.expectEmit(true, true, true, true, address(registry));
        emit Revoked(regId, 2, Y1, newA, newR, newWIR, bytes32(0));
        vm.prank(alice);
        registry.revoke(regId, Y1, newA, newR, newWIR);

        (bytes memory a, bytes memory r, bytes memory i, bytes memory w, uint64 v) = registry.getValues(regId);
        assertEq(v, 2);
        assertEq(a, newA);
        assertEq(r, newR);
        assertEq(w, newWIR);
        assertEq(i, iBefore); // a revokálás I-t nem érinti
        assertEq(registry.valuesHashAt(regId, 2), keccak256(abi.encode(newA, newR, iBefore)));

        assertTrue(registry.isRevoked(regId, Y1));
        assertFalse(registry.isRevoked(regId, Y2));
        assertEq(registry.revokedAt(regId, Y1), 2);
        assertEq(registry.revokedAt(regId, Y2), 0);
        assertEq(registry.revokedCount(regId), 1);
        assertEq(registry.getRevokedLog(regId, 0, 1), _one(Y1));
    }

    function test_revokeOnlyIssuer() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        vm.prank(bob);
        registry.revoke(regId, Y1, _g1("A"), _g2("R"), _g1("W"));
    }

    function test_revokeUnknownRegistryReverts() public {
        bytes32 id = keccak256("no-such-registry");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownRegistry.selector, id));
        vm.prank(alice);
        registry.revoke(id, Y1, _g1("A"), _g2("R"), _g1("W"));
    }

    function test_revokeZeroYReverts() public {
        vm.expectRevert(StateRegistry.EmptyRevocationId.selector);
        _revoke(regId, bytes32(0));
    }

    function test_revokeTwiceReverts() public {
        _revoke(regId, Y1);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.AlreadyRevoked.selector, Y1));
        _revoke(regId, Y1);

        assertEq(registry.revokedCount(regId), 1);
        assertEq(registry.revokedAt(regId, Y1), 1);
    }

    function test_revokeBadPointLengthReverts() public {
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(96)));
        registry.revoke(regId, Y1, _g2("A"), _g2("R"), _g1("W"));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG2Length.selector, uint256(48)));
        registry.revoke(regId, Y1, _g1("A"), _g1("R"), _g1("W"));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(96)));
        registry.revoke(regId, Y1, _g1("A"), _g2("R"), _g2("W"));
        vm.stopPrank();

        assertFalse(registry.isRevoked(regId, Y1));
        assertEq(_version(regId), 0);
    }

    // Ugyanaz az y két partícióban egymástól függetlenül revokálható.
    function test_revocationIsPerRegistry() public {
        bytes32 id2 = _freshRegistry();
        _revoke(regId, Y1);

        assertTrue(registry.isRevoked(regId, Y1));
        assertFalse(registry.isRevoked(id2, Y1));
        assertEq(_version(id2), 0);
        assertEq(registry.revokedCount(id2), 0);

        _revoke(id2, Y1);
        assertTrue(registry.isRevoked(id2, Y1));
        assertEq(registry.revokedAt(id2, Y1), 1);
    }

    // ---------------------------------------------------------------------
    // Őrzött (globális) revokálás
    // ---------------------------------------------------------------------

    function test_guardedRevoke() public {
        _issue(regId, "1");
        uint64 v = _version(regId);

        vm.expectEmit(true, true, true, true, address(registry));
        emit Revoked(regId, v + 1, Y1, _g1(abi.encode("A", Y1)), _g2(abi.encode("R", Y1)), _g1(abi.encode("WIR-r", Y1)), DIGEST);
        _guardedRevoke(regId, v, Y1);

        assertTrue(registry.isRevoked(regId, Y1));
        assertEq(_version(regId), v + 1);
    }

    function test_guardedRevokeStaleVersionReverts() public {
        _issue(regId, "1");
        uint64 v = _version(regId);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v - 1, v));
        _guardedRevoke(regId, v - 1, Y1);
    }

    // Két kérelem ugyanarra a versionre: a második már elavult állapotra hivatkozik.
    function test_guardedRevokeStaleAfterOtherRevocation() public {
        uint64 v = _version(regId);
        _guardedRevoke(regId, v, Y1);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v, v + 1));
        _guardedRevoke(regId, v, Y2);

        _guardedRevoke(regId, v + 1, Y2);
        assertTrue(registry.isRevoked(regId, Y2));
    }

    // A kiadás is lépteti a versiont, így az őrzött revokálást is érvényteleníti.
    function test_guardedRevokeStaleAfterIssuance() public {
        uint64 v = _version(regId);
        _issue(regId, "1");

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v, v + 1));
        _guardedRevoke(regId, v, Y1);
    }

    function test_guardedRevokeOnlyIssuer() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        vm.prank(bob);
        registry.guardedRevoke(regId, 0, Y1, _g1("A"), _g2("R"), _g1("W"), DIGEST);
    }

    // ---------------------------------------------------------------------
    // Csoportra szűkített őrzött revokálás
    // ---------------------------------------------------------------------

    function test_guardedRevokeNarrowed() public {
        bytes32 g = _createGroup(regId, _pair(Y1, Y2));
        uint64 v = _version(regId);
        assertEq(registry.groupVersion(g), 0);

        vm.expectEmit(true, true, true, true, address(registry));
        emit Revoked(regId, v + 1, Y1, _g1(abi.encode("A", Y1)), _g2(abi.encode("R", Y1)), _g1(abi.encode("WIR-r", Y1)), DIGEST);
        _narrowedRevoke(g, v, 0, Y1);

        assertTrue(registry.isRevoked(regId, Y1));
        assertEq(_version(regId), v + 1);
        assertEq(registry.groupVersion(g), 1);
    }

    function test_guardedRevokeNarrowedUnknownGroupReverts() public {
        bytes32 g = keccak256("no-such-group");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownGroup.selector, g));
        _narrowedRevoke(g, 0, 0, Y1);
    }

    function test_guardedRevokeNarrowedOnlyIssuer() public {
        bytes32 g = _createGroup(regId, _one(Y1));
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        vm.prank(bob);
        registry.guardedRevokeNarrowed(g, 0, 0, Y1, _g1("A"), _g2("R"), _g1("W"), DIGEST);
    }

    function test_guardedRevokeNarrowedStaleVersionReverts() public {
        bytes32 g = _createGroup(regId, _one(Y1));
        uint64 v = _version(regId);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v + 1, v));
        _narrowedRevoke(g, v + 1, 0, Y1);
    }

    function test_guardedRevokeNarrowedStaleGroupVersionReverts() public {
        bytes32 g = _createGroup(regId, _pair(Y1, Y2));

        // egy másik csoporttag revokálása lépteti a csoport versionjét
        _revoke(regId, Y2);
        uint64 v = _version(regId);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleGroupVersion.selector, g, uint64(0), uint64(1)));
        _narrowedRevoke(g, v, 0, Y1);

        _narrowedRevoke(g, v, 1, Y1);
        assertTrue(registry.isRevoked(regId, Y1));
    }

    // Csoporton kívüli revokálás a globális versiont lépteti, a csoportét nem.
    function test_guardedRevokeNarrowedIgnoresNonMemberRevocation() public {
        bytes32 g = _createGroup(regId, _pair(Y1, Y2));
        _revoke(regId, Y3);

        assertEq(registry.groupVersion(g), 0);
        _narrowedRevoke(g, _version(regId), 0, Y1);
        assertTrue(registry.isRevoked(regId, Y1));
    }

    // A csoport a saját registryjében revokál, nem egy másikban.
    function test_guardedRevokeNarrowedTargetsGroupRegistry() public {
        bytes32 id2 = _freshRegistry();
        _publishSrs(id2, SRS_DEGREE, q);
        _issue(regId, "1"); // a két registry versionje eltér

        bytes32 g = _createGroup(id2, _one(Y1));
        _narrowedRevoke(g, _version(id2), 0, Y1);

        assertTrue(registry.isRevoked(id2, Y1));
        assertFalse(registry.isRevoked(regId, Y1));
        assertEq(_version(id2), 1);
        assertEq(_version(regId), 1);
    }

    // ---------------------------------------------------------------------
    // Csoportok
    // ---------------------------------------------------------------------

    function test_createGroup() public {
        bytes32[] memory members = _triple(Y1, Y2, Y3);
        bytes32 expectedId = keccak256(abi.encode(regId, carol, LABEL));

        vm.expectEmit(true, true, true, true, address(registry));
        emit GroupCreated(expectedId, regId, carol, LABEL, members);
        bytes32 g = _createGroup(regId, members);

        assertEq(g, expectedId);
        (bytes32 rid, address creator, uint256 createdAt, bytes32[] memory stored) = registry.getGroup(g);
        assertEq(rid, regId);
        assertEq(creator, carol);
        assertEq(createdAt, block.timestamp);
        assertEq(stored, members);
        assertEq(registry.groupVersion(g), 0);
    }

    function test_createGroupUnknownRegistryReverts() public {
        vm.expectRevert(StateRegistry.SrsNotPublished.selector);
        _createGroup(keccak256("no-such-registry"), _one(Y1));
    }

    function test_createGroupEmptyReverts() public {
        vm.expectRevert(StateRegistry.EmptyGroup.selector);
        _createGroup(regId, new bytes32[](0));
    }

    function test_createGroupSizeBoundedBySrs() public {
        bytes32[] memory members = new bytes32[](SRS_DEGREE + 1);
        for (uint256 i = 0; i < members.length; i++) {
            members[i] = bytes32(i + 1);
        }

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GroupTooLarge.selector, members.length, SRS_DEGREE));
        _createGroup(regId, members);

        // pontosan SRS_DEGREE tag még belefér
        assembly {
            mstore(members, sub(mload(members), 1))
        }
        bytes32 g = _createGroup(regId, members);
        (,,, bytes32[] memory stored) = registry.getGroup(g);
        assertEq(stored.length, SRS_DEGREE);
    }

    function test_createGroupDuplicateReverts() public {
        bytes32 g = _createGroup(regId, _one(Y1));
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GroupExists.selector, g));
        _createGroup(regId, _one(Y2));
    }

    function test_sameLabelDifferentCreatorGetsDistinctGroup() public {
        bytes32 g1 = _createGroup(regId, _one(Y1));
        vm.prank(bob);
        bytes32 g2 = registry.createGroup(regId, LABEL, _one(Y1));

        assertTrue(g1 != g2);
        (, address creator,,) = registry.getGroup(g2);
        assertEq(creator, bob);
    }

    function test_sameLabelDifferentRegistryGetsDistinctGroup() public {
        bytes32 id2 = _freshRegistry();
        _publishSrs(id2, SRS_DEGREE, q);

        bytes32 g1 = _createGroup(regId, _one(Y1));
        bytes32 g2 = _createGroup(id2, _one(Y1));

        assertTrue(g1 != g2);
        (bytes32 rid,,,) = registry.getGroup(g2);
        assertEq(rid, id2);
    }

    function test_createGroupZeroMemberReverts() public {
        vm.expectRevert(StateRegistry.EmptyRevocationId.selector);
        _createGroup(regId, _pair(bytes32(0), Y1));
    }

    function test_createGroupUnsortedReverts() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.MembersNotSorted.selector, uint256(1)));
        _createGroup(regId, _pair(Y2, Y1));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.MembersNotSorted.selector, uint256(2)));
        _createGroup(regId, _triple(Y1, Y3, Y2));
    }

    function test_createGroupDuplicateMemberReverts() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.MembersNotSorted.selector, uint256(1)));
        _createGroup(regId, _pair(Y1, Y1));
    }

    function test_unknownGroupReadsRevert() public {
        bytes32 g = keccak256("no-such-group");

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownGroup.selector, g));
        registry.getGroup(g);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownGroup.selector, g));
        registry.groupVersion(g);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownGroup.selector, g));
        registry.isGroupMember(g, Y1);
    }

    function test_isGroupMember() public {
        bytes32 g = _createGroup(regId, _triple(Y1, Y2, Y3));

        assertTrue(registry.isGroupMember(g, Y1));
        assertTrue(registry.isGroupMember(g, Y2));
        assertTrue(registry.isGroupMember(g, Y3));
        assertFalse(registry.isGroupMember(g, bytes32(0)));
        assertFalse(registry.isGroupMember(g, bytes32(uint256(0x12))));
        assertFalse(registry.isGroupMember(g, bytes32(uint256(0x44))));
    }

    function test_groupVersionCountsRevokedMembers() public {
        bytes32 g = _createGroup(regId, _triple(Y1, Y2, Y3));

        _revoke(regId, Y1);
        assertEq(registry.groupVersion(g), 1);
        _revoke(regId, Y3);
        assertEq(registry.groupVersion(g), 2);
    }

    // Más registryben történt revokálás nem számít bele a csoport versionjébe.
    function test_groupVersionIgnoresOtherRegistries() public {
        bytes32 id2 = _freshRegistry();
        bytes32 g = _createGroup(regId, _pair(Y1, Y2));

        _revoke(id2, Y1);
        assertEq(registry.groupVersion(g), 0);
    }

    // ---------------------------------------------------------------------
    // Olvasó függvények
    // ---------------------------------------------------------------------

    function test_registryIdOf() public view {
        assertEq(registry.registryIdOf(credDefId, LABEL), keccak256(abi.encode(credDefId, LABEL)));
        assertEq(registry.registryIdOf(credDefId, LABEL), regId);
        assertTrue(registry.registryIdOf(credDefId, LABEL) != registry.registryIdOf(credDefId, LABEL2));
    }

    function test_getValuesMatchesGetRegistry() public {
        _issue(regId, "1");
        _revoke(regId, Y1);

        (bytes memory a, bytes memory r, bytes memory i, bytes memory w, uint64 v) = registry.getValues(regId);
        StateRegistry.Registry memory reg = registry.getRegistry(regId);
        assertEq(a, reg.A);
        assertEq(r, reg.Rtilde);
        assertEq(i, reg.I);
        assertEq(w, reg.WIR);
        assertEq(v, reg.version);
    }

    // A régi versionök hash-e változatlan marad, a jövőbeli version 0.
    function test_valuesHashHistory() public {
        bytes32 h0 = registry.valuesHashAt(regId, 0);
        _issue(regId, "1");
        bytes32 h1 = registry.valuesHashAt(regId, 1);
        _revoke(regId, Y1);

        (bytes memory a, bytes memory r, bytes memory i,,) = registry.getValues(regId);
        assertEq(registry.valuesHashAt(regId, 0), h0);
        assertEq(registry.valuesHashAt(regId, 1), h1);
        assertEq(registry.valuesHashAt(regId, 2), keccak256(abi.encode(a, r, i)));
        assertEq(registry.valuesHashAt(regId, 3), bytes32(0));
        assertTrue(h0 != h1);
    }

    function test_revokedLogPaging() public {
        bytes32[] memory ys = _triple(Y1, Y2, Y3);
        for (uint256 i = 0; i < ys.length; i++) {
            _revoke(regId, ys[i]);
        }

        assertEq(registry.revokedCount(regId), 3);
        assertEq(registry.getRevokedLog(regId, 0, 10), ys);
        assertEq(registry.getRevokedLog(regId, 1, 1), _one(Y2));
        assertEq(registry.getRevokedLog(regId, 1, 2), _pair(Y2, Y3));
        assertEq(registry.getRevokedLog(regId, 3, 5).length, 0);
        assertEq(registry.revokedAt(regId, Y3), 3);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.IndexOutOfRange.selector, uint256(4)));
        registry.getRevokedLog(regId, 4, 1);
    }

    function test_emptyRevokedLog() public {
        assertEq(registry.revokedCount(regId), 0);
        assertEq(registry.getRevokedLog(regId, 0, 5).length, 0);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.IndexOutOfRange.selector, uint256(1)));
        registry.getRevokedLog(regId, 1, 1);
    }

    // ---------------------------------------------------------------------
    // Fuzz
    // ---------------------------------------------------------------------

    function testFuzz_nonIssuerCannotIssue(address caller) public {
        vm.assume(caller != alice);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, caller));
        vm.prank(caller);
        registry.issueUpdate(regId, _g1("I"), _g1("WIR"));
    }

    function testFuzz_nonIssuerCannotRevoke(address caller) public {
        vm.assume(caller != alice);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, caller));
        vm.prank(caller);
        registry.revoke(regId, Y1, _g1("A"), _g2("R"), _g1("W"));
    }

    function testFuzz_fullLifecycle(bytes32 y) public {
        vm.assume(y != bytes32(0));

        _issue(regId, "1");
        _revoke(regId, y);

        assertTrue(registry.isRevoked(regId, y));
        assertEq(registry.revokedAt(regId, y), 2);
        assertEq(_version(regId), 2);
    }

    function testFuzz_registryIdOf(bytes32 label) public view {
        assertEq(registry.registryIdOf(credDefId, label), keccak256(abi.encode(credDefId, label)));
    }

    function testFuzz_isGroupMember(bytes32 y) public {
        bytes32 g = _createGroup(regId, _triple(Y1, Y2, Y3));
        bool expected = y == Y1 || y == Y2 || y == Y3;
        assertEq(registry.isGroupMember(g, y), expected);
    }
}
