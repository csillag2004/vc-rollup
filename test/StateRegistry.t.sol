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

    address public admin = makeAddr("admin"); // ADMIN DID
    address public alice = makeAddr("alice"); // kibocsátó (issuer DID)
    address public bob = makeAddr("bob");
    address public carol = makeAddr("carol"); // csoport létrehozó

    bytes32 public schemaId;
    bytes32 public credDefId;

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
    bytes32 public constant SALT = keccak256("salt");
    bytes32 public constant DIGEST = keccak256("guard");
    bytes32 public constant LABEL = keccak256("label");

    event SrsPublished(uint32 degree, bytes32 srsHash, bytes[] g1Powers, bytes[] g2Powers);
    event IssuanceRegistered(bytes32 indexed credDefId, bytes32 indexed commitment);
    event Issued(uint64 indexed version, bytes32[] commitments, bytes newI, bytes newWIR);
    event RevocationRequested(bytes32 indexed credDefId, bytes32 indexed commitment, bytes32 guardDigest, bytes32 guardGroup);
    event RevocationRequestCancelled(bytes32 indexed credDefId, bytes32 indexed commitment);
    event Revoked(uint64 indexed version, bytes32 indexed y, bytes32 indexed credDefId, bytes32 commitment, bytes newA, bytes newRtilde, bytes newWIR, bytes32 guardDigest);
    event GroupCreated(bytes32 indexed groupId, address indexed creator, bytes32 label, bytes32[] members);

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

        registry = _deploy(q);
        (bytes[] memory g1, bytes[] memory g2) = _srs(SRS_DEGREE, q);
        vm.prank(admin);
        registry.publishSrs(g1, g2);
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

    function _deploy(bytes memory _q) internal returns (StateRegistry) {
        return new StateRegistry(address(credDefRegistry), admin, v0, qTilde, _q);
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

    function _c(bytes32 y, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(y, salt));
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

    function _wrongStatus(bytes32 c, StateRegistry.Status expected, StateRegistry.Status actual)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(StateRegistry.WrongStatus.selector, c, expected, actual);
    }

    function _assertStatus(bytes32 c, StateRegistry.Status s) internal view {
        assertEq(uint8(registry.getIssuance(c).status), uint8(s));
    }

    function _registerIssuance(bytes32 y, bytes32 salt) internal returns (bytes32 c) {
        c = _c(y, salt);
        vm.prank(alice);
        registry.registerIssuance(credDefId, c);
    }

    function _include(bytes32 c) internal {
        vm.prank(admin);
        registry.issueUpdate(_one(c), _g1(abi.encode("I", c)), _g1(abi.encode("WIR-i", c)));
    }

    function _issue(bytes32 y, bytes32 salt) internal returns (bytes32 c) {
        c = _registerIssuance(y, salt);
        _include(c);
    }

    function _request(bytes32 c, bytes32 guardDigest, bytes32 guardGroup) internal {
        vm.prank(alice);
        registry.requestRevocation(c, guardDigest, guardGroup);
    }

    function _revoke(bytes32 y, bytes32 salt) internal {
        vm.prank(admin);
        registry.revoke(y, salt, _g1(abi.encode("A", y, salt)), _g2(abi.encode("R", y, salt)), _g1(abi.encode("WIR-r", y, salt)));
    }

    function _guardedRevoke(uint64 expectedVersion, bytes32 y, bytes32 salt) internal {
        vm.prank(admin);
        registry.guardedRevoke(
            expectedVersion, y, salt, _g1(abi.encode("A", y, salt)), _g2(abi.encode("R", y, salt)), _g1(abi.encode("WIR-r", y, salt))
        );
    }

    function _narrowedRevoke(uint64 expectedVersion, uint64 expectedGroupVersion, bytes32 y, bytes32 salt) internal {
        vm.prank(admin);
        registry.guardedRevokeNarrowed(
            expectedVersion,
            expectedGroupVersion,
            y,
            salt,
            _g1(abi.encode("A", y, salt)),
            _g2(abi.encode("R", y, salt)),
            _g1(abi.encode("WIR-r", y, salt))
        );
    }

    function _createGroup(bytes32[] memory members) internal returns (bytes32) {
        vm.prank(carol);
        return registry.createGroup(LABEL, members);
    }

    // ---------------------------------------------------------------------
    // Konstruktor
    // ---------------------------------------------------------------------

    function test_constructorStoresInitialState() public view {
        assertEq(address(registry.credDefRegistry()), address(credDefRegistry));
        assertEq(address(registry.didRegistry()), address(didRegistry));
        assertEq(registry.adminDid(), admin);

        assertEq(registry.getV0(), v0);
        assertEq(registry.getQtilde(), qTilde);
        assertEq(registry.getQ(), q);
        assertEq(registry.getA(), v0);
        assertEq(registry.getRtilde(), G2_GEN);
        assertEq(registry.getI(), G1_GEN);
        assertEq(registry.getWIR(), G1_GEN);
        assertEq(registry.getVersion(), 0);
        assertEq(registry.valuesHashAt(0), keccak256(abi.encode(v0, G2_GEN, G1_GEN)));
    }

    function test_generatorConstants() public view {
        assertEq(registry.G1_GENERATOR(), G1_GEN);
        assertEq(registry.G2_GENERATOR(), G2_GEN);
        assertEq(G1_GEN.length, 48);
        assertEq(G2_GEN.length, 96);
    }

    function test_freshRegistryHasNoSrs() public {
        StateRegistry fresh = _deploy(q);
        assertEq(fresh.getSrsHash(), bytes32(0));
        assertEq(fresh.getSrsLength(), 0);
    }

    function test_constructorRejectsZeroAddresses() public {
        vm.expectRevert(StateRegistry.ZeroAddress.selector);
        new StateRegistry(address(0), admin, v0, qTilde, q);

        vm.expectRevert(StateRegistry.ZeroAddress.selector);
        new StateRegistry(address(credDefRegistry), address(0), v0, qTilde, q);
    }

    function test_constructorRejectsBadPointLengths() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(96)));
        new StateRegistry(address(credDefRegistry), admin, _g2("V0"), qTilde, q);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG2Length.selector, uint256(48)));
        new StateRegistry(address(credDefRegistry), admin, v0, _g1("Qtilde"), q);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(1)));
        new StateRegistry(address(credDefRegistry), admin, v0, qTilde, hex"01");
    }

    function test_constructorAcceptsEmptyQ() public {
        StateRegistry r = _deploy("");
        assertEq(r.getQ().length, 0);
    }

    // ---------------------------------------------------------------------
    // SRS publikálás
    // ---------------------------------------------------------------------

    function test_publishSrs() public {
        StateRegistry fresh = _deploy(q);
        (bytes[] memory g1, bytes[] memory g2) = _srs(3, q);
        bytes32 h = keccak256(abi.encode(g1, g2));

        vm.expectEmit(true, true, true, true, address(fresh));
        emit SrsPublished(3, h, g1, g2);
        vm.prank(admin);
        fresh.publishSrs(g1, g2);

        assertEq(fresh.getSrsHash(), h);
        assertEq(fresh.getSrsLength(), 3);
    }

    function test_setUpPublishedSrs() public view {
        assertTrue(registry.getSrsHash() != bytes32(0));
        assertEq(registry.getSrsLength(), SRS_DEGREE);
    }

    function test_publishSrsOnlyAdmin() public {
        StateRegistry fresh = _deploy(q);
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, q);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotAdmin.selector, bob));
        vm.prank(bob);
        fresh.publishSrs(g1, g2);
    }

    function test_publishSrsFollowsAdminDidOwner() public {
        StateRegistry fresh = _deploy(q);
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, q);

        vm.prank(admin);
        didRegistry.changeOwner(admin, bob);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotAdmin.selector, admin));
        vm.prank(admin);
        fresh.publishSrs(g1, g2);

        vm.prank(bob);
        fresh.publishSrs(g1, g2);
        assertEq(fresh.getSrsLength(), 2);
    }

    function test_publishSrsTwiceReverts() public {
        (bytes[] memory g1, bytes[] memory g2) = _srs(SRS_DEGREE, q);
        vm.expectRevert(StateRegistry.SrsAlreadyPublished.selector);
        vm.prank(admin);
        registry.publishSrs(g1, g2);
    }

    function test_publishSrsTooShortReverts() public {
        StateRegistry fresh = _deploy(q);
        bytes[] memory g1 = new bytes[](1);
        bytes[] memory g2 = new bytes[](1);
        g1[0] = G1_GEN;
        g2[0] = G2_GEN;

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadSrsLength.selector, uint256(1), uint256(1)));
        vm.prank(admin);
        fresh.publishSrs(g1, g2);
    }

    function test_publishSrsLengthMismatchReverts() public {
        StateRegistry fresh = _deploy(q);
        (bytes[] memory g1,) = _srs(2, q);
        (, bytes[] memory g2) = _srs(1, q);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadSrsLength.selector, uint256(3), uint256(2)));
        vm.prank(admin);
        fresh.publishSrs(g1, g2);
    }

    function test_publishSrsBadPointLengthReverts() public {
        StateRegistry fresh = _deploy(q);
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, q);

        g1[2] = hex"01";
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(1)));
        vm.prank(admin);
        fresh.publishSrs(g1, g2);

        (g1, g2) = _srs(2, q);
        g2[2] = _g1("not-g2");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG2Length.selector, uint256(48)));
        vm.prank(admin);
        fresh.publishSrs(g1, g2);
    }

    function test_publishSrsGeneratorMismatchReverts() public {
        StateRegistry fresh = _deploy(q);
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, q);

        g1[0] = _g1("fake-g");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.SrsMismatch.selector, uint256(0)));
        vm.prank(admin);
        fresh.publishSrs(g1, g2);

        (g1, g2) = _srs(2, q);
        g2[0] = _g2("fake-g~");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.SrsMismatch.selector, uint256(0)));
        vm.prank(admin);
        fresh.publishSrs(g1, g2);
    }

    function test_publishSrsKeyMismatchReverts() public {
        StateRegistry fresh = _deploy(q);
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, q);

        g2[1] = _g2("fake-Qtilde");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.SrsMismatch.selector, uint256(1)));
        vm.prank(admin);
        fresh.publishSrs(g1, g2);

        (g1, g2) = _srs(2, q);
        g1[1] = _g1("fake-Q");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.SrsMismatch.selector, uint256(1)));
        vm.prank(admin);
        fresh.publishSrs(g1, g2);
    }

    // Ha Q nincs megadva, g1Powers[1] tetszőleges lehet.
    function test_publishSrsWithoutQ() public {
        StateRegistry fresh = _deploy("");
        (bytes[] memory g1, bytes[] memory g2) = _srs(2, "");

        vm.prank(admin);
        fresh.publishSrs(g1, g2);
        assertEq(fresh.getSrsLength(), 2);
    }

    function test_registerIssuanceBeforeSrsReverts() public {
        StateRegistry fresh = _deploy(q);
        vm.expectRevert(StateRegistry.SrsNotPublished.selector);
        vm.prank(alice);
        fresh.registerIssuance(credDefId, _c(Y1, SALT));
    }

    function test_createGroupBeforeSrsReverts() public {
        StateRegistry fresh = _deploy(q);
        vm.expectRevert(StateRegistry.SrsNotPublished.selector);
        vm.prank(carol);
        fresh.createGroup(LABEL, _one(Y1));
    }

    // ---------------------------------------------------------------------
    // Kiadás regisztrálása
    // ---------------------------------------------------------------------

    function test_registerIssuance() public {
        bytes32 c = _c(Y1, SALT);

        vm.expectEmit(true, true, true, true, address(registry));
        emit IssuanceRegistered(credDefId, c);
        _registerIssuance(Y1, SALT);

        StateRegistry.Issuance memory iss = registry.getIssuance(c);
        assertEq(iss.credDefId, credDefId);
        assertEq(uint8(iss.status), uint8(StateRegistry.Status.Registered));
        assertEq(iss.guardDigest, bytes32(0));
        assertEq(iss.guardGroup, bytes32(0));
        assertEq(iss.includedAt, 0);
        assertEq(iss.revokedAt, 0);

        // a regisztráció nem lépteti a versiont
        assertEq(registry.getVersion(), 0);
    }

    function test_registerIssuanceUnknownCredDefReverts() public {
        bytes32 fake = keccak256("fake");
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownCredDef.selector, fake));
        vm.prank(alice);
        registry.registerIssuance(fake, _c(Y1, SALT));
    }

    function test_registerIssuanceNotIssuerReverts() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        vm.prank(bob);
        registry.registerIssuance(credDefId, _c(Y1, SALT));
    }

    function test_registerIssuanceFollowsIssuerDidOwner() public {
        vm.prank(alice);
        didRegistry.changeOwner(alice, bob);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, alice));
        vm.prank(alice);
        registry.registerIssuance(credDefId, _c(Y1, SALT));

        vm.prank(bob);
        registry.registerIssuance(credDefId, _c(Y1, SALT));
        _assertStatus(_c(Y1, SALT), StateRegistry.Status.Registered);
    }

    function test_registerIssuanceZeroCommitmentReverts() public {
        vm.expectRevert(StateRegistry.EmptyCommitment.selector);
        vm.prank(alice);
        registry.registerIssuance(credDefId, bytes32(0));
    }

    function test_registerIssuanceTwiceReverts() public {
        bytes32 c = _registerIssuance(Y1, SALT);
        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.None, StateRegistry.Status.Registered));
        _registerIssuance(Y1, SALT);
    }

    // ---------------------------------------------------------------------
    // Kiadás beszámítása (issueUpdate)
    // ---------------------------------------------------------------------

    function test_issueUpdate() public {
        bytes32 c1 = _registerIssuance(Y1, SALT);
        bytes32 c2 = _registerIssuance(Y2, SALT);
        bytes32[] memory cs = _pair(c1, c2);
        bytes memory newI = _g1("I1");
        bytes memory newWIR = _g1("WIR1");

        vm.expectEmit(true, true, true, true, address(registry));
        emit Issued(1, cs, newI, newWIR);
        vm.prank(admin);
        registry.issueUpdate(cs, newI, newWIR);

        assertEq(registry.getVersion(), 1);
        assertEq(registry.getI(), newI);
        assertEq(registry.getWIR(), newWIR);
        // a kiadás A-t és R̃-t nem érinti
        assertEq(registry.getA(), v0);
        assertEq(registry.getRtilde(), G2_GEN);
        assertEq(registry.valuesHashAt(1), keccak256(abi.encode(v0, G2_GEN, newI)));

        for (uint256 i = 0; i < cs.length; i++) {
            StateRegistry.Issuance memory iss = registry.getIssuance(cs[i]);
            assertEq(uint8(iss.status), uint8(StateRegistry.Status.Included));
            assertEq(iss.includedAt, 1);
        }
    }

    function test_issueUpdateSequentialVersions() public {
        bytes32 c1 = _issue(Y1, SALT);
        bytes32 c2 = _issue(Y2, SALT);

        assertEq(registry.getVersion(), 2);
        assertEq(registry.getIssuance(c1).includedAt, 1);
        assertEq(registry.getIssuance(c2).includedAt, 2);
        assertTrue(registry.valuesHashAt(1) != registry.valuesHashAt(2));
    }

    function test_issueUpdateOnlyAdmin() public {
        bytes32 c = _registerIssuance(Y1, SALT);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotAdmin.selector, alice));
        vm.prank(alice);
        registry.issueUpdate(_one(c), _g1("I"), _g1("WIR"));
    }

    function test_issueUpdateEmptyReverts() public {
        vm.expectRevert(StateRegistry.NothingToInclude.selector);
        vm.prank(admin);
        registry.issueUpdate(new bytes32[](0), _g1("I"), _g1("WIR"));
    }

    function test_issueUpdateBadPointLengthReverts() public {
        bytes32 c = _registerIssuance(Y1, SALT);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(96)));
        vm.prank(admin);
        registry.issueUpdate(_one(c), _g2("I"), _g1("WIR"));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(0)));
        vm.prank(admin);
        registry.issueUpdate(_one(c), _g1("I"), "");
    }

    function test_issueUpdateUnregisteredReverts() public {
        bytes32 c = _c(Y1, SALT);
        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.Registered, StateRegistry.Status.None));
        vm.prank(admin);
        registry.issueUpdate(_one(c), _g1("I"), _g1("WIR"));
    }

    function test_issueUpdateAlreadyIncludedReverts() public {
        bytes32 c = _issue(Y1, SALT);
        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.Registered, StateRegistry.Status.Included));
        vm.prank(admin);
        registry.issueUpdate(_one(c), _g1("I"), _g1("WIR"));
    }

    function test_issueUpdateDuplicateInBatchReverts() public {
        bytes32 c = _registerIssuance(Y1, SALT);
        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.Registered, StateRegistry.Status.Included));
        vm.prank(admin);
        registry.issueUpdate(_pair(c, c), _g1("I"), _g1("WIR"));
    }

    function test_issueUpdateIsAtomic() public {
        bytes32 c1 = _registerIssuance(Y1, SALT);
        bytes32 c2 = _c(Y2, SALT); // nincs regisztrálva

        vm.expectRevert(_wrongStatus(c2, StateRegistry.Status.Registered, StateRegistry.Status.None));
        vm.prank(admin);
        registry.issueUpdate(_pair(c1, c2), _g1("I"), _g1("WIR"));

        _assertStatus(c1, StateRegistry.Status.Registered);
        assertEq(registry.getVersion(), 0);
        assertEq(registry.getI(), G1_GEN);
    }

    // ---------------------------------------------------------------------
    // Revokálási kérelem
    // ---------------------------------------------------------------------

    function test_requestRevocationUnguarded() public {
        bytes32 c = _issue(Y1, SALT);

        vm.expectEmit(true, true, true, true, address(registry));
        emit RevocationRequested(credDefId, c, bytes32(0), bytes32(0));
        _request(c, bytes32(0), bytes32(0));

        StateRegistry.Issuance memory iss = registry.getIssuance(c);
        assertEq(uint8(iss.status), uint8(StateRegistry.Status.Requested));
        assertEq(iss.guardDigest, bytes32(0));
        assertEq(iss.guardGroup, bytes32(0));
    }

    function test_requestRevocationGuarded() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, bytes32(0));

        StateRegistry.Issuance memory iss = registry.getIssuance(c);
        assertEq(uint8(iss.status), uint8(StateRegistry.Status.Requested));
        assertEq(iss.guardDigest, DIGEST);
        assertEq(iss.guardGroup, bytes32(0));
    }

    function test_requestRevocationNarrowed() public {
        bytes32 g = _createGroup(_pair(Y1, Y2));
        bytes32 c = _issue(Y1, SALT);

        vm.expectEmit(true, true, true, true, address(registry));
        emit RevocationRequested(credDefId, c, DIGEST, g);
        _request(c, DIGEST, g);

        assertEq(registry.getIssuance(c).guardGroup, g);
    }

    function test_requestRevocationGroupWithoutGuardReverts() public {
        bytes32 g = _createGroup(_one(Y1));
        bytes32 c = _issue(Y1, SALT);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GroupWithoutGuard.selector, g));
        _request(c, bytes32(0), g);
    }

    function test_requestRevocationUnknownGroupReverts() public {
        bytes32 c = _issue(Y1, SALT);
        bytes32 g = keccak256("no-such-group");

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownGroup.selector, g));
        _request(c, DIGEST, g);
    }

    function test_requestRevocationNotIssuerReverts() public {
        bytes32 c = _issue(Y1, SALT);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        vm.prank(bob);
        registry.requestRevocation(c, bytes32(0), bytes32(0));
    }

    function test_requestRevocationRequiresIncluded() public {
        bytes32 c = _registerIssuance(Y1, SALT);
        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.Included, StateRegistry.Status.Registered));
        _request(c, bytes32(0), bytes32(0));
    }

    // Nem létező rekordnál az állapot-ellenőrzés fut előbb, nem az issuer-ellenőrzés.
    function test_requestRevocationUnknownCommitmentReverts() public {
        bytes32 c = _c(Y1, SALT);
        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.Included, StateRegistry.Status.None));
        vm.prank(bob);
        registry.requestRevocation(c, bytes32(0), bytes32(0));
    }

    function test_requestRevocationTwiceReverts() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, bytes32(0), bytes32(0));

        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.Included, StateRegistry.Status.Requested));
        _request(c, bytes32(0), bytes32(0));
    }

    // ---------------------------------------------------------------------
    // Kérelem visszavonása
    // ---------------------------------------------------------------------

    function test_cancelRevocationRequest() public {
        bytes32 g = _createGroup(_one(Y1));
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, g);

        vm.expectEmit(true, true, true, true, address(registry));
        emit RevocationRequestCancelled(credDefId, c);
        vm.prank(alice);
        registry.cancelRevocationRequest(c);

        StateRegistry.Issuance memory iss = registry.getIssuance(c);
        assertEq(uint8(iss.status), uint8(StateRegistry.Status.Included));
        assertEq(iss.guardDigest, bytes32(0));
        assertEq(iss.guardGroup, bytes32(0));
        assertEq(iss.includedAt, 1);
    }

    function test_cancelRequiresRequested() public {
        bytes32 c = _issue(Y1, SALT);
        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.Requested, StateRegistry.Status.Included));
        vm.prank(alice);
        registry.cancelRevocationRequest(c);
    }

    function test_cancelNotIssuerReverts() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, bytes32(0), bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        vm.prank(bob);
        registry.cancelRevocationRequest(c);
    }

    function test_requestAgainAfterCancel() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, bytes32(0));
        vm.prank(alice);
        registry.cancelRevocationRequest(c);

        _request(c, bytes32(0), bytes32(0));
        _assertStatus(c, StateRegistry.Status.Requested);
        assertEq(registry.getIssuance(c).guardDigest, bytes32(0));
    }

    function test_cancelledRequestCannotBeRevoked() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, bytes32(0), bytes32(0));
        vm.prank(alice);
        registry.cancelRevocationRequest(c);

        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.Requested, StateRegistry.Status.Included));
        _revoke(Y1, SALT);
    }

    // ---------------------------------------------------------------------
    // Feltétel nélküli revokálás
    // ---------------------------------------------------------------------

    function test_revoke() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, bytes32(0), bytes32(0));

        bytes memory iBefore = registry.getI();
        bytes memory newA = _g1("A1");
        bytes memory newR = _g2("R1");
        bytes memory newWIR = _g1("WIR-r1");

        vm.expectEmit(true, true, true, true, address(registry));
        emit Revoked(2, Y1, credDefId, c, newA, newR, newWIR, bytes32(0));
        vm.prank(admin);
        registry.revoke(Y1, SALT, newA, newR, newWIR);

        assertEq(registry.getVersion(), 2);
        assertEq(registry.getA(), newA);
        assertEq(registry.getRtilde(), newR);
        assertEq(registry.getWIR(), newWIR);
        assertEq(registry.getI(), iBefore); // a revokálás I-t nem érinti
        assertEq(registry.valuesHashAt(2), keccak256(abi.encode(newA, newR, iBefore)));

        StateRegistry.Issuance memory iss = registry.getIssuance(c);
        assertEq(uint8(iss.status), uint8(StateRegistry.Status.Revoked));
        assertEq(iss.includedAt, 1);
        assertEq(iss.revokedAt, 2);

        assertTrue(registry.isRevoked(Y1));
        assertFalse(registry.isRevoked(Y2));
        assertEq(registry.revokedCommitmentOf(Y1), c);
        assertEq(registry.revokedCommitmentOf(Y2), bytes32(0));
        assertEq(registry.revokedCount(), 1);
        assertEq(registry.revokedAt(0), Y1);
    }

    function test_revokeOnlyAdmin() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, bytes32(0), bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotAdmin.selector, alice));
        vm.prank(alice);
        registry.revoke(Y1, SALT, _g1("A"), _g2("R"), _g1("W"));
    }

    function test_revokeZeroYReverts() public {
        vm.expectRevert(StateRegistry.EmptyRevocationId.selector);
        _revoke(bytes32(0), SALT);
    }

    function test_revokeWrongSaltReverts() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, bytes32(0), bytes32(0));

        bytes32 wrongSalt = keccak256("wrong");
        vm.expectRevert(_wrongStatus(_c(Y1, wrongSalt), StateRegistry.Status.Requested, StateRegistry.Status.None));
        _revoke(Y1, wrongSalt);
    }

    function test_revokeWithoutRequestReverts() public {
        bytes32 c = _issue(Y1, SALT);
        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.Requested, StateRegistry.Status.Included));
        _revoke(Y1, SALT);
    }

    function test_revokeGuardedRequestReverts() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GuardedRequest.selector, c, DIGEST));
        _revoke(Y1, SALT);
    }

    function test_revokeTwiceReverts() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, bytes32(0), bytes32(0));
        _revoke(Y1, SALT);

        vm.expectRevert(_wrongStatus(c, StateRegistry.Status.Requested, StateRegistry.Status.Revoked));
        _revoke(Y1, SALT);
    }

    // Ugyanaz az y egy másik commitment (más salt) alatt nem revokálható újra.
    function test_revokeSameYUnderOtherCommitmentReverts() public {
        bytes32 salt2 = keccak256("salt2");
        bytes32 c1 = _issue(Y1, SALT);
        bytes32 c2 = _issue(Y1, salt2);
        _request(c1, bytes32(0), bytes32(0));
        _request(c2, bytes32(0), bytes32(0));
        _revoke(Y1, SALT);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.AlreadyRevoked.selector, Y1));
        _revoke(Y1, salt2);

        _assertStatus(c2, StateRegistry.Status.Requested);
        assertEq(registry.revokedCommitmentOf(Y1), c1);
    }

    function test_revokeBadPointLengthReverts() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, bytes32(0), bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(96)));
        vm.prank(admin);
        registry.revoke(Y1, SALT, _g2("A"), _g2("R"), _g1("W"));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG2Length.selector, uint256(48)));
        vm.prank(admin);
        registry.revoke(Y1, SALT, _g1("A"), _g1("R"), _g1("W"));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.BadG1Length.selector, uint256(96)));
        vm.prank(admin);
        registry.revoke(Y1, SALT, _g1("A"), _g2("R"), _g2("W"));

        _assertStatus(c, StateRegistry.Status.Requested);
    }

    // ---------------------------------------------------------------------
    // Őrzött (globális) revokálás
    // ---------------------------------------------------------------------

    function test_guardedRevoke() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, bytes32(0));
        uint64 v = registry.getVersion();

        vm.expectEmit(true, true, true, true, address(registry));
        emit Revoked(v + 1, Y1, credDefId, c, _g1(abi.encode("A", Y1, SALT)), _g2(abi.encode("R", Y1, SALT)), _g1(abi.encode("WIR-r", Y1, SALT)), DIGEST);
        _guardedRevoke(v, Y1, SALT);

        _assertStatus(c, StateRegistry.Status.Revoked);
        assertEq(registry.getVersion(), v + 1);
    }

    function test_guardedRevokeStaleVersionReverts() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, bytes32(0));
        uint64 v = registry.getVersion();

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v - 1, v));
        _guardedRevoke(v - 1, Y1, SALT);
    }

    // Két kérelem ugyanarra a versionre: a második már elavult állapotra hivatkozik.
    function test_guardedRevokeStaleAfterOtherRevocation() public {
        bytes32 c1 = _issue(Y1, SALT);
        bytes32 c2 = _issue(Y2, SALT);
        _request(c1, DIGEST, bytes32(0));
        _request(c2, DIGEST, bytes32(0));
        uint64 v = registry.getVersion();

        _guardedRevoke(v, Y1, SALT);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v, v + 1));
        _guardedRevoke(v, Y2, SALT);

        _guardedRevoke(v + 1, Y2, SALT);
        _assertStatus(c2, StateRegistry.Status.Revoked);
    }

    function test_guardedRevokeRejectsNarrowedRequest() public {
        bytes32 g = _createGroup(_one(Y1));
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, g);
        uint64 v = registry.getVersion();

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.WrongGuardScope.selector, c, g));
        _guardedRevoke(v, Y1, SALT);
    }

    function test_guardedRevokeOnlyAdmin() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, bytes32(0));
        uint64 v = registry.getVersion();

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotAdmin.selector, bob));
        vm.prank(bob);
        registry.guardedRevoke(v, Y1, SALT, _g1("A"), _g2("R"), _g1("W"));
    }

    // ---------------------------------------------------------------------
    // Csoportra szűkített őrzött revokálás
    // ---------------------------------------------------------------------

    function test_guardedRevokeNarrowed() public {
        bytes32 g = _createGroup(_pair(Y1, Y2));
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, g);
        uint64 v = registry.getVersion();
        assertEq(registry.groupVersion(g), 0);

        _narrowedRevoke(v, 0, Y1, SALT);

        _assertStatus(c, StateRegistry.Status.Revoked);
        assertEq(registry.getVersion(), v + 1);
        assertEq(registry.groupVersion(g), 1);
    }

    function test_guardedRevokeNarrowedStaleVersionReverts() public {
        bytes32 g = _createGroup(_one(Y1));
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, g);
        uint64 v = registry.getVersion();

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, v + 1, v));
        _narrowedRevoke(v + 1, 0, Y1, SALT);
    }

    function test_guardedRevokeNarrowedRejectsGlobalRequest() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, DIGEST, bytes32(0));
        uint64 v = registry.getVersion();

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.WrongGuardScope.selector, c, bytes32(0)));
        _narrowedRevoke(v, 0, Y1, SALT);
    }

    function test_guardedRevokeNarrowedStaleGroupVersionReverts() public {
        bytes32 g = _createGroup(_pair(Y1, Y2));
        bytes32 c1 = _issue(Y1, SALT);
        bytes32 c2 = _issue(Y2, SALT);
        _request(c1, DIGEST, g);
        _request(c2, bytes32(0), bytes32(0));

        // egy másik csoporttag revokálása lépteti a csoport versionjét
        _revoke(Y2, SALT);
        uint64 v = registry.getVersion();

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleGroupVersion.selector, g, uint64(0), uint64(1)));
        _narrowedRevoke(v, 0, Y1, SALT);

        _narrowedRevoke(v, 1, Y1, SALT);
        _assertStatus(c1, StateRegistry.Status.Revoked);
    }

    // Csoporton kívüli revokálás a globális versiont lépteti, a csoportét nem.
    function test_guardedRevokeNarrowedIgnoresNonMemberRevocation() public {
        bytes32 g = _createGroup(_pair(Y1, Y2));
        bytes32 c1 = _issue(Y1, SALT);
        bytes32 c3 = _issue(Y3, SALT);
        _request(c1, DIGEST, g);
        _request(c3, bytes32(0), bytes32(0));
        _revoke(Y3, SALT);

        assertEq(registry.groupVersion(g), 0);
        _narrowedRevoke(registry.getVersion(), 0, Y1, SALT);
        _assertStatus(c1, StateRegistry.Status.Revoked);
    }

    // ---------------------------------------------------------------------
    // Csoportok
    // ---------------------------------------------------------------------

    function test_createGroup() public {
        bytes32[] memory members = _triple(Y1, Y2, Y3);
        bytes32 expectedId = keccak256(abi.encode(carol, LABEL));

        vm.expectEmit(true, true, true, true, address(registry));
        emit GroupCreated(expectedId, carol, LABEL, members);
        bytes32 g = _createGroup(members);

        assertEq(g, expectedId);
        (address creator, uint256 createdAt, bytes32[] memory stored) = registry.getGroup(g);
        assertEq(creator, carol);
        assertEq(createdAt, block.timestamp);
        assertEq(stored, members);
        assertEq(registry.groupVersion(g), 0);
    }

    function test_createGroupEmptyReverts() public {
        vm.expectRevert(StateRegistry.EmptyGroup.selector);
        _createGroup(new bytes32[](0));
    }

    function test_createGroupSizeBoundedBySrs() public {
        bytes32[] memory members = new bytes32[](SRS_DEGREE + 1);
        for (uint256 i = 0; i < members.length; i++) {
            members[i] = bytes32(i + 1);
        }

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GroupTooLarge.selector, members.length, SRS_DEGREE));
        _createGroup(members);

        // pontosan SRS_DEGREE tag még belefér
        assembly {
            mstore(members, sub(mload(members), 1))
        }
        bytes32 g = _createGroup(members);
        (,, bytes32[] memory stored) = registry.getGroup(g);
        assertEq(stored.length, SRS_DEGREE);
    }

    function test_createGroupDuplicateReverts() public {
        bytes32 g = _createGroup(_one(Y1));
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GroupExists.selector, g));
        _createGroup(_one(Y2));
    }

    function test_sameLabelDifferentCreatorGetsDistinctGroup() public {
        bytes32 g1 = _createGroup(_one(Y1));
        vm.prank(bob);
        bytes32 g2 = registry.createGroup(LABEL, _one(Y1));

        assertTrue(g1 != g2);
        (address creator,,) = registry.getGroup(g2);
        assertEq(creator, bob);
    }

    function test_createGroupZeroMemberReverts() public {
        vm.expectRevert(StateRegistry.EmptyRevocationId.selector);
        _createGroup(_pair(bytes32(0), Y1));
    }

    function test_createGroupUnsortedReverts() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.MembersNotSorted.selector, uint256(1)));
        _createGroup(_pair(Y2, Y1));

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.MembersNotSorted.selector, uint256(2)));
        _createGroup(_triple(Y1, Y3, Y2));
    }

    function test_createGroupDuplicateMemberReverts() public {
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.MembersNotSorted.selector, uint256(1)));
        _createGroup(_pair(Y1, Y1));
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
        bytes32 g = _createGroup(_triple(Y1, Y2, Y3));

        assertTrue(registry.isGroupMember(g, Y1));
        assertTrue(registry.isGroupMember(g, Y2));
        assertTrue(registry.isGroupMember(g, Y3));
        assertFalse(registry.isGroupMember(g, bytes32(0)));
        assertFalse(registry.isGroupMember(g, bytes32(uint256(0x12))));
        assertFalse(registry.isGroupMember(g, bytes32(uint256(0x44))));
    }

    function test_groupVersionCountsRevokedMembers() public {
        bytes32 g = _createGroup(_triple(Y1, Y2, Y3));
        bytes32 c1 = _issue(Y1, SALT);
        bytes32 c3 = _issue(Y3, SALT);
        _request(c1, bytes32(0), bytes32(0));
        _request(c3, bytes32(0), bytes32(0));

        _revoke(Y1, SALT);
        assertEq(registry.groupVersion(g), 1);
        _revoke(Y3, SALT);
        assertEq(registry.groupVersion(g), 2);
    }

    // ---------------------------------------------------------------------
    // Olvasó függvények
    // ---------------------------------------------------------------------

    function test_commitmentOf() public view {
        assertEq(registry.commitmentOf(Y1, SALT), keccak256(abi.encode(Y1, SALT)));
        assertTrue(registry.commitmentOf(Y1, SALT) != registry.commitmentOf(Y1, keccak256("other")));
    }

    function test_getValuesMatchesGetters() public {
        bytes32 c = _issue(Y1, SALT);
        _request(c, bytes32(0), bytes32(0));
        _revoke(Y1, SALT);

        (bytes memory a, bytes memory r, bytes memory i, bytes memory w, uint64 v) = registry.getValues();
        assertEq(a, registry.getA());
        assertEq(r, registry.getRtilde());
        assertEq(i, registry.getI());
        assertEq(w, registry.getWIR());
        assertEq(v, registry.getVersion());
    }

    // A régi versionök hash-e változatlan marad, a jövőbeli version 0.
    function test_valuesHashHistory() public {
        bytes32 h0 = registry.valuesHashAt(0);
        bytes32 c = _issue(Y1, SALT);
        bytes32 h1 = registry.valuesHashAt(1);
        _request(c, bytes32(0), bytes32(0));
        _revoke(Y1, SALT);

        assertEq(registry.valuesHashAt(0), h0);
        assertEq(registry.valuesHashAt(1), h1);
        assertEq(
            registry.valuesHashAt(2), keccak256(abi.encode(registry.getA(), registry.getRtilde(), registry.getI()))
        );
        assertEq(registry.valuesHashAt(3), bytes32(0));
        assertTrue(h0 != h1);
    }

    function test_getIssuanceUnknownIsEmpty() public view {
        StateRegistry.Issuance memory iss = registry.getIssuance(keccak256("unknown"));
        assertEq(uint8(iss.status), uint8(StateRegistry.Status.None));
        assertEq(iss.credDefId, bytes32(0));
        assertEq(iss.includedAt, 0);
        assertEq(iss.revokedAt, 0);
    }

    function test_revokedLogPaging() public {
        bytes32[] memory ys = _triple(Y1, Y2, Y3);
        for (uint256 i = 0; i < ys.length; i++) {
            bytes32 c = _issue(ys[i], SALT);
            _request(c, bytes32(0), bytes32(0));
            _revoke(ys[i], SALT);
        }

        assertEq(registry.revokedCount(), 3);
        assertEq(registry.getRevokedLog(0, 10), ys);
        assertEq(registry.getRevokedLog(1, 1), _one(Y2));
        assertEq(registry.getRevokedLog(1, 2), _pair(Y2, Y3));
        assertEq(registry.getRevokedLog(3, 5).length, 0);
        assertEq(registry.revokedAt(2), Y3);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.IndexOutOfRange.selector, uint256(4)));
        registry.getRevokedLog(4, 1);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.IndexOutOfRange.selector, uint256(3)));
        registry.revokedAt(3);
    }

    function test_emptyRevokedLog() public {
        assertEq(registry.revokedCount(), 0);
        assertEq(registry.getRevokedLog(0, 5).length, 0);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.IndexOutOfRange.selector, uint256(0)));
        registry.revokedAt(0);
    }

    // ---------------------------------------------------------------------
    // Fuzz
    // ---------------------------------------------------------------------

    function testFuzz_nonAdminCannotIssue(address caller) public {
        vm.assume(caller != admin);
        bytes32 c = _registerIssuance(Y1, SALT);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotAdmin.selector, caller));
        vm.prank(caller);
        registry.issueUpdate(_one(c), _g1("I"), _g1("WIR"));
    }

    function testFuzz_nonIssuerCannotRegister(address caller) public {
        vm.assume(caller != alice);

        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, caller));
        vm.prank(caller);
        registry.registerIssuance(credDefId, _c(Y1, SALT));
    }

    function testFuzz_fullLifecycle(bytes32 y, bytes32 salt) public {
        vm.assume(y != bytes32(0));

        bytes32 c = _issue(y, salt);
        _request(c, bytes32(0), bytes32(0));
        _revoke(y, salt);

        assertTrue(registry.isRevoked(y));
        assertEq(registry.revokedCommitmentOf(y), c);
        _assertStatus(c, StateRegistry.Status.Revoked);
        assertEq(registry.getVersion(), 2);
    }

    function testFuzz_isGroupMember(bytes32 y) public {
        bytes32 g = _createGroup(_triple(Y1, Y2, Y3));
        bool expected = y == Y1 || y == Y2 || y == Y3;
        assertEq(registry.isGroupMember(g, y), expected);
    }
}
