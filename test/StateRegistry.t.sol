// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EthereumDIDRegistry} from "ethr-did-registry/EthereumDIDRegistry.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {CredDefRegistry} from "../src/CredDefRegistry.sol";
import {StateRegistry} from "../src/StateRegistry.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {BLS} from "../src/lib/BLS.sol";

/// Valódi BLS12-381 értékekkel tesztelünk: a pontokat a precompile-ok állítják elő egy ismert teszt-α-val.
contract StateRegistryTest is Test {
    EthereumDIDRegistry public didRegistry;
    SchemaRegistry public schemaRegistry;
    CredDefRegistry public credDefRegistry;
    PolicyRegistry public policies;
    StateRegistry public registry;

    address public alice = makeAddr("alice"); // kibocsátó (issuer DID)
    address public bob = makeAddr("bob");

    bytes32 public credDefId;
    bytes32 public regId;
    bytes32 public constant LABEL = keccak256("flat-42");

    uint256 public constant ALPHA = 0x1234567890abcdef1234567890abcdef;
    uint256 public constant V0_DLOG = 0x5eed;
    uint32 public constant SRS_DEGREE = 4;

    uint256 public constant Y1 = 0x11;
    uint256 public constant Y2 = 0x22;
    uint256 public constant Y3 = 0x33;
    uint256 public constant Y4 = 0x44;

    // a tesztben követett állapot (a contracttal párhuzamosan)
    bytes internal curA;
    bytes internal curR;
    bytes internal curI;
    bytes internal curW;
    uint256[] internal issuedYs;

    function setUp() public {
        didRegistry = new EthereumDIDRegistry();
        schemaRegistry = new SchemaRegistry();
        credDefRegistry = new CredDefRegistry(address(didRegistry), address(schemaRegistry));
        policies = new PolicyRegistry(address(credDefRegistry));
        registry = new StateRegistry(address(credDefRegistry), address(policies));

        string[] memory attributes = new string[](1);
        attributes[0] = "flat";
        bytes32 schemaId = schemaRegistry.registerSchema("Interest", "1.0", true, attributes);
        vm.prank(alice);
        credDefId = credDefRegistry.registerCredDef(alice, schemaId, "default", keccak256("alice#bbs-key-1"));

        (bytes memory v0, bytes memory qt, bytes memory q) = _keys(ALPHA);
        vm.prank(alice);
        regId = registry.createRegistry(credDefId, LABEL, v0, qt, q);
        (bytes[] memory p1, bytes[] memory p2) = _srs(SRS_DEGREE);
        vm.prank(alice);
        registry.publishSrs(regId, p1, p2);
        curA = _v0();
        curR = BLS.g2();
        curI = BLS.g1();
        curW = BLS.g1();
    }

    // ------------------------------------------------------------ segédfüggvények

    function _keys(uint256 alphaG1) internal view returns (bytes memory v0, bytes memory qt, bytes memory q) {
        v0 = _v0();
        qt = BLS.g2Mul(BLS.g2(), ALPHA);
        q = BLS.g1Mul(BLS.g1(), alphaG1);
    }

    function _v0() internal view returns (bytes memory) {
        return BLS.g1Mul(BLS.g1(), V0_DLOG);
    }

    function _srs(uint32 degree) internal view returns (bytes[] memory p1, bytes[] memory p2) {
        p1 = new bytes[](degree + 1);
        p2 = new bytes[](degree + 1);
        uint256 a = 1;
        for (uint256 i = 0; i <= degree; i++) {
            p1[i] = BLS.g1Mul(BLS.g1(), a);
            p2[i] = BLS.g2Mul(BLS.g2(), a);
            a = mulmod(a, ALPHA, BLS.R);
        }
    }

    function _issueStep(uint256 y) internal view returns (StateRegistry.IssueStep memory s) {
        uint256 f = addmod(y, ALPHA, BLS.R);
        s.newI = BLS.g1Mul(curI, f);
        s.newWIR = BLS.g1Mul(curW, f);
        s.T = BLS.g1Mul(curI, y);
        uint256 k = 0xbeef + y;
        s.R = BLS.g1Mul(curI, k);
        uint256 c = registry.issueChallenge(regId, s.newI, s.T, s.R);
        s.z = addmod(k, mulmod(c, y, BLS.R), BLS.R);
    }

    function _issue(uint256 y) internal {
        StateRegistry.IssueStep memory s = _issueStep(y);
        vm.prank(alice);
        registry.issueUpdate(regId, s);
        curI = s.newI;
        curW = s.newWIR;
        issuedYs.push(y);
    }

    function _revokeValues(uint256 y) internal view returns (bytes memory newA, bytes memory newR, bytes memory newW) {
        uint256 f = addmod(y, ALPHA, BLS.R);
        uint256 fi = BLS.frInv(f);
        newA = BLS.g1Mul(curA, fi);
        newR = BLS.g2Mul(curR, f);
        newW = BLS.g1Mul(curW, fi);
    }

    function _revoke(uint256 y) internal {
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(y);
        vm.prank(alice);
        registry.revoke(regId, bytes32(y), a, r, w);
        curA = a; curR = r; curW = w;
    }

    function _members(uint256 a, uint256 b) internal pure returns (bytes32[] memory m) {
        m = new bytes32[](2);
        m[0] = bytes32(a);
        m[1] = bytes32(b);
    }

    function _groupWitness(bytes32[] memory members) internal view returns (bytes memory) {
        uint256 p = 1;
        for (uint256 i = 0; i < members.length; i++) p = mulmod(p, addmod(uint256(members[i]), ALPHA, BLS.R), BLS.R);
        return BLS.g1Mul(curI, BLS.frInv(p));
    }

    function _createGroup(bytes32 label, bytes32[] memory members) internal returns (bytes32) {
        (, bytes[] memory p2) = _srs(SRS_DEGREE);
        bytes memory ws = _groupWitness(members);
        vm.prank(alice);
        return registry.createGroup(regId, label, members, ws, p2);
    }

    // ------------------------------------------------------------ BLS könyvtár

    function test_generatorsAndNegation() public view {
        assertTrue(BLS.pairingEq(BLS.g1(), BLS.g2(), BLS.g1(), BLS.g2()));
        bytes memory p = BLS.g1Mul(BLS.g1(), 12345);
        assertTrue(BLS.isZero(BLS.g1Add(p, BLS.g1Neg(p))));
        assertFalse(BLS.pairingEq(p, BLS.g2(), BLS.g1(), BLS.g2()));
    }

    function test_setPolyCoeffs() public pure {
        bytes32[] memory m = _members(2, 5);
        uint256[] memory c = BLS.setPolyCoeffs(m);
        assertEq(c[0], 10);
        assertEq(c[1], 7);
        assertEq(c[2], 1);
    }

    function test_frInv() public view {
        uint256 a = 0xdeadbeef;
        assertEq(mulmod(a, BLS.frInv(a), BLS.R), 1);
    }

    // ------------------------------------------------------------ létrehozás és SRS

    function test_createRegistryInitialValues() public view {
        (bytes memory A, bytes memory R, bytes memory I, bytes memory W, uint64 v) = registry.getValues(regId);
        assertEq(A, _v0());
        assertEq(R, BLS.g2());
        assertEq(I, BLS.g1());
        assertEq(W, BLS.g1());
        assertEq(v, 0);
        assertEq(registry.getRegistry(regId).srsDegree, SRS_DEGREE);
    }

    function test_createRegistryKeyMismatchReverts() public {
        (bytes memory v0, bytes memory qt, bytes memory q) = _keys(ALPHA + 1);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.KeyMismatch.selector);
        registry.createRegistry(credDefId, keccak256("other"), v0, qt, q);
    }

    function test_createRegistryOnlyIssuer() public {
        (bytes memory v0, bytes memory qt, bytes memory q) = _keys(ALPHA);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        registry.createRegistry(credDefId, keccak256("other"), v0, qt, q);
    }

    function test_publishSrsRejectsWrongPowers() public {
        (bytes memory v0, bytes memory qt, bytes memory q) = _keys(ALPHA);
        vm.prank(alice);
        bytes32 r2 = registry.createRegistry(credDefId, keccak256("p2"), v0, qt, q);
        (bytes[] memory p1, bytes[] memory p2) = _srs(3);
        p1[3] = BLS.g1Mul(BLS.g1(), 99);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.SrsStructureInvalid.selector);
        registry.publishSrs(r2, p1, p2);
        (p1, p2) = _srs(3);
        p2[2] = BLS.g2Mul(BLS.g2(), 99);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.SrsStructureInvalid.selector);
        registry.publishSrs(r2, p1, p2);
    }

    function test_publishSrsTwiceReverts() public {
        (bytes[] memory p1, bytes[] memory p2) = _srs(SRS_DEGREE);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.SrsAlreadyPublished.selector);
        registry.publishSrs(regId, p1, p2);
    }

    // ------------------------------------------------------------ kiadás

    function test_issue() public {
        _issue(Y1);
        (bytes memory A,, bytes memory I, bytes memory W, uint64 v) = registry.getValues(regId);
        assertEq(A, _v0()); // static add
        assertEq(I, curI);
        assertEq(W, curW);
        assertEq(v, 1);
        assertEq(registry.valuesHashAt(regId, 1), keccak256(abi.encode(curA, curR, curI)));
    }

    function test_issueWrongSchnorrReverts() public {
        StateRegistry.IssueStep memory s = _issueStep(Y1);
        s.z = addmod(s.z, 1, BLS.R);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.IssueProofFailed.selector);
        registry.issueUpdate(regId, s);
    }

    function test_issueWrongStepReverts() public {
        StateRegistry.IssueStep memory s = _issueStep(Y1);
        s.newI = BLS.g1Mul(curI, addmod(Y1, ALPHA + 1, BLS.R)); // két tényező helyett más
        s.R = BLS.g1Mul(curI, 0xbeef + Y1);
        uint256 c = registry.issueChallenge(regId, s.newI, s.T, s.R);
        s.z = addmod(0xbeef + Y1, mulmod(c, Y1, BLS.R), BLS.R);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.StepCheckFailed.selector);
        registry.issueUpdate(regId, s);
    }

    function test_issueOnlyIssuer() public {
        StateRegistry.IssueStep memory s = _issueStep(Y1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        registry.issueUpdate(regId, s);
    }

    // ------------------------------------------------------------ visszavonás

    function test_revoke() public {
        _issue(Y1);
        _issue(Y2);
        _revoke(Y1);
        (bytes memory A, bytes memory R,,, uint64 v) = registry.getValues(regId);
        assertEq(A, curA);
        assertEq(R, curR);
        assertEq(v, 3);
        assertTrue(registry.isRevoked(regId, bytes32(Y1)));
        assertEq(registry.revokedAt(regId, bytes32(Y1)), 3);
        assertEq(registry.revokedCount(regId), 1);
        // A és R̃ ugyanazt a visszavont halmazt kódolja
        assertTrue(BLS.pairingEq(curA, curR, _v0(), BLS.g2()));
    }

    function test_revokeWrongStepReverts() public {
        _issue(Y1);
        (, bytes memory r, bytes memory w) = _revokeValues(Y1);
        bytes memory bad = BLS.g1Mul(curA, 7);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.StepCheckFailed.selector);
        registry.revoke(regId, bytes32(Y1), bad, r, w);
    }

    function test_revokeInconsistentRtildeReverts() public {
        _issue(Y1);
        (bytes memory a,, bytes memory w) = _revokeValues(Y1);
        bytes memory bad = BLS.g2Mul(curR, 7);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.ConsistencyCheckFailed.selector);
        registry.revoke(regId, bytes32(Y1), a, bad, w);
    }

    function test_revokeWrongWIRReverts() public {
        _issue(Y1);
        (bytes memory a, bytes memory r,) = _revokeValues(Y1);
        bytes memory bad = BLS.g1Mul(curW, 7);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.SubsetCheckFailed.selector);
        registry.revoke(regId, bytes32(Y1), a, r, bad);
    }

    function test_revokeStaleValuesReverts() public {
        _issue(Y1);
        _issue(Y2);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y1);
        _revoke(Y2); // közben más visszavonás: a régi állapotból számolt értékek már nem lépnek
        vm.prank(alice);
        vm.expectRevert(StateRegistry.StepCheckFailed.selector);
        registry.revoke(regId, bytes32(Y1), a, r, w);
    }

    function test_revokeTwiceReverts() public {
        _issue(Y1);
        _revoke(Y1);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.AlreadyRevoked.selector, bytes32(Y1)));
        registry.revoke(regId, bytes32(Y1), a, r, w);
    }

    function test_revokeOutOfFieldReverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.RevocationIdOutOfField.selector, bytes32(BLS.R)));
        registry.revoke(regId, bytes32(BLS.R), curA, curR, curW);
    }

    // ------------------------------------------------------------ csoportok

    function test_createGroupOfIssued() public {
        _issue(Y1);
        _issue(Y2);
        _issue(Y3);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        assertTrue(registry.isGroupMember(g, bytes32(Y1)));
        assertFalse(registry.isGroupMember(g, bytes32(Y3)));
        assertEq(registry.groupVersion(g), 0);
        _revoke(Y3);
        assertEq(registry.groupVersion(g), 0);
        _revoke(Y2);
        assertEq(registry.groupVersion(g), 1);
    }

    /// A tanú α nélkül csak a kiadott halmaz ismeretében számolható; rossz tanúval nincs csoport.
    /// (α birtokában bármely halmazhoz van tanú: tisztességes issuer mellett köt, mint minden α-beli ellenőrzés.)
    function test_createGroupWrongWitnessReverts() public {
        _issue(Y1);
        _issue(Y2);
        _issue(Y3);
        bytes memory ws = _groupWitness(_members(Y1, Y2));
        (, bytes[] memory p2) = _srs(SRS_DEGREE);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.GroupSubsetCheckFailed.selector);
        registry.createGroup(regId, LABEL, _members(Y1, Y3), ws, p2);
    }

    function test_createGroupUnsortedReverts() public {
        (, bytes[] memory p2) = _srs(SRS_DEGREE);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.MembersNotSorted.selector, 1));
        registry.createGroup(regId, LABEL, _members(Y2, Y1), curI, p2);
    }

    function test_createGroupTooLargeReverts() public {
        (, bytes[] memory p2) = _srs(SRS_DEGREE);
        bytes32[] memory m = new bytes32[](5);
        for (uint256 i = 0; i < 5; i++) m[i] = bytes32(i + 1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GroupTooLarge.selector, 5, SRS_DEGREE));
        registry.createGroup(regId, LABEL, m, curI, p2);
    }

    // ------------------------------------------------------------ policy-k és guardolt frissítés

    function _groupPolicy(bytes32 g, PolicyRegistry.Class cls, PolicyRegistry.CasMode mode) internal returns (bytes32) {
        PolicyRegistry.Binding[] memory b = new PolicyRegistry.Binding[](1);
        b[0] = PolicyRegistry.Binding({name: "S", kind: PolicyRegistry.BindingKind.Group, target: g});
        vm.prank(alice);
        return policies.registerPolicy("forall x in S. NotRevoked(x)", cls, mode, b);
    }

    function _guard(bytes32 policyId, uint64 v) internal pure returns (StateRegistry.Guard memory g) {
        g.policyId = policyId;
        g.expectedVersions = new uint64[](1);
        g.expectedVersions[0] = v;
        g.proofHash = keccak256("proof");
    }

    function test_policyCasModeTooWeakReverts() public {
        PolicyRegistry.Binding[] memory b = new PolicyRegistry.Binding[](1);
        b[0] = PolicyRegistry.Binding({name: "R", kind: PolicyRegistry.BindingKind.Registry, target: regId});
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.CasModeTooWeak.selector, PolicyRegistry.CasMode.None, PolicyRegistry.CasMode.Global));
        policies.registerPolicy("forall x in Issued. NotRevoked(x)", PolicyRegistry.Class.CoStable, PolicyRegistry.CasMode.None, b);
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.GroupModeNeedsGroups.selector, 0));
        policies.registerPolicy("forall x in Issued. NotRevoked(x)", PolicyRegistry.Class.CoStable, PolicyRegistry.CasMode.Group, b);
    }

    function test_bindPolicyOnlyIssuer() public {
        bytes32 p = _groupPolicy(bytes32(0), PolicyRegistry.Class.Stable, PolicyRegistry.CasMode.None);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.NotIssuer.selector, credDefId, bob));
        policies.bindPolicy(credDefId, PolicyRegistry.Action.Revoke, p);
    }

    /// a lakásfoglalás: Alice és Bob ugyanarra a csoportverzióra köti a guardot, csak az első megy át
    function test_flatReservationCas() public {
        _issue(Y1);
        _issue(Y2);
        _issue(Y3);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _groupPolicy(g, PolicyRegistry.Class.CoStable, PolicyRegistry.CasMode.Group);
        vm.prank(alice);
        policies.bindPolicy(credDefId, PolicyRegistry.Action.Revoke, p);

        // kötött policy mellett a nem őrzött visszavonás tilos
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y3);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.PolicyRequired.selector, p));
        registry.revoke(regId, bytes32(Y3), a, r, w);

        uint64 gv = registry.groupVersion(g);
        // Alice foglal
        (a, r, w) = _revokeValues(Y1);
        vm.prank(alice);
        registry.guardedRevoke(regId, bytes32(Y1), a, r, w, _guard(p, gv));
        curA = a; curR = r; curW = w;
        // Bob ugyanarra a verzióra kötött guarddal: elutasítva
        (a, r, w) = _revokeValues(Y2);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleGroupVersion.selector, g, gv, gv + 1));
        registry.guardedRevoke(regId, bytes32(Y2), a, r, w, _guard(p, gv));
    }

    function test_groupCasIgnoresOutsideRevocation() public {
        _issue(Y1);
        _issue(Y2);
        _issue(Y3);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _groupPolicy(g, PolicyRegistry.Class.CoStable, PolicyRegistry.CasMode.Group);
        uint64 gv = registry.groupVersion(g);
        _revoke(Y3); // a csoporton kívül
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y1);
        vm.prank(alice);
        registry.guardedRevoke(regId, bytes32(Y1), a, r, w, _guard(p, gv));
    }

    function test_globalCasRejectsAnyUpdate() public {
        _issue(Y1);
        _issue(Y2);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _groupPolicy(g, PolicyRegistry.Class.Volatile, PolicyRegistry.CasMode.Global);
        (,,,, uint64 v) = registry.getValues(regId);
        _issue(Y3);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.StaleVersion.selector, 0, v, v + 1));
        registry.guardedRevoke(regId, bytes32(Y1), a, r, w, _guard(p, v));
    }

    function test_stableGuardNeedsNoComparison() public {
        _issue(Y1);
        _issue(Y2);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _groupPolicy(g, PolicyRegistry.Class.Stable, PolicyRegistry.CasMode.None);
        _revoke(Y1);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y2);
        vm.prank(alice);
        registry.guardedRevoke(regId, bytes32(Y2), a, r, w, _guard(p, 12345));
    }

    function test_wrongPolicyReverts() public {
        _issue(Y1);
        _issue(Y2);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _groupPolicy(g, PolicyRegistry.Class.CoStable, PolicyRegistry.CasMode.Group);
        bytes32 other = _groupPolicy(g, PolicyRegistry.Class.Stable, PolicyRegistry.CasMode.None);
        vm.prank(alice);
        policies.bindPolicy(credDefId, PolicyRegistry.Action.Revoke, p);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.WrongPolicy.selector, p, other));
        registry.guardedRevoke(regId, bytes32(Y1), a, r, w, _guard(other, 0));
    }

    /// kiadási szabály: kiadás csak akkor, ha a csoportban már valakit visszavontak (stable guard)
    function test_guardedIssueAcrossRegistries() public {
        _issue(Y1);
        _issue(Y2);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        PolicyRegistry.Binding[] memory b = new PolicyRegistry.Binding[](1);
        b[0] = PolicyRegistry.Binding({name: "M", kind: PolicyRegistry.BindingKind.Group, target: g});
        vm.prank(alice);
        bytes32 p = policies.registerPolicy("exists x in M. Revoked(x)", PolicyRegistry.Class.Stable, PolicyRegistry.CasMode.None, b);
        vm.prank(alice);
        policies.bindPolicy(credDefId, PolicyRegistry.Action.Issue, p);

        StateRegistry.IssueStep memory s = _issueStep(Y3);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.PolicyRequired.selector, p));
        registry.issueUpdate(regId, s);
        vm.prank(alice);
        registry.guardedIssueUpdate(regId, s, _guard(p, 0));
    }

    function testFuzz_nonIssuerCannotRevoke(address caller) public {
        vm.assume(caller != alice);
        _issue(Y1);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y1);
        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, caller));
        registry.revoke(regId, bytes32(Y1), a, r, w);
    }
}
