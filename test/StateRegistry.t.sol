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

    function _issueValues(uint256 y) internal view returns (bytes memory newI, bytes memory newW) {
        uint256 f = addmod(y, ALPHA, BLS.R);
        newI = BLS.g1Mul(curI, f);
        newW = BLS.g1Mul(curW, f);
    }

    function _issue(uint256 y) internal {
        (bytes memory i, bytes memory w) = _issueValues(y);
        vm.prank(alice);
        registry.issueUpdate(regId, bytes32(y), i, w);
        curI = i;
        curW = w;
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
        curA = a;
        curR = r;
        curW = w;
    }

    function _members(uint256 a, uint256 b) internal pure returns (bytes32[] memory m) {
        m = new bytes32[](2);
        m[0] = bytes32(a);
        m[1] = bytes32(b);
    }

    function _createGroup(bytes32 label, bytes32[] memory members) internal returns (bytes32) {
        vm.prank(alice);
        return registry.createGroup(regId, label, members);
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

    /// a kiadás nyilvános: az y a tárolóban és az eseményben is látszik
    function test_issueRevealsY() public {
        (bytes memory i, bytes memory w) = _issueValues(Y1);
        vm.expectEmit(true, true, true, true);
        emit StateRegistry.Issued(regId, 1, bytes32(Y1), i, w, bytes32(0));
        vm.prank(alice);
        registry.issueUpdate(regId, bytes32(Y1), i, w);
        assertTrue(registry.isIssued(regId, bytes32(Y1)));
        assertEq(registry.issuedAt(regId, bytes32(Y1)), 1);
        assertEq(registry.issuedCount(regId), 1);
        bytes32[] memory log = registry.getIssuedLog(regId, 0, 10);
        assertEq(log.length, 1);
        assertEq(log[0], bytes32(Y1));
    }

    function test_issueTwiceReverts() public {
        _issue(Y1);
        (bytes memory i, bytes memory w) = _issueValues(Y1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.AlreadyIssued.selector, bytes32(Y1)));
        registry.issueUpdate(regId, bytes32(Y1), i, w);
    }

    function test_issueZeroIdReverts() public {
        vm.prank(alice);
        vm.expectRevert(StateRegistry.EmptyRevocationId.selector);
        registry.issueUpdate(regId, bytes32(0), curI, curW);
    }

    function test_issueOutOfFieldReverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.RevocationIdOutOfField.selector, bytes32(BLS.R)));
        registry.issueUpdate(regId, bytes32(BLS.R), curI, curW);
    }

    /// y = −α esetén I' = I^0 a végtelen távoli pont: elutasítjuk (és egy ilyen y α-t is felfedné)
    function test_issueMinusAlphaReverts() public {
        uint256 y = BLS.R - ALPHA;
        (bytes memory i, bytes memory w) = _issueValues(y);
        assertTrue(BLS.isZero(i));
        vm.prank(alice);
        vm.expectRevert(StateRegistry.InvalidPoint.selector);
        registry.issueUpdate(regId, bytes32(y), i, w);
    }

    function test_issueWrongStepReverts() public {
        (, bytes memory w) = _issueValues(Y1);
        bytes memory bad = BLS.g1Mul(curI, addmod(Y1, ALPHA + 1, BLS.R)); // más tényező
        vm.prank(alice);
        vm.expectRevert(StateRegistry.StepCheckFailed.selector);
        registry.issueUpdate(regId, bytes32(Y1), bad, w);
    }

    function test_issueWrongWIRReverts() public {
        (bytes memory i,) = _issueValues(Y1);
        bytes memory bad = BLS.g1Mul(curW, 7);
        vm.prank(alice);
        vm.expectRevert(StateRegistry.SubsetCheckFailed.selector);
        registry.issueUpdate(regId, bytes32(Y1), i, bad);
    }

    function test_issueOnlyIssuer() public {
        (bytes memory i, bytes memory w) = _issueValues(Y1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, bob));
        registry.issueUpdate(regId, bytes32(Y1), i, w);
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

    function test_revokeNotIssuedReverts() public {
        _issue(Y1);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y2);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssued.selector, bytes32(Y2)));
        registry.revoke(regId, bytes32(Y2), a, r, w);
    }

    /// A trapdoor birtokosa minden pairing-ellenőrzést kielégítő értékeket tud számolni egy soha ki nem adott
    /// ID visszavonásához, a W_IR-t is: W_IR' = g^(P_Iss(α)/P_Rev'(α)). A visszavont ⊆ kiadott relációt
    /// ezért a tároló köti, nem a (5) ellenőrzés.
    function test_issuerWithAlphaCannotRevokeUnissued() public {
        _issue(Y1);
        uint256 f = addmod(Y2, ALPHA, BLS.R);
        bytes memory a = BLS.g1Mul(curA, BLS.frInv(f));
        bytes memory r = BLS.g2Mul(curR, f);
        uint256 pIss = addmod(Y1, ALPHA, BLS.R);
        bytes memory w = BLS.g1Mul(BLS.g1(), mulmod(pIss, BLS.frInv(f), BLS.R));
        // mindhárom egyenlet teljesül
        bytes[] memory ps = new bytes[](2);
        uint256[] memory ss = new uint256[](2);
        ps[0] = BLS.g2();
        ss[0] = Y2;
        ps[1] = BLS.g2Mul(BLS.g2(), ALPHA);
        ss[1] = 1;
        assertTrue(BLS.pairingEq(a, BLS.g2Msm(ps, ss), curA, BLS.g2()));
        assertTrue(BLS.pairingEq(a, r, _v0(), BLS.g2()));
        assertTrue(BLS.pairingEq(w, r, curI, BLS.g2()));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.NotIssued.selector, bytes32(Y2)));
        registry.revoke(regId, bytes32(Y2), a, r, w);
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

    /// csak kiadott ID lehet tag: ezt a tároló dönti el, így az α birtokosát is köti
    function test_createGroupMemberNotIssuedReverts() public {
        _issue(Y1);
        _issue(Y2);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.MemberNotIssued.selector, bytes32(Y3)));
        registry.createGroup(regId, LABEL, _members(Y1, Y3));
    }

    /// csoportot bárki létrehozhat, például a verifier
    function test_createGroupByAnyone() public {
        _issue(Y1);
        _issue(Y2);
        vm.prank(bob);
        bytes32 g = registry.createGroup(regId, LABEL, _members(Y1, Y2));
        (, address creator,,) = registry.getGroup(g);
        assertEq(creator, bob);
    }

    function test_createGroupUnsortedReverts() public {
        _issue(Y1);
        _issue(Y2);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.MembersNotSorted.selector, 1));
        registry.createGroup(regId, LABEL, _members(Y2, Y1));
    }

    function test_createGroupTooLargeReverts() public {
        bytes32[] memory m = new bytes32[](5);
        for (uint256 i = 0; i < 5; i++) {
            m[i] = bytes32(i + 1);
        }
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GroupTooLarge.selector, 5, SRS_DEGREE));
        registry.createGroup(regId, LABEL, m);
    }

    // ------------------------------------------------------------ policy-k és guardolt frissítés

    function _clause(PolicyRegistry.Quant q, uint32 k, PolicyRegistry.Domain d, uint8 b, PolicyRegistry.Polarity body)
        internal
        pure
        returns (PolicyRegistry.Op memory op)
    {
        op = PolicyRegistry.Op({kind: PolicyRegistry.OpKind.Clause, quant: q, k: k, domain: d, binding: b, body: body});
    }

    function _connective(PolicyRegistry.OpKind kind) internal pure returns (PolicyRegistry.Op memory op) {
        op.kind = kind;
    }

    function _ops(PolicyRegistry.Op memory a) internal pure returns (PolicyRegistry.Op[] memory ops) {
        ops = new PolicyRegistry.Op[](1);
        ops[0] = a;
    }

    function _none() internal pure returns (PolicyRegistry.Op[] memory) {
        return new PolicyRegistry.Op[](0);
    }

    function _bind(bytes32 name, PolicyRegistry.BindingKind kind, bytes32 target)
        internal
        pure
        returns (PolicyRegistry.Binding[] memory b)
    {
        b = new PolicyRegistry.Binding[](1);
        b[0] = PolicyRegistry.Binding({name: name, kind: kind, target: target});
    }

    function _policy(
        string memory q,
        PolicyRegistry.Binding[] memory b,
        PolicyRegistry.Op[] memory pres,
        PolicyRegistry.Op[] memory pub
    ) internal returns (bytes32) {
        vm.prank(alice);
        return policies.registerPolicy(q, b, pres, pub);
    }

    /// ∀x∈S. NotRevoked(x): a foglalás guardja, csak nyilvános rész
    function _reservationPolicy(bytes32 g) internal returns (bytes32) {
        return _policy(
            "forall x in S. NotRevoked(x)",
            _bind("S", PolicyRegistry.BindingKind.Group, g),
            _none(),
            _ops(_clause(PolicyRegistry.Quant.All, 0, PolicyRegistry.Domain.Group, 0, PolicyRegistry.Polarity.Down))
        );
    }

    function _guard(bytes32 policyId, uint64 v) internal pure returns (StateRegistry.Guard memory g) {
        g.policyId = policyId;
        g.expectedVersions = new uint64[](1);
        g.expectedVersions[0] = v;
        g.proof = bytes("proof");
    }

    function _bindTo(PolicyRegistry.Action action, bytes32 p) internal {
        vm.prank(alice);
        policies.bindPolicy(credDefId, action, p);
    }

    function _guardedRevoke(uint256 y, StateRegistry.Guard memory g) internal {
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(y);
        vm.prank(alice);
        registry.guardedRevoke(regId, bytes32(y), a, r, w, g);
        curA = a;
        curR = r;
        curW = w;
    }

    function _expectGuardedRevokeReverts(uint256 y, StateRegistry.Guard memory g, bytes memory err) internal {
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(y);
        vm.prank(alice);
        vm.expectRevert(err);
        registry.guardedRevoke(regId, bytes32(y), a, r, w, g);
    }

    /// a GUARDS.md táblázatának sorai és a négy osztály
    function test_registerPolicyComputesClass() public {
        PolicyRegistry.Quant All = PolicyRegistry.Quant.All;
        PolicyRegistry.Quant Ex = PolicyRegistry.Quant.Exists;
        PolicyRegistry.Quant AtMost = PolicyRegistry.Quant.AtMost;
        PolicyRegistry.Domain G = PolicyRegistry.Domain.Group;
        PolicyRegistry.Domain Iss = PolicyRegistry.Domain.Issued;
        PolicyRegistry.Domain P = PolicyRegistry.Domain.Presented;
        PolicyRegistry.Polarity Up = PolicyRegistry.Polarity.Up;
        PolicyRegistry.Polarity Down = PolicyRegistry.Polarity.Down;

        // foglalás: ∀x∈S. NotRevoked(x) → co-stable
        assertEq(uint8(policies.classify(_ops(_clause(All, 0, G, 0, Down)))), uint8(PolicyRegistry.Class.CoStable));
        // a lakás foglalt: ∃x∈S. Revoked(x) → stable
        assertEq(uint8(policies.classify(_ops(_clause(Ex, 0, G, 0, Up)))), uint8(PolicyRegistry.Class.Stable));
        // bérlet: ∃x∈Presented. Revoked(x) → stable
        assertEq(uint8(policies.classify(_ops(_clause(Ex, 0, P, 0, Up)))), uint8(PolicyRegistry.Class.Stable));
        // a bemutatott még érvényes: ∃x∈Presented. NotRevoked(x) → co-stable
        assertEq(uint8(policies.classify(_ops(_clause(Ex, 0, P, 0, Down)))), uint8(PolicyRegistry.Class.CoStable));
        // legfeljebb egy aktív: atmost 1 x∈Issued. NotRevoked(x) → volatile
        assertEq(uint8(policies.classify(_ops(_clause(AtMost, 1, Iss, 0, Down)))), uint8(PolicyRegistry.Class.Volatile));
        // senki sincs visszavonva: ∀x∈Issued. NotRevoked(x) → co-stable
        assertEq(uint8(policies.classify(_ops(_clause(All, 0, Iss, 0, Down)))), uint8(PolicyRegistry.Class.CoStable));
        // van aktív: ∃x∈Issued. NotRevoked(x) → volatile
        assertEq(uint8(policies.classify(_ops(_clause(Ex, 0, Iss, 0, Down)))), uint8(PolicyRegistry.Class.Volatile));
        // mind visszavonva: ∀x∈Issued. Revoked(x) → volatile
        assertEq(uint8(policies.classify(_ops(_clause(All, 0, Iss, 0, Up)))), uint8(PolicyRegistry.Class.Volatile));
        // legfeljebb k visszavont: atmost 2 x∈Issued. Revoked(x) → co-stable
        assertEq(uint8(policies.classify(_ops(_clause(AtMost, 2, Iss, 0, Up)))), uint8(PolicyRegistry.Class.CoStable));
        // atmost egy fix halmazon megfordít: atmost 1 x∈S. Revoked(x) → co-stable
        assertEq(uint8(policies.classify(_ops(_clause(AtMost, 1, G, 0, Up)))), uint8(PolicyRegistry.Class.CoStable));
        // csak hitelesítő atom: ∃x∈Presented. Sig(x) → állapotfüggetlen
        assertEq(
            uint8(policies.classify(_ops(_clause(Ex, 0, P, 0, PolicyRegistry.Polarity.Neutral)))),
            uint8(PolicyRegistry.Class.StateIndependent)
        );
        // üres program → állapotfüggetlen
        assertEq(uint8(policies.classify(_none())), uint8(PolicyRegistry.Class.StateIndependent));
        // ∧ és ∨ join: stable ∧ co-stable → volatile, stable ∨ stable → stable
        PolicyRegistry.Op[] memory mixed = new PolicyRegistry.Op[](3);
        mixed[0] = _clause(Ex, 0, P, 0, Up);
        mixed[1] = _clause(Ex, 0, P, 0, Down);
        mixed[2] = _connective(PolicyRegistry.OpKind.And);
        assertEq(uint8(policies.classify(mixed)), uint8(PolicyRegistry.Class.Volatile));
        mixed[1] = _clause(Ex, 0, P, 0, Up);
        mixed[2] = _connective(PolicyRegistry.OpKind.Or);
        assertEq(uint8(policies.classify(mixed)), uint8(PolicyRegistry.Class.Stable));

        // a regisztrált policy a kiszámolt osztályt tárolja, deklaráció nélkül
        PolicyRegistry.Binding[] memory b = _bind("R", PolicyRegistry.BindingKind.Registry, regId);
        bytes32 p = _policy(
            "exists x in Presented. NotRevoked(x) & atmost 1 y in Issued. NotRevoked(y)",
            b,
            _ops(_clause(Ex, 0, P, 0, Down)),
            _ops(_clause(AtMost, 1, Iss, 0, Down))
        );
        assertEq(uint8(policies.presentedClass(p)), uint8(PolicyRegistry.Class.CoStable));
        assertEq(uint8(policies.publicClass(p)), uint8(PolicyRegistry.Class.Volatile));
    }

    function test_registerPolicyRejectsMalformed() public {
        PolicyRegistry.Binding[] memory g = _bind("S", PolicyRegistry.BindingKind.Group, bytes32(uint256(1)));
        PolicyRegistry.Binding[] memory reg = _bind("R", PolicyRegistry.BindingKind.Registry, regId);
        PolicyRegistry.Op memory ok =
            _clause(PolicyRegistry.Quant.All, 0, PolicyRegistry.Domain.Group, 0, PolicyRegistry.Polarity.Down);

        vm.expectRevert(PolicyRegistry.EmptyQuery.selector);
        policies.registerPolicy("", g, _none(), _ops(ok));

        PolicyRegistry.Binding[] memory dup = new PolicyRegistry.Binding[](2);
        dup[0] = g[0];
        dup[1] = g[0];
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.DuplicateBindingName.selector, 1));
        policies.registerPolicy("q", dup, _none(), _ops(ok));

        PolicyRegistry.Op[] memory long = new PolicyRegistry.Op[](33);
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.ProgramTooLong.selector, 33));
        policies.registerPolicy("q", g, _none(), long);

        PolicyRegistry.Op[] memory lonely = new PolicyRegistry.Op[](2);
        lonely[0] = ok;
        lonely[1] = _connective(PolicyRegistry.OpKind.And);
        vm.expectRevert(PolicyRegistry.MalformedProgram.selector);
        policies.registerPolicy("q", g, _none(), lonely);

        PolicyRegistry.Op[] memory two = new PolicyRegistry.Op[](2);
        two[0] = ok;
        two[1] = ok;
        vm.expectRevert(PolicyRegistry.MalformedProgram.selector);
        policies.registerPolicy("q", g, _none(), two);

        PolicyRegistry.Op memory badIdx =
            _clause(PolicyRegistry.Quant.All, 0, PolicyRegistry.Domain.Group, 1, PolicyRegistry.Polarity.Down);
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadBinding.selector, 0));
        policies.registerPolicy("q", g, _none(), _ops(badIdx));

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.DomainBindingMismatch.selector, 0));
        policies.registerPolicy("q", reg, _none(), _ops(ok));

        // presented program: csak Presented, csak ∃ és atleast, ∃-nél k = 0
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadPresentedClause.selector, 0));
        policies.registerPolicy("q", g, _ops(ok), _none());
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadPresentedClause.selector, 0));
        policies.registerPolicy(
            "q",
            reg,
            _ops(
                _clause(PolicyRegistry.Quant.All, 0, PolicyRegistry.Domain.Presented, 0, PolicyRegistry.Polarity.Down)
            ),
            _none()
        );
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadPresentedClause.selector, 0));
        policies.registerPolicy(
            "q",
            reg,
            _ops(
                _clause(
                    PolicyRegistry.Quant.Exists, 3, PolicyRegistry.Domain.Presented, 0, PolicyRegistry.Polarity.Down
                )
            ),
            _none()
        );

        // public program: nem Presented, a törzs Up vagy Down, ∀-nél k = 0
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadPublicClause.selector, 0));
        policies.registerPolicy(
            "q",
            reg,
            _none(),
            _ops(
                _clause(
                    PolicyRegistry.Quant.Exists, 0, PolicyRegistry.Domain.Presented, 0, PolicyRegistry.Polarity.Down
                )
            )
        );
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadPublicClause.selector, 0));
        policies.registerPolicy(
            "q",
            g,
            _none(),
            _ops(_clause(PolicyRegistry.Quant.All, 0, PolicyRegistry.Domain.Group, 0, PolicyRegistry.Polarity.Mixed))
        );
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadPublicClause.selector, 0));
        policies.registerPolicy(
            "q",
            g,
            _none(),
            _ops(_clause(PolicyRegistry.Quant.All, 2, PolicyRegistry.Domain.Group, 0, PolicyRegistry.Polarity.Down))
        );
    }

    function test_policyIdCoversPrograms() public {
        PolicyRegistry.Binding[] memory g = _bind("S", PolicyRegistry.BindingKind.Group, bytes32(uint256(1)));
        PolicyRegistry.Op memory down =
            _clause(PolicyRegistry.Quant.All, 0, PolicyRegistry.Domain.Group, 0, PolicyRegistry.Polarity.Down);
        PolicyRegistry.Op memory up =
            _clause(PolicyRegistry.Quant.All, 0, PolicyRegistry.Domain.Group, 0, PolicyRegistry.Polarity.Up);
        bytes32 a = _policy("q", g, _none(), _ops(down));
        bytes32 b = _policy("q", g, _none(), _ops(up));
        assertTrue(a != b);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.PolicyExists.selector, a));
        policies.registerPolicy("q", g, _none(), _ops(down));
    }

    function test_bindPolicyOnlyIssuer() public {
        bytes32 p = _reservationPolicy(bytes32(0));
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.NotIssuer.selector, credDefId, bob));
        policies.bindPolicy(credDefId, PolicyRegistry.Action.Revoke, p);
    }

    /// kiadási szabály: kiadás csak akkor, ha a csoportban már valakit visszavontak; a contract kiértékeli
    function test_publicGuardEvaluatedOnChain() public {
        _issue(Y1);
        _issue(Y2);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _policy(
            "exists x in M. Revoked(x)",
            _bind("M", PolicyRegistry.BindingKind.Group, g),
            _none(),
            _ops(_clause(PolicyRegistry.Quant.Exists, 0, PolicyRegistry.Domain.Group, 0, PolicyRegistry.Polarity.Up))
        );
        _bindTo(PolicyRegistry.Action.Issue, p);

        (bytes memory i, bytes memory w) = _issueValues(Y3);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GuardFalse.selector, p));
        registry.guardedIssueUpdate(regId, bytes32(Y3), i, w, _guard(p, 0));

        _revoke(Y1);
        (i, w) = _issueValues(Y3);
        vm.prank(alice);
        registry.guardedIssueUpdate(regId, bytes32(Y3), i, w, _guard(p, 0));
    }

    /// a lakásfoglalás: Alice és Bob ugyanarra az állapotra készül; az első foglalás után a guard hamis
    function test_flatReservationRaceDecidedOnChain() public {
        _issue(Y1);
        _issue(Y2);
        _issue(Y3);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _reservationPolicy(g);
        _bindTo(PolicyRegistry.Action.Revoke, p);
        uint64 gv = registry.groupVersion(g);

        _guardedRevoke(Y1, _guard(p, gv)); // Alice foglal
        _expectGuardedRevokeReverts(Y2, _guard(p, gv), abi.encodeWithSelector(StateRegistry.GuardFalse.selector, p));
    }

    /// az egyetlen író, a kibocsátó sem foglalhatja le kétszer a lakást: egyik út sem vezet át
    function test_issuerCannotReserveTwice() public {
        _issue(Y1);
        _issue(Y2);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _reservationPolicy(g);
        _bindTo(PolicyRegistry.Action.Revoke, p);
        _guardedRevoke(Y1, _guard(p, 0));

        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y2);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.PolicyRequired.selector, p));
        registry.revoke(regId, bytes32(Y2), a, r, w);

        bytes32 lax = _policy(
            "exists x in S. Revoked(x)",
            _bind("S", PolicyRegistry.BindingKind.Group, g),
            _none(),
            _ops(_clause(PolicyRegistry.Quant.Exists, 0, PolicyRegistry.Domain.Group, 0, PolicyRegistry.Polarity.Up))
        );
        _expectGuardedRevokeReverts(
            Y2, _guard(lax, 0), abi.encodeWithSelector(StateRegistry.WrongPolicy.selector, p, lax)
        );
        for (uint64 v = 0; v < 4; v++) {
            _expectGuardedRevokeReverts(Y2, _guard(p, v), abi.encodeWithSelector(StateRegistry.GuardFalse.selector, p));
        }
    }

    /// The supported public at-most predicate is evaluated from ledger counts.
    function test_publicAtMostUsesCounters() public {
        _issue(Y1);
        _issue(Y2);
        _issue(Y3);
        PolicyRegistry.Binding[] memory b = _bind("R", PolicyRegistry.BindingKind.Registry, regId);
        bytes32 p = _policy(
            "atmost 1 y in Issued. NotRevoked(y)",
            b,
            _none(),
            _ops(_clause(PolicyRegistry.Quant.AtMost, 1, PolicyRegistry.Domain.Issued, 0, PolicyRegistry.Polarity.Down))
        );
        _bindTo(PolicyRegistry.Action.Issue, p);

        (,,,, uint64 v) = registry.getValues(regId);
        (bytes memory i, bytes memory w) = _issueValues(Y4);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GuardFalse.selector, p)); // három aktív
        registry.guardedIssueUpdate(regId, bytes32(Y4), i, w, _guard(p, v));

        _revoke(Y1);
        _revoke(Y2);
        (,,,, v) = registry.getValues(regId);
        (i, w) = _issueValues(Y4);
        vm.prank(alice);
        registry.guardedIssueUpdate(regId, bytes32(Y4), i, w, _guard(p, v));
    }

    function _presentedPolicy(PolicyRegistry.Polarity polarity) internal returns (bytes32) {
        return _policy(
            "private predicate",
            _bind("R", PolicyRegistry.BindingKind.Registry, regId),
            _ops(_clause(PolicyRegistry.Quant.Exists, 0, PolicyRegistry.Domain.Presented, 0, polarity)),
            _none()
        );
    }

    function test_presentedPolicyCannotBindUpdates() public {
        // All classes are excluded, including stable and state-independent programs.
        for (uint8 polarity = 0; polarity < 4; polarity++) {
            bytes32 p = _presentedPolicy(PolicyRegistry.Polarity(polarity));
            for (uint8 action = 0; action < 2; action++) {
                vm.prank(alice);
                vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.UnsupportedPrivateGuard.selector, p));
                policies.bindPolicy(credDefId, PolicyRegistry.Action(action), p);
                assertEq(policies.boundPolicy(credDefId, PolicyRegistry.Action(action)), bytes32(0));
            }
        }
    }

    function test_presentedGuardCannotAuthorizeUnboundIssue() public {
        bytes32 p = _presentedPolicy(PolicyRegistry.Polarity.Up);
        (bytes memory i, bytes memory w) = _issueValues(Y1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnsupportedPrivateGuard.selector, p));
        registry.guardedIssueUpdate(regId, bytes32(Y1), i, w, _guard(p, 0));
        assertEq(registry.issuedCount(regId), 0);
    }

    function test_presentedGuardCannotAuthorizeUnboundRevoke() public {
        _issue(Y1);
        for (uint8 polarity = 0; polarity < 4; polarity++) {
            bytes32 p = _presentedPolicy(PolicyRegistry.Polarity(polarity));
            _expectGuardedRevokeReverts(
                Y1, _guard(p, 0), abi.encodeWithSelector(StateRegistry.UnsupportedPrivateGuard.selector, p)
            );
        }
        assertEq(registry.revokedCount(regId), 0);
    }

    function test_updatePolicyCannotBeRemovedOrReplaced() public {
        bytes32 p = _reservationPolicy(bytes32(0));
        bytes32 replacement = _policy("true", new PolicyRegistry.Binding[](0), _none(), _none());
        for (uint8 action = 0; action < 2; action++) {
            _bindTo(PolicyRegistry.Action(action), p);
            _bindTo(PolicyRegistry.Action(action), p); // Idempotence does not change the guarantee.
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.PolicyLocked.selector, p, bytes32(0)));
            policies.bindPolicy(credDefId, PolicyRegistry.Action(action), bytes32(0));
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.PolicyLocked.selector, p, replacement));
            policies.bindPolicy(credDefId, PolicyRegistry.Action(action), replacement);
            assertEq(policies.boundPolicy(credDefId, PolicyRegistry.Action(action)), p);
        }
    }

    function test_presentationPolicyRemainsMutable() public {
        bytes32 p = _presentedPolicy(PolicyRegistry.Polarity.Up);
        bytes32 other = _presentedPolicy(PolicyRegistry.Polarity.Down);
        _bindTo(PolicyRegistry.Action.Present, p);
        _bindTo(PolicyRegistry.Action.Present, other);
        assertEq(policies.boundPolicy(credDefId, PolicyRegistry.Action.Present), other);
        _bindTo(PolicyRegistry.Action.Present, bytes32(0));
        assertEq(policies.boundPolicy(credDefId, PolicyRegistry.Action.Present), bytes32(0));
    }

    function test_publicGuardedIssueAcrossRegistries() public {
        _issue(Y1);
        _issue(Y2);
        bytes32 sourceGroup = _createGroup(LABEL, _members(Y1, Y2));
        string[] memory attributes = new string[](1);
        attributes[0] = "flat";
        bytes32 destinationSchema = schemaRegistry.registerSchema("Lease", "1.0", true, attributes);
        vm.prank(alice);
        bytes32 destinationDef =
            credDefRegistry.registerCredDef(alice, destinationSchema, "default", keccak256("alice#bbs-key-2"));
        (bytes memory v0, bytes memory qt, bytes memory q) = _keys(ALPHA);
        vm.prank(alice);
        bytes32 destination = registry.createRegistry(destinationDef, keccak256("lease"), v0, qt, q);
        (bytes[] memory p1, bytes[] memory p2) = _srs(SRS_DEGREE);
        vm.prank(alice);
        registry.publishSrs(destination, p1, p2);
        bytes32 policy = _policy(
            "exists x in Interest. Revoked(x)",
            _bind("Interest", PolicyRegistry.BindingKind.Group, sourceGroup),
            _none(),
            _ops(_clause(PolicyRegistry.Quant.Exists, 0, PolicyRegistry.Domain.Group, 0, PolicyRegistry.Polarity.Up))
        );
        vm.prank(alice);
        policies.bindPolicy(destinationDef, PolicyRegistry.Action.Issue, policy);
        bytes memory newI = BLS.g1Mul(BLS.g1(), addmod(Y3, ALPHA, BLS.R));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.GuardFalse.selector, policy));
        registry.guardedIssueUpdate(destination, bytes32(Y3), newI, newI, _guard(policy, 0));
        assertEq(registry.issuedCount(destination), 0);

        // The source transition changes only its registry, and enables the destination's guard.
        _revoke(Y1);
        assertEq(registry.revokedCount(destination), 0);
        bytes32 differentPolicy = _policy(
            "exists x in Interest. Revoked(x)",
            _bind("Interest", PolicyRegistry.BindingKind.Registry, destination),
            _none(),
            _ops(_clause(PolicyRegistry.Quant.Exists, 0, PolicyRegistry.Domain.Issued, 0, PolicyRegistry.Polarity.Up))
        );
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.WrongPolicy.selector, policy, differentPolicy));
        registry.guardedIssueUpdate(destination, bytes32(Y3), newI, newI, _guard(differentPolicy, 0));
        vm.prank(alice);
        registry.guardedIssueUpdate(destination, bytes32(Y3), newI, newI, _guard(policy, 0));
        assertTrue(registry.isIssued(destination, bytes32(Y3)));
        assertFalse(registry.isIssued(regId, bytes32(Y3)));
    }

    function test_publicGuardRejectsUnknownGroup() public {
        bytes32 missing = keccak256("unknown group");
        bytes32 policy = _reservationPolicy(missing);
        (bytes memory newI, bytes memory newWIR) = _issueValues(Y1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.UnknownGroup.selector, missing));
        registry.guardedIssueUpdate(regId, bytes32(Y1), newI, newWIR, _guard(policy, 0));
        assertEq(registry.issuedCount(regId), 0);
    }

    function test_groupGuardIgnoresOutsideRevocation() public {
        _issue(Y1);
        _issue(Y2);
        _issue(Y3);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _reservationPolicy(g);
        _revoke(Y3); // a csoporton kívül
        _guardedRevoke(Y1, _guard(p, 0));
    }

    function test_wrongPolicyReverts() public {
        _issue(Y1);
        _issue(Y2);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _reservationPolicy(g);
        bytes32 other = _policy(
            "exists x in S. Revoked(x)",
            _bind("S", PolicyRegistry.BindingKind.Group, g),
            _none(),
            _ops(_clause(PolicyRegistry.Quant.Exists, 0, PolicyRegistry.Domain.Group, 0, PolicyRegistry.Polarity.Up))
        );
        _bindTo(PolicyRegistry.Action.Revoke, p);
        _expectGuardedRevokeReverts(
            Y1, _guard(other, 0), abi.encodeWithSelector(StateRegistry.WrongPolicy.selector, p, other)
        );
    }

    function test_unguardedUpdateRejectedWhenBound() public {
        _issue(Y1);
        _issue(Y2);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _reservationPolicy(g);
        _bindTo(PolicyRegistry.Action.Revoke, p);
        _bindTo(PolicyRegistry.Action.Issue, p);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.PolicyRequired.selector, p));
        registry.revoke(regId, bytes32(Y1), a, r, w);
        (bytes memory i, bytes memory iw) = _issueValues(Y3);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StateRegistry.PolicyRequired.selector, p));
        registry.issueUpdate(regId, bytes32(Y3), i, iw);
    }

    /// a guard bizonyítása láncra kerül: bárki utólag ellenőrizheti
    function test_guardProofEmitted() public {
        _issue(Y1);
        _issue(Y2);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _reservationPolicy(g);
        StateRegistry.Guard memory gd = _guard(p, 0);
        gd.proof = hex"c0ffee0102";
        (,,,, uint64 v) = registry.getValues(regId);
        vm.expectEmit(true, true, true, true);
        emit StateRegistry.GuardProof(regId, v + 1, p, hex"c0ffee0102");
        _guardedRevoke(Y1, gd);
    }

    function test_guardDigestBindsProof() public {
        _issue(Y1);
        _issue(Y2);
        _issue(Y3);
        bytes32 g = _createGroup(LABEL, _members(Y1, Y2));
        bytes32 p = _reservationPolicy(g);
        StateRegistry.Guard memory gd = _guard(p, 0);
        gd.proof = hex"01";
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(Y3);
        (,,,, uint64 v) = registry.getValues(regId);
        bytes32 digest = keccak256(abi.encode(p, keccak256(hex"01")));
        assertTrue(digest != keccak256(abi.encode(p, keccak256(hex"02"))));
        vm.expectEmit(true, true, true, true);
        emit StateRegistry.Revoked(regId, v + 1, bytes32(Y3), a, r, w, digest);
        _guardedRevoke(Y3, gd);
    }

    /// minden kvantor és polaritás egy referencia-számlálással szemben, csoporton és Issued-on
    function testFuzz_publicClauseMatchesCount(
        uint8 quantSeed,
        bool up,
        uint8 kSeed,
        uint8 revokedSeed,
        bool overIssued
    ) public {
        PolicyRegistry.Quant quant = PolicyRegistry.Quant(quantSeed % 4);
        bool trivial = quant == PolicyRegistry.Quant.All || quant == PolicyRegistry.Quant.Exists;
        uint32 k = trivial ? 0 : uint32(kSeed % 5);
        uint256 revoked = revokedSeed % 4;

        _issue(Y1);
        _issue(Y2);
        _issue(Y3);
        _issue(Y4);
        bytes32[] memory m = new bytes32[](3);
        m[0] = bytes32(Y1);
        m[1] = bytes32(Y2);
        m[2] = bytes32(Y3);
        bytes32 g = _createGroup(LABEL, m);
        if (revoked > 0) _revoke(Y1);
        if (revoked > 1) _revoke(Y2);
        if (revoked > 2) _revoke(Y3);

        PolicyRegistry.Polarity body = up ? PolicyRegistry.Polarity.Up : PolicyRegistry.Polarity.Down;
        PolicyRegistry.Binding[] memory b = overIssued
            ? _bind("R", PolicyRegistry.BindingKind.Registry, regId)
            : _bind("S", PolicyRegistry.BindingKind.Group, g);
        PolicyRegistry.Domain d = overIssued ? PolicyRegistry.Domain.Issued : PolicyRegistry.Domain.Group;
        bytes32 p = _policy("fuzz", b, _none(), _ops(_clause(quant, k, d, 0, body)));

        uint256 n = overIssued ? 4 : 3;
        uint256 cnt = up ? revoked : n - revoked;
        bool expected = quant == PolicyRegistry.Quant.All
            ? cnt == n
            : quant == PolicyRegistry.Quant.Exists
                ? cnt >= 1
                : quant == PolicyRegistry.Quant.AtLeast ? cnt >= k : cnt <= k;

        // Y4 a csoporton kívül van; a guard a visszavonása előtti állapotra vonatkozik
        if (expected) {
            _guardedRevoke(Y4, _guard(p, 0));
        } else {
            _expectGuardedRevokeReverts(Y4, _guard(p, 0), abi.encodeWithSelector(StateRegistry.GuardFalse.selector, p));
        }
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
