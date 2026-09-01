// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry2.sol";

contract PolicyRegistryTest is Test {
    PolicyRegistry registry;

    bytes32 constant S_A = keccak256("schema:A");
    bytes32 constant S_B = keccak256("schema:B");
    bytes32 constant ISS_X = keccak256("issuer:X");

    event PolicyRegistered(
        bytes32 indexed policyId,
        address indexed registrar,
        uint8  slotCount,
        uint16 termCount,
        uint16 atomCount,
        uint16 nodeCount
    );

    function setUp() public {
        registry = new PolicyRegistry();
    }

    // =======================================================================
    // Fixture
    // =======================================================================

    /// @dev Az alap érvényes policy:
    ///
    ///        slotCount = 1
    ///        terms  = [ CONST(0=VALID), CONST(S_A), SCHEMA_ID(0), REVOCATION(0) ]
    ///        atoms  = [ EQ(0,3)  -> revocation(s0) == VALID
    ///                   EQ(1,2)  -> schemaId(s0)   == S_A ]
    ///        nodes  = [ LEAF 0, LEAF 1, AND[0,1] ]
    ///
    ///      A termek (kind, slot, value) szerint, az atomok (rel, termA, termB)
    ///      szerint szigorúan növekvő sorrendben állnak.
    function _valid()
        internal
        pure
        returns (
            uint8 slotCount,
            PolicyRegistry.Term[] memory terms,
            PolicyRegistry.Atom[] memory atoms,
            PolicyRegistry.Node[] memory nodes
        )
    {
        slotCount = 1;

        terms = new PolicyRegistry.Term[](4);
        terms[0] = _const(bytes32(0));               // VALID
        terms[1] = _const(S_A);
        terms[2] = _acc(PolicyRegistry.TermKind.SCHEMA_ID, 0);
        terms[3] = _acc(PolicyRegistry.TermKind.REVOCATION, 0);

        atoms = new PolicyRegistry.Atom[](2);
        atoms[0] = _eq(0, 3);
        atoms[1] = _eq(1, 2);

        nodes = new PolicyRegistry.Node[](3);
        nodes[0] = _leaf(0);
        nodes[1] = _leaf(1);
        nodes[2] = _gate(PolicyRegistry.NodeKind.AND, _kids(0, 1));
    }

    // ---- apró építők -------------------------------------------------------

    function _const(bytes32 v) internal pure returns (PolicyRegistry.Term memory) {
        return PolicyRegistry.Term({kind: PolicyRegistry.TermKind.CONST, slot: 0, value: v});
    }

    function _acc(PolicyRegistry.TermKind k, uint16 slot)
        internal pure returns (PolicyRegistry.Term memory)
    {
        return PolicyRegistry.Term({kind: k, slot: slot, value: bytes32(0)});
    }

    function _eq(uint16 a, uint16 b) internal pure returns (PolicyRegistry.Atom memory) {
        return PolicyRegistry.Atom({rel: PolicyRegistry.Rel.EQ, termA: a, termB: b});
    }

    function _leaf(uint16 atomIndex) internal pure returns (PolicyRegistry.Node memory) {
        return PolicyRegistry.Node({
            kind: PolicyRegistry.NodeKind.LEAF,
            atomIndex: atomIndex,
            children: new uint16[](0)
        });
    }

    function _gate(PolicyRegistry.NodeKind k, uint16[] memory children)
        internal pure returns (PolicyRegistry.Node memory)
    {
        return PolicyRegistry.Node({kind: k, atomIndex: 0, children: children});
    }

    function _kids(uint16 a, uint16 b) internal pure returns (uint16[] memory ch) {
        ch = new uint16[](2);
        ch[0] = a;
        ch[1] = b;
    }

    function _registerValid() internal returns (bytes32) {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();
        return registry.registerPolicy(sc, t, a, n);
    }

    // =======================================================================
    // Regisztráció
    // =======================================================================

    function test_Register_Succeeds() public {
        bytes32 id = _registerValid();
        assertTrue(id != bytes32(0));
        assertTrue(registry.exists(id));
    }

    function test_Register_ReturnsComputedId() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        bytes32 expected = registry.computePolicyId(sc, t, a, n);
        bytes32 actual = registry.registerPolicy(sc, t, a, n);
        assertEq(actual, expected);
    }

    /// @dev A policyId a tartalomtól függ, nem a hívótól.
    function test_ComputeId_IsCallerIndependent() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        bytes32 id1 = registry.computePolicyId(sc, t, a, n);
        vm.prank(address(0xBEEF));
        bytes32 id2 = registry.computePolicyId(sc, t, a, n);
        assertEq(id1, id2);
    }

    /// @dev Eltérő tartalom -> eltérő azonosító.
    function test_ComputeId_DiffersOnContent() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        bytes32 id1 = registry.computePolicyId(sc, t, a, n);
        t[1] = _const(S_B);
        bytes32 id2 = registry.computePolicyId(sc, t, a, n);
        assertTrue(id1 != id2);
    }

    function test_Register_RevertsOnDuplicate() public {
        bytes32 id = _registerValid();

        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        vm.expectRevert(
            abi.encodeWithSelector(PolicyRegistry.PolicyAlreadyRegistered.selector, id)
        );
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Register_EmitsEvent() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        bytes32 id = registry.computePolicyId(sc, t, a, n);

        vm.expectEmit(true, true, false, true, address(registry));
        emit PolicyRegistered(id, address(this), 1, 4, 2, 3);
        registry.registerPolicy(sc, t, a, n);
    }

    /// @dev Bárki regisztrálhat: a tartalom-alapú azonosító miatt nincs mit elfoglalni.
    function test_Register_IsPermissionless() public {
        vm.prank(address(0xBEEF));
        bytes32 id = _registerValid();
        assertTrue(registry.exists(id));
    }

    // =======================================================================
    // Olvasás
    // =======================================================================

    function test_Exists_FalseForUnknown() public view {
        assertFalse(registry.exists(keccak256("nincs ilyen")));
    }

    function test_GetPolicy_ReturnsRawShape() public {
        bytes32 id = _registerValid();

        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = registry.getPolicy(id);

        assertEq(sc, 1);
        assertEq(t.length, 4);
        assertEq(a.length, 2);
        assertEq(n.length, 3);

        assertEq(uint8(t[2].kind), uint8(PolicyRegistry.TermKind.SCHEMA_ID));
        assertEq(t[1].value, S_A);
        assertEq(a[1].termA, 1);
        assertEq(a[1].termB, 2);
        assertEq(n[2].children.length, 2);
    }

    /// @dev A visszaadott nyers alaknak vissza kell adnia ugyanazt a policyId-t.
    function test_GetPolicy_RoundTripsThroughComputeId() public {
        bytes32 id = _registerValid();

        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = registry.getPolicy(id);

        assertEq(registry.computePolicyId(sc, t, a, n), id);
    }

    function test_GetPolicy_RevertsForUnknown() public {
        bytes32 id = keccak256("nincs ilyen");
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.UnknownPolicy.selector, id));
        registry.getPolicy(id);
    }

    function test_GetPredicates_ResolvesTerms() public {
        bytes32 id = _registerValid();

        (uint8 sc, PolicyRegistry.ResolvedPredicate[] memory preds) = registry.getPredicates(id);

        assertEq(sc, 1);
        assertEq(preds.length, 2);

        // preds[0]: EQ( CONST(VALID), REVOCATION(0) )
        assertEq(uint8(preds[0].rel), uint8(PolicyRegistry.Rel.EQ));
        assertEq(uint8(preds[0].termA.kind), uint8(PolicyRegistry.TermKind.CONST));
        assertEq(preds[0].termA.value, bytes32(0));
        assertEq(uint8(preds[0].termB.kind), uint8(PolicyRegistry.TermKind.REVOCATION));
        assertEq(preds[0].termB.slot, 0);

        // preds[1]: EQ( CONST(S_A), SCHEMA_ID(0) )
        assertEq(preds[1].termA.value, S_A);
        assertEq(uint8(preds[1].termB.kind), uint8(PolicyRegistry.TermKind.SCHEMA_ID));
    }

    function test_GetPredicates_RevertsForUnknown() public {
        bytes32 id = keccak256("nincs ilyen");
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.UnknownPolicy.selector, id));
        registry.getPredicates(id);
    }

    function test_GetRootPredicate_RootIsLast() public {
        bytes32 id = _registerValid();

        (uint8 sc, PolicyRegistry.ResolvedNode[] memory dag) = registry.getRootPredicate(id);

        assertEq(sc, 1);
        assertEq(dag.length, 3);

        // A gyökér az utolsó elem, és kapu.
        assertEq(uint8(dag[2].kind), uint8(PolicyRegistry.NodeKind.AND));
        assertEq(dag[2].children.length, 2);
        assertEq(dag[2].children[0], 0);
        assertEq(dag[2].children[1], 1);

        // A levelekben feloldott predikátum áll.
        assertEq(uint8(dag[0].kind), uint8(PolicyRegistry.NodeKind.LEAF));
        assertEq(uint8(dag[0].predicate.termB.kind), uint8(PolicyRegistry.TermKind.REVOCATION));
        assertEq(dag[0].children.length, 0);
    }

    /// @dev Kapunál a predicate mező nullákkal van kitöltve, nem jelent semmit.
    function test_GetRootPredicate_GateHasEmptyPredicate() public {
        bytes32 id = _registerValid();
        (, PolicyRegistry.ResolvedNode[] memory dag) = registry.getRootPredicate(id);

        assertEq(uint8(dag[2].predicate.rel), 0);
        assertEq(dag[2].predicate.termA.value, bytes32(0));
        assertEq(dag[2].predicate.termB.value, bytes32(0));
    }

    // =======================================================================
    // Típusrendszer
    // =======================================================================

    function test_TermType_Mapping() public view {
        assertEq(
            uint8(registry.termType(PolicyRegistry.TermKind.CONST)),
            uint8(PolicyRegistry.TermType.POLY)
        );
        assertEq(
            uint8(registry.termType(PolicyRegistry.TermKind.SCHEMA_ID)),
            uint8(PolicyRegistry.TermType.ID)
        );
        assertEq(
            uint8(registry.termType(PolicyRegistry.TermKind.CRED_DEF_ID)),
            uint8(PolicyRegistry.TermType.ID)
        );
        assertEq(
            uint8(registry.termType(PolicyRegistry.TermKind.ISSUER)),
            uint8(PolicyRegistry.TermType.ID)
        );
        assertEq(
            uint8(registry.termType(PolicyRegistry.TermKind.REVOCATION)),
            uint8(PolicyRegistry.TermType.STATUS)
        );
    }

    // =======================================================================
    // Validáció — méretkorlátok
    // =======================================================================

    function test_Revert_ZeroSlots() public {
        (
            ,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        vm.expectRevert(PolicyRegistry.BadSlotCount.selector);
        registry.registerPolicy(0, t, a, n);
    }

    function test_Revert_TooManySlots() public {
        (
            ,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        vm.expectRevert(PolicyRegistry.BadSlotCount.selector);
        registry.registerPolicy(33, t, a, n);
    }

    function test_Revert_NoTerms() public {
        (
            uint8 sc,
            ,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        vm.expectRevert(PolicyRegistry.BadTermCount.selector);
        registry.registerPolicy(sc, new PolicyRegistry.Term[](0), a, n);
    }

    function test_Revert_NoAtoms() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            ,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        vm.expectRevert(PolicyRegistry.BadAtomCount.selector);
        registry.registerPolicy(sc, t, new PolicyRegistry.Atom[](0), n);
    }

    function test_Revert_NoNodes() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
        ) = _valid();

        vm.expectRevert(PolicyRegistry.BadNodeCount.selector);
        registry.registerPolicy(sc, t, a, new PolicyRegistry.Node[](0));
    }

    // =======================================================================
    // Validáció — termek
    // =======================================================================

    function test_Revert_ConstWithNonZeroSlot() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        t[0].slot = 1; // CONST-nak nem lehet slotja

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadTerm.selector, 0));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_AccessorWithNonZeroValue() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        t[2].value = S_B; // accessornak nem lehet literálja

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadTerm.selector, 2));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_AccessorSlotOutOfRange() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        t[2].slot = 5; // slotCount == 1

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadTerm.selector, 2));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_TermsUnsorted() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        // A két accessor felcserélve: REVOCATION (kind 4) elé kerül SCHEMA_ID (kind 1).
        PolicyRegistry.Term memory tmp = t[2];
        t[2] = t[3];
        t[3] = tmp;

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.TermsNotCanonical.selector, 3));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_DuplicateTerms() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        t[1] = t[0]; // szigorúan növekvő -> az egyenlőség is bukik

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.TermsNotCanonical.selector, 1));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_UnusedSlot() public {
        (
            ,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        // Két slotot hirdetünk, de csak a 0-ásra hivatkozik term.
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.UnusedSlot.selector, 1));
        registry.registerPolicy(2, t, a, n);
    }

    function test_Revert_UnusedTerm() public {
        uint8 sc = 1;

        PolicyRegistry.Term[] memory t = new PolicyRegistry.Term[](5);
        t[0] = _const(bytes32(0));
        t[1] = _const(S_A);
        t[2] = _acc(PolicyRegistry.TermKind.SCHEMA_ID, 0);   // kind 1
        t[3] = _acc(PolicyRegistry.TermKind.ISSUER, 0);      // kind 3 — egy atom sem hivatkozik rá
        t[4] = _acc(PolicyRegistry.TermKind.REVOCATION, 0);  // kind 4

        PolicyRegistry.Atom[] memory a = new PolicyRegistry.Atom[](2);
        a[0] = _eq(0, 4);
        a[1] = _eq(1, 2);

        PolicyRegistry.Node[] memory n = new PolicyRegistry.Node[](3);
        n[0] = _leaf(0);
        n[1] = _leaf(1);
        n[2] = _gate(PolicyRegistry.NodeKind.AND, _kids(0, 1));

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.UnusedTerm.selector, 3));
        registry.registerPolicy(sc, t, a, n);
    }

    // =======================================================================
    // Validáció — atomok
    // =======================================================================

    function test_Revert_AtomTermOutOfRange() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        a[0].termB = 99;

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadAtom.selector, 0));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_AtomNotNormalized() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        a[0] = _eq(3, 0); // termA > termB

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadAtom.selector, 0));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_AtomSelfComparison() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        a[0] = _eq(2, 2);

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadAtom.selector, 0));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_AtomBothConst() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        a[0] = _eq(0, 1); // CONST vs CONST

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadAtom.selector, 0));
        registry.registerPolicy(sc, t, a, n);
    }

    /// @dev ID-t STATUS-hoz hasonlítani badarság.
    function test_Revert_AtomTypeMismatch() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        a[0] = _eq(2, 3); // SCHEMA_ID vs REVOCATION
        a[1] = _eq(2, 3); // a sorrend-ellenőrzés elé essen a típushiba

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.AtomTypeMismatch.selector, 0));
        registry.registerPolicy(sc, t, a, n);
    }

    /// @dev Két azonos fajta accessor összehasonlítása viszont rendben van
    ///      (ez lesz majd a cross-constraint alakja).
    function test_TwoAccessorsOfSameType_IsValid() public {
        uint8 sc = 2;

        PolicyRegistry.Term[] memory t = new PolicyRegistry.Term[](4);
        t[0] = _const(bytes32(0));
        t[1] = _acc(PolicyRegistry.TermKind.ISSUER, 0);      // kind 3, slot 0
        t[2] = _acc(PolicyRegistry.TermKind.ISSUER, 1);      // kind 3, slot 1
        t[3] = _acc(PolicyRegistry.TermKind.REVOCATION, 0);  // kind 4

        PolicyRegistry.Atom[] memory a = new PolicyRegistry.Atom[](2);
        a[0] = _eq(0, 3); // revocation(s0) == VALID
        a[1] = _eq(1, 2); // issuer(s0) == issuer(s1)

        PolicyRegistry.Node[] memory n = new PolicyRegistry.Node[](3);
        n[0] = _leaf(0);
        n[1] = _leaf(1);
        n[2] = _gate(PolicyRegistry.NodeKind.AND, _kids(0, 1));

        bytes32 id = registry.registerPolicy(sc, t, a, n);
        assertTrue(registry.exists(id));
    }

    /// @dev A POLY nem szűr, ezért a STATUS-hoz hasonlított literált külön nézzük.
    function test_Revert_StatusLiteralOutOfRange() public {
        uint8 sc = 1;

        PolicyRegistry.Term[] memory t = new PolicyRegistry.Term[](3);
        t[0] = _const(bytes32(uint256(42)));                 // nem érvényes állapot
        t[1] = _acc(PolicyRegistry.TermKind.SCHEMA_ID, 0);
        t[2] = _acc(PolicyRegistry.TermKind.REVOCATION, 0);

        PolicyRegistry.Atom[] memory a = new PolicyRegistry.Atom[](1);
        a[0] = _eq(0, 2);

        PolicyRegistry.Node[] memory n = new PolicyRegistry.Node[](2);
        n[0] = _leaf(0);
        n[1] = _leaf(0);

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadAtom.selector, 0));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_AtomsUnsorted() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        PolicyRegistry.Atom memory tmp = a[0];
        a[0] = a[1];
        a[1] = tmp;

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.AtomsNotCanonical.selector, 1));
        registry.registerPolicy(sc, t, a, n);
    }

    // =======================================================================
    // Validáció — node-ok
    // =======================================================================

    function test_Revert_LeafWithChildren() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        n[0].children = _kids(0, 1);

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadNode.selector, 0));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_LeafAtomOutOfRange() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        n[0].atomIndex = 99;

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadNode.selector, 0));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_GateWithAtomIndex() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        n[2].atomIndex = 1; // kapunál holt mezőnek nullának kell lennie

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadNode.selector, 2));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_GateWithTooFewChildren() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        uint16[] memory one = new uint16[](1);
        one[0] = 0;
        n[2].children = one;

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadNode.selector, 2));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_ChildIndexNotLessThanOwn() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        n[2].children = _kids(0, 2); // önmagára mutat

        vm.expectRevert(
            abi.encodeWithSelector(PolicyRegistry.NotTopologicallyOrdered.selector, 2)
        );
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_ChildrenNotStrictlyIncreasing() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        n[2].children = _kids(1, 0);

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.BadNode.selector, 2));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_UnusedAtom() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
            PolicyRegistry.Node[] memory n
        ) = _valid();

        n[1] = _leaf(0); // az 1-es atomra már semmi nem hivatkozik

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.UnusedAtom.selector, 1));
        registry.registerPolicy(sc, t, a, n);
    }

    function test_Revert_UnreachableNode() public {
        (
            uint8 sc,
            PolicyRegistry.Term[] memory t,
            PolicyRegistry.Atom[] memory a,
        ) = _valid();

        // Két azonos kapu; a gyökér az utolsó, tehát a 2-es elérhetetlen.
        PolicyRegistry.Node[] memory n = new PolicyRegistry.Node[](4);
        n[0] = _leaf(0);
        n[1] = _leaf(1);
        n[2] = _gate(PolicyRegistry.NodeKind.AND, _kids(0, 1));
        n[3] = _gate(PolicyRegistry.NodeKind.AND, _kids(0, 1));

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.UnreachableNode.selector, 2));
        registry.registerPolicy(sc, t, a, n);
    }

    // =======================================================================
    // OR, mélyebb DAG
    // =======================================================================

    /// @dev A rajzod szerinti alak kicsiben: OR( AND(...), LEAF ).
    function test_NestedDag_Registers() public {
        uint8 sc = 2;

        PolicyRegistry.Term[] memory t = new PolicyRegistry.Term[](5);
        t[0] = _const(bytes32(0));                           // VALID
        t[1] = _const(S_A);
        t[2] = _acc(PolicyRegistry.TermKind.SCHEMA_ID, 0);   // kind 1, slot 0
        t[3] = _acc(PolicyRegistry.TermKind.REVOCATION, 0);  // kind 4, slot 0
        t[4] = _acc(PolicyRegistry.TermKind.REVOCATION, 1);  // kind 4, slot 1

        PolicyRegistry.Atom[] memory a = new PolicyRegistry.Atom[](3);
        a[0] = _eq(0, 3); // revocation(s0) == VALID
        a[1] = _eq(0, 4); // revocation(s1) == VALID
        a[2] = _eq(1, 2); // schemaId(s0)   == S_A

        PolicyRegistry.Node[] memory n = new PolicyRegistry.Node[](5);
        n[0] = _leaf(0);
        n[1] = _leaf(1);
        n[2] = _leaf(2);
        n[3] = _gate(PolicyRegistry.NodeKind.AND, _kids(0, 2));
        n[4] = _gate(PolicyRegistry.NodeKind.OR,  _kids(1, 3));

        bytes32 id = registry.registerPolicy(sc, t, a, n);

        (, PolicyRegistry.ResolvedNode[] memory dag) = registry.getRootPredicate(id);
        assertEq(dag.length, 5);
        assertEq(uint8(dag[4].kind), uint8(PolicyRegistry.NodeKind.OR));
    }

    /// @dev Megosztott részkifejezés: egy LEAF node-ra két kapu is mutat.
    function test_SharedSubexpression_Registers() public {
        uint8 sc = 1;

        PolicyRegistry.Term[] memory t = new PolicyRegistry.Term[](4);
        t[0] = _const(bytes32(0));
        t[1] = _const(S_A);
        t[2] = _acc(PolicyRegistry.TermKind.SCHEMA_ID, 0);
        t[3] = _acc(PolicyRegistry.TermKind.REVOCATION, 0);

        PolicyRegistry.Atom[] memory a = new PolicyRegistry.Atom[](2);
        a[0] = _eq(0, 3);
        a[1] = _eq(1, 2);

        // A 0-ás LEAF mindkét kapu gyereke — ettől DAG, nem fa.
        PolicyRegistry.Node[] memory n = new PolicyRegistry.Node[](5);
        n[0] = _leaf(0);
        n[1] = _leaf(1);
        n[2] = _gate(PolicyRegistry.NodeKind.AND, _kids(0, 1));
        n[3] = _gate(PolicyRegistry.NodeKind.OR,  _kids(0, 1));
        n[4] = _gate(PolicyRegistry.NodeKind.OR,  _kids(2, 3));

        bytes32 id = registry.registerPolicy(sc, t, a, n);
        assertTrue(registry.exists(id));
    }
}