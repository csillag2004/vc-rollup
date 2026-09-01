// SPDX-License-Identifier: MIT
/*pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";

contract PolicyRegistryTest is Test {
    PolicyRegistry reg;

    address admin = address(0xA11CE);
    address notAdmin = address(0xBEEF);

    bytes32 constant RESIDENCE = keccak256("ResidencePermit");
    bytes32 constant PASSPORT = keccak256("Passport");
    bytes32 constant NATIONAL_ID = keccak256("NationalID");
    bytes32 constant ADDRESS_PROOF = keccak256("ProofOfAddress");

    // két kibocsátó, növekvő sorrendben
    address constant ISS_A = address(0x1111111111111111111111111111111111111111);
    address constant ISS_B = address(0x2222222222222222222222222222222222222222);

    function setUp() public {
        reg = new PolicyRegistry(admin);
    }

    // ------------------------------------------------------------ segédek

    function _leaf(bytes32 schemaId) internal pure returns (PolicyRegistry.Leaf memory l) {
        address[] memory iss = new address[](2);
        iss[0] = ISS_A;
        iss[1] = ISS_B;
        l = PolicyRegistry.Leaf({
            schemaId: schemaId,
            validation: PolicyRegistry.Validation.Valid,
            issuers: iss
        });
    }

    /// AND( OR(Passport, NationalID), ProofOfAddress )
    /// id: 0=Passport 1=NationalID 2=ProofOfAddress 3=OR 4=AND
    function _demoDag()
        internal
        pure
        returns (PolicyRegistry.Leaf[] memory leaves, PolicyRegistry.Gate[] memory gates)
    {
        leaves = new PolicyRegistry.Leaf[](3);
        leaves[0] = _leaf(PASSPORT);
        leaves[1] = _leaf(NATIONAL_ID);
        leaves[2] = _leaf(ADDRESS_PROOF);

        gates = new PolicyRegistry.Gate[](2);
        gates[0] = PolicyRegistry.Gate({dagType: PolicyRegistry.DAGType.OR, left: 0, right: 1});
        gates[1] = PolicyRegistry.Gate({dagType: PolicyRegistry.DAGType.AND, left: 3, right: 2});
    }

    function _set() internal {
        (PolicyRegistry.Leaf[] memory leaves, PolicyRegistry.Gate[] memory gates) = _demoDag();
        vm.prank(admin);
        reg.setPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance, leaves, gates);
    }

    // ------------------------------------------------------------ roundtrip

    /// Ez a fontos teszt: a beágyazott dinamikus tömbök (issuers)
    /// túlélik-e a storage -> memory mélymásolást.
    function test_setAndGet_roundtrip() public {
        _set();

        PolicyRegistry.DAG memory d = reg.getPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance);

        assertEq(d.root, 4, "root");
        assertTrue(d.valid, "valid");
        assertGt(d.createdAt, 0, "createdAt");

        assertEq(d.leaves.length, 3, "leaf count");
        assertEq(d.gates.length, 2, "gate count");

        assertEq(d.leaves[0].schemaId, PASSPORT);
        assertEq(d.leaves[1].schemaId, NATIONAL_ID);
        assertEq(d.leaves[2].schemaId, ADDRESS_PROOF);

        // a beágyazott tömb
        assertEq(d.leaves[0].issuers.length, 2, "issuer count");
        assertEq(d.leaves[0].issuers[0], ISS_A);
        assertEq(d.leaves[0].issuers[1], ISS_B);

        assertEq(uint8(d.gates[0].dagType), uint8(PolicyRegistry.DAGType.OR));
        assertEq(d.gates[0].left, 0);
        assertEq(d.gates[0].right, 1);
        assertEq(uint8(d.gates[1].dagType), uint8(PolicyRegistry.DAGType.AND));
        assertEq(d.gates[1].left, 3);
        assertEq(d.gates[1].right, 2);
    }

    // ------------------------------------------------------------ frissítés

    /// Nagyobb DAG-ról kisebbre: maradnak-e szemételemek a tömbök végén?
    function test_update_shrinks() public {
        _set(); // 3 levél, 2 kapu

        // AND(Passport, ProofOfAddress) — 2 levél, 1 kapu
        PolicyRegistry.Leaf[] memory leaves = new PolicyRegistry.Leaf[](2);
        leaves[0] = _leaf(PASSPORT);
        leaves[1] = _leaf(ADDRESS_PROOF);

        PolicyRegistry.Gate[] memory gates = new PolicyRegistry.Gate[](1);
        gates[0] = PolicyRegistry.Gate({dagType: PolicyRegistry.DAGType.AND, left: 0, right: 1});

        vm.prank(admin);
        reg.setPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance, leaves, gates);

        PolicyRegistry.DAG memory d = reg.getPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance);
        assertEq(d.leaves.length, 2, "stale leaves left behind");
        assertEq(d.gates.length, 1, "stale gates left behind");
        assertEq(d.root, 2, "root not recomputed");
        assertEq(d.leaves[1].schemaId, ADDRESS_PROOF);
        assertEq(d.leaves[1].issuers.length, 2);
    }

    /// Külön operation-ök nem gázolnak egymásba.
    function test_operations_are_independent() public {
        _set();
        vm.expectRevert("Policy does not exist.");
        reg.getPolicy(RESIDENCE, PolicyRegistry.Operation.Presentation);
    }

    // ------------------------------------------------------------ validálás

    function test_revert_notAdmin() public {
        (PolicyRegistry.Leaf[] memory leaves, PolicyRegistry.Gate[] memory gates) = _demoDag();
        vm.prank(notAdmin);
        vm.expectRevert("Only admin can set policy.");
        reg.setPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance, leaves, gates);
    }

    /// Kapu, ami magára vagy későbbi node-ra mutat -> kör.
    function test_revert_gateInputNotEarlier() public {
        (PolicyRegistry.Leaf[] memory leaves, PolicyRegistry.Gate[] memory gates) = _demoDag();
        gates[0].left = 4; // a 3-as kapu a 4-esre mutatna

        vm.prank(admin);
        vm.expectRevert("Gate input must be earlier.");
        reg.setPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance, leaves, gates);
    }

    /// Olyan levél, amire egyetlen kapu sem hivatkozik.
    function test_revert_deadNode() public {
        PolicyRegistry.Leaf[] memory leaves = new PolicyRegistry.Leaf[](3);
        leaves[0] = _leaf(PASSPORT);
        leaves[1] = _leaf(NATIONAL_ID);
        leaves[2] = _leaf(ADDRESS_PROOF); // ezt senki nem használja

        PolicyRegistry.Gate[] memory gates = new PolicyRegistry.Gate[](2);
        gates[0] = PolicyRegistry.Gate({dagType: PolicyRegistry.DAGType.OR, left: 0, right: 1});
        gates[1] = PolicyRegistry.Gate({dagType: PolicyRegistry.DAGType.AND, left: 3, right: 0});

        vm.prank(admin);
        vm.expectRevert("Dead node.");
        reg.setPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance, leaves, gates);
    }

    function test_revert_issuersNotSorted() public {
        (PolicyRegistry.Leaf[] memory leaves, PolicyRegistry.Gate[] memory gates) = _demoDag();
        address[] memory iss = new address[](2);
        iss[0] = ISS_B; // fordítva
        iss[1] = ISS_A;
        leaves[0].issuers = iss;

        vm.prank(admin);
        vm.expectRevert("Issuers must be sorted and unique.");
        reg.setPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance, leaves, gates);
    }

    function test_revert_emptyIssuers() public {
        (PolicyRegistry.Leaf[] memory leaves, PolicyRegistry.Gate[] memory gates) = _demoDag();
        leaves[1].issuers = new address[](0);

        vm.prank(admin);
        vm.expectRevert("Leaf has no issuers.");
        reg.setPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance, leaves, gates);
    }

    // ------------------------------------------------------------ állapot

    function test_deactivate_and_activate() public {
        _set();

        vm.prank(admin);
        reg.deactivatePolicy(RESIDENCE, PolicyRegistry.Operation.Issuance);
        assertFalse(reg.getPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance).valid);

        vm.prank(admin);
        vm.expectRevert("Policy is already deactivated.");
        reg.deactivatePolicy(RESIDENCE, PolicyRegistry.Operation.Issuance);

        vm.prank(admin);
        reg.activatePolicy(RESIDENCE, PolicyRegistry.Operation.Issuance);
        assertTrue(reg.getPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance).valid);
    }

    /// Deaktivált policy felülírása automatikusan újraaktivál — szándékos?
    function test_setPolicy_reactivates() public {
        _set();
        vm.prank(admin);
        reg.deactivatePolicy(RESIDENCE, PolicyRegistry.Operation.Issuance);
        _set();
        assertTrue(reg.getPolicy(RESIDENCE, PolicyRegistry.Operation.Issuance).valid);
    }

    function test_revert_deactivateNonexistent() public {
        vm.prank(admin);
        vm.expectRevert("Policy does not exist.");
        reg.deactivatePolicy(keccak256("Nope"), PolicyRegistry.Operation.Issuance);
    }
}
*/