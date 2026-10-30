// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {EthereumDIDRegistry} from "ethr-did-registry/EthereumDIDRegistry.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {CredDefRegistry} from "../src/CredDefRegistry.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {StateRegistry} from "../src/StateRegistry.sol";
import {BLS} from "../src/lib/BLS.sol";

/// Teljes VDR telepítése. Ha DID_REGISTRY meg van adva, a meglévő ethr-DID registryt használja.
///   forge script script/Deploy.s.sol --rpc-url op_sepolia --private-key $PRIVATE_KEY --broadcast
contract Deploy is Script {
    function run() external {
        // a verify-on-write ellenőrzésekhez EIP-2537 kell: e(g, g̃) · e(-g, g̃) = 1
        (bool ok, bytes memory out) = BLS.PAIRING.staticcall(abi.encodePacked(BLS.g1(), BLS.g2(), BLS.g1Neg(BLS.g1()), BLS.g2()));
        require(ok && out.length == 32 && uint256(bytes32(out)) == 1, "no EIP-2537 pairing precompile on this chain");

        address did = vm.envOr("DID_REGISTRY", address(0));
        vm.startBroadcast();
        if (did == address(0)) did = address(new EthereumDIDRegistry());
        SchemaRegistry schemas = new SchemaRegistry();
        CredDefRegistry credDefs = new CredDefRegistry(did, address(schemas));
        PolicyRegistry policies = new PolicyRegistry(address(credDefs));
        StateRegistry state = new StateRegistry(address(credDefs), address(policies));
        vm.stopBroadcast();

        console.log("EthereumDIDRegistry", did);
        console.log("SchemaRegistry     ", address(schemas));
        console.log("CredDefRegistry    ", address(credDefs));
        console.log("PolicyRegistry     ", address(policies));
        console.log("StateRegistry      ", address(state));
    }
}
