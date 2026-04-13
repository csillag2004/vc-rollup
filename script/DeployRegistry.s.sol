// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "ethr-did-registry/EthereumDIDRegistry.sol";

contract DeployRegistry is Script {
    function run() external {
        vm.startBroadcast();
        EthereumDIDRegistry registry = new EthereumDIDRegistry();
        console.log("Registry deployed at:", address(registry));
        vm.stopBroadcast();
    }
}