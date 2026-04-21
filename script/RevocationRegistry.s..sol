pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {CredDefRegistry} from "../src/CredDefRegistry.sol";
import {RevocationRegistry} from "../src/RevocationRegistry.sol";

contract DeployRevocationRegistry is Script{
    function run() external{
        vm.startBroadcast();
        RevocationRegistry revocation = new RevocationRegistry();
        console.log("RevocationRegistry:", address(revocation));
        vm.stopBroadcast();
    }
}