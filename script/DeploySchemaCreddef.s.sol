pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {CredDefRegistry} from "../src/CredDefRegistry.sol";

contract DeploySchemaAndCredDef is Script{
    function run() external{
        address didRegistry = vm.envAddress("REGISTRY_ADDRESS");
        vm.startBroadcast();
        SchemaRegistry schema = new SchemaRegistry();
        console.log("SchemaRegistry:", address(schema));
        CredDefRegistry creddef = new CredDefRegistry(didRegistry, address(schema));
        console.log("CredDefRegistry:", address(creddef));  
        vm.stopBroadcast();
    }
}