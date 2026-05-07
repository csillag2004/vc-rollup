pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {Accumulator} from "../src/Accumulator.sol";

contract DeployAccumulator is Script{
    function run() external{

        vm.startBroadcast();
        Accumulator accumulator = new Accumulator();
        console.log("Accumulator:", address(accumulator));
        vm.stopBroadcast();
    }
}