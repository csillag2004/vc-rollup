pragma solidity ^0.8.24;

contract Accumulator {
    bytes public accumulatorValue;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function setAccumulator(bytes calldata newValue) external onlyOwner {
        accumulatorValue = newValue;
    }

    function getAccumulator() external view returns (bytes memory) {
        return accumulatorValue;
    }
}