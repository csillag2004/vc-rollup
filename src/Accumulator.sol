pragma solidity ^0.8.24;

contract Accumulator {
    bytes accumulatorValue;
    bytes publicKey;
    bytes params;
    address owner;
    
    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    event giveaccumulatorValue(bytes value);
    event givepublicKey(bytes value);
    event giveparams(bytes value);
    event giveowner(address value);

    function setAccumulator(bytes calldata newValue) external onlyOwner {
        accumulatorValue = newValue;
    }

    function getAccumulator() external view returns (bytes memory) {
        return accumulatorValue;
    }

    function setPublicKey(bytes calldata newPublicKey) external onlyOwner {
        publicKey = newPublicKey;
    }

    function getPublicKey() external view returns (bytes memory) {
        return publicKey;
    }

    function setParams(bytes calldata newParams) external onlyOwner {
        params = newParams;
    }

    function getParams() external view returns (bytes memory) {
        return params;
    }

    function getOwner() external view returns (address) {
        return owner;
    }
}