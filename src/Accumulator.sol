pragma solidity ^0.8.24;

contract Accumulator {
    bytes accumulatorValue;
    bytes publicKey;
    bytes params;
    address owner;
    bytes witnessUpdateInfo;
    uint256 epoch;


    constructor() {
        owner = msg.sender;
        epoch = 0;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    event AccumulatorUpdated(
        bytes value,
        uint256[] additions,
        uint256[] removals,
        bytes witnessUpdateInfo,
        uint256 epoch
    );
    event givepublicKey(bytes value);
    event giveparams(bytes value);
    event giveowner(address value);

    function setAccumulator(bytes calldata newValue, uint256[] calldata additions, uint256[] calldata removals, bytes calldata witnessInfo) external onlyOwner {
        accumulatorValue = newValue;
        witnessUpdateInfo = witnessInfo;
        epoch++;
        emit AccumulatorUpdated(accumulatorValue, additions, removals, witnessUpdateInfo, epoch);
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