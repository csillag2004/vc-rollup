pragma solidity ^0.8.24;
import {CredDefRegistry} from "./CredDefRegistry.sol";

contract RevocationRegistry{

    struct RevocationList {
        bytes32 credDefId;
        address issuer;
        uint256 maxCredentials;
        bytes currentAccumulator;
        uint256 currentEpoch;
        uint256 createdAt;
    }

    mapping(bytes32 => RevocationList) public lists;
    mapping(bytes32 => mapping(uint256 => bytes)) private deltas;

    CredDefRegistry public credDefRegistry;

    constructor(address _credDefRegistry) {
        credDefRegistry = CredDefRegistry(_credDefRegistry);
    }

    event UpdatedRegistry(
        bytes32 indexed registryId,
        uint256 indexed epoch,
        bytes newAccumulator,
        bytes delta
    );

    event RegistryCreated(bytes32 indexed registryId, bytes32 indexed credDefId, address indexed issuer);


    function createRegistry(
        bytes32 credDefId,
        uint256 maxCredentials,
        bytes calldata initialAccumulator
    ) external returns (bytes32 registryId){
        //REVERTEK
        CredDefRegistry.CredDef memory c = credDefRegistry.getCredDef(credDefId);
        if (c.createdAt == 0) revert("This CredDef does not exist.");
        if (c.issuer != msg.sender) revert("Only issuer can create the registry.");
        if (maxCredentials == 0) revert("maxCredentials is empty.");
        if (initialAccumulator.length==0) revert("Accumulator is empty.");

        registryId = keccak256(abi.encodePacked(msg.sender, credDefId));

        //ha már létezik revert
        if(lists[registryId].createdAt != 0){
            revert("This RecList is already exist.");
        }

        //létrehozás
        RevocationList storage r = lists[registryId];
        r.credDefId = credDefId;
        r.issuer = msg.sender;
        r.maxCredentials = maxCredentials;
        r.currentAccumulator = initialAccumulator;
        r.currentEpoch = 0;
        r.createdAt = block.timestamp;

        //event kiküldés
        emit RegistryCreated(registryId, credDefId, msg.sender);

        return registryId;
    }


    function updateRegistry(
        bytes32 registryId,
        bytes calldata newAccumulator,
        bytes calldata delta          // published for holders to update witnesses
    ) external{
        //revertek
        if (!(lists[registryId].createdAt > 0)) revert("This RevocationList does not exist.");
        if (newAccumulator.length==0) revert("Accumulator is empty.");
        if (msg.sender != lists[registryId].issuer) revert("Only issuer can update the registry.");

        //módosítás
        lists[registryId].currentAccumulator = newAccumulator;
        lists[registryId].currentEpoch++;
        
        //delt létrehozás
        deltas[registryId][lists[registryId].currentEpoch] = delta;
        
        //event kiküldés
        emit UpdatedRegistry(
            registryId,
            lists[registryId].currentEpoch,
            newAccumulator,
            delta
        );
    }


    function getRegistry(bytes32 registryId) external view returns (bytes memory value, uint256 epoch){
        if (!(lists[registryId].createdAt > 0)) revert("This RevocationList does not exist.");
        return (lists[registryId].currentAccumulator, lists[registryId].currentEpoch);
    }


    function getDelta(bytes32 registryId, uint256 epoch) external view returns (bytes memory){
        if (!(lists[registryId].createdAt > 0)) revert("This RevocationList does not exist.");
        if (epoch == 0 || epoch > lists[registryId].currentEpoch) revert("Invalid epoch.");
        return deltas[registryId][epoch];
    }

}