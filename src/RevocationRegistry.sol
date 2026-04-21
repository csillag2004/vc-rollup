pragma solidity ^0.8.24;
import {CredDefRegistry} from "./CredDefRegistry.sol";

contract RevocationRegistry{

    struct RevocationList {
        bytes32 credDefId;
        address issuer;
        bytes currentAccumulator;
        uint256 currentEpoch;
        uint256 createdAt;
    }

    mapping(bytes32 => RevocationList) public lists;

    CredDefRegistry public credDefRegistry;

    constructor(address _credDefRegistry) {
        credDefRegistry = CredDefRegistry(_credDefRegistry);
    }

    event UpdatedRegistry(
        bytes32 indexed registryId,
        uint256 indexed epoch,
        bytes newAccumulator,
        uint256[] addedScalars,
        uint256[] revokedScalars
    );

    event RegistryCreated(bytes32 indexed registryId, bytes32 indexed credDefId, address indexed issuer, bytes newAccumulator);


    function createRegistry(
        bytes32 credDefId,
        bytes calldata initialAccumulator
    ) external returns (bytes32 registryId){
        //REVERTEK
        CredDefRegistry.CredDef memory c = credDefRegistry.getCredDef(credDefId);
        if (c.createdAt == 0) revert("This CredDef does not exist.");
        if (c.issuer != msg.sender) revert("Only issuer can create the registry.");
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
        r.currentAccumulator = initialAccumulator;
        r.currentEpoch = 0;
        r.createdAt = block.timestamp;

        //event kiküldés
        emit RegistryCreated(registryId, credDefId, msg.sender, initialAccumulator);

        return registryId;
    }


    function updateRegistry(
        bytes32 registryId,
        bytes calldata newAccumulator,
        uint256[] calldata addedScalars,
        uint256[] calldata revokedScalars
    ) external{
        //revertek
        if (!(lists[registryId].createdAt > 0)) revert("This RevocationList does not exist.");
        if (newAccumulator.length==0) revert("Accumulator is empty.");
        if (msg.sender != lists[registryId].issuer) revert("Only issuer can update the registry.");
        if (addedScalars.length == 0 && revokedScalars.length == 0) revert("Nothing to update.");

        //módosítás
        lists[registryId].currentAccumulator = newAccumulator;
        lists[registryId].currentEpoch++;
        
        
        //event kiküldés
        emit UpdatedRegistry(
            registryId,
            lists[registryId].currentEpoch,
            newAccumulator,
            addedScalars,
            revokedScalars
        );
    }


    function getRegistry(bytes32 registryId) external view returns (bytes memory value, uint256 epoch){
        if (!(lists[registryId].createdAt > 0)) revert("This RevocationList does not exist.");
        return (lists[registryId].currentAccumulator, lists[registryId].currentEpoch);
    }


}