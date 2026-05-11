pragma solidity ^0.8.24;
import {CredDefRegistry} from "./CredDefRegistry.sol";
import {Accumulator} from "./Accumulator.sol";

contract RevocationRegistry{

    struct RevocationList {
        bytes32 credDefId;
        address issuer;
        Accumulator currentAccumulator;
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

    event RegistryCreated(
        bytes32 indexed registryId,
        bytes32 indexed credDefId,
        address indexed issuer,
        address accumulator,
        bytes initialAccumulator
    );


    function createRegistry(
        bytes32 credDefId,
        address accumulatorAddr
    ) external returns (bytes32 registryId){
        //REVERTEK
        CredDefRegistry.CredDef memory c = credDefRegistry.getCredDef(credDefId);
        if (c.createdAt == 0) revert("This CredDef does not exist.");
        if (c.issuer != msg.sender) revert("Only issuer can create the registry.");
        if (accumulatorAddr == address(0)) revert("Accumulator address is zero.");

        Accumulator acc = Accumulator(accumulatorAddr);
        if (acc.getOwner() != msg.sender) revert("Issuer must own the accumulator.");

        bytes memory initial = acc.getAccumulator();
        if (initial.length == 0) revert("Accumulator is empty.");

        registryId = keccak256(abi.encodePacked(msg.sender, credDefId));

        //ha már létezik revert
        if(lists[registryId].createdAt != 0){
            revert("This RecList is already exist.");
        }

        //létrehozás
        RevocationList storage r = lists[registryId];
        r.credDefId = credDefId;
        r.issuer = msg.sender;
        r.currentAccumulator = acc;
        r.currentEpoch = 0;
        r.createdAt = block.timestamp;

        //event kiküldés
        emit RegistryCreated(registryId, credDefId, msg.sender, accumulatorAddr, initial);

        return registryId;
    }


    function updateRegistry(
        bytes32 registryId,
        uint256[] calldata addedScalars,
        uint256[] calldata revokedScalars
    ) external{
        //revertek
        RevocationList storage r = lists[registryId];
        if (!(r.createdAt > 0)) revert("This RevocationList does not exist.");
        if (msg.sender != r.issuer) revert("Only issuer can update the registry.");
        if (addedScalars.length == 0 && revokedScalars.length == 0) revert("Nothing to update.");

        // Read current bytes from the issuer-owned Accumulator contract
        bytes memory current = r.currentAccumulator.getAccumulator();
        if (current.length == 0) revert("Accumulator is empty.");

        r.currentEpoch++;

        //event kiküldés
        emit UpdatedRegistry(
            registryId,
            r.currentEpoch,
            current,
            addedScalars,
            revokedScalars
        );
    }


    function getRegistry(bytes32 registryId) external view returns (bytes memory value, uint256 epoch){
        RevocationList storage r = lists[registryId];
        if (!(r.createdAt > 0)) revert("This RevocationList does not exist.");
        return (r.currentAccumulator.getAccumulator(), r.currentEpoch);
    }
}