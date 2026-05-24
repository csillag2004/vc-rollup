pragma solidity ^0.8.24;
import {SchemaRegistry} from "./SchemaRegistry.sol";

interface IEthereumDIDRegistry {
    function identityOwner(address identity) external view returns (address);
}

contract CredDefRegistry{

    struct CredDef {
        address issuer;
        bytes32 schemaId;
        string tag;
        uint256 createdAt;
    }

    mapping(bytes32 => CredDef) private creddefs;

    SchemaRegistry public schemaRegistry;
    IEthereumDIDRegistry public didRegistry;

    constructor(address _schemaRegistry, address _didRegistry) {
        schemaRegistry = SchemaRegistry(_schemaRegistry);
        didRegistry = IEthereumDIDRegistry(_didRegistry);
    }

    event CredDefRegistered(bytes32 indexed credDefId, address indexed issuer, bytes32 indexed schemaId, string tag);

    function registerCredDef(
        address issuer,
        bytes32 schemaId,
        string calldata tag
    ) external returns (bytes32 credDefId){
        //revertek
        if (bytes(tag).length==0) revert("Tag is empty.");
        require(didRegistry.identityOwner(issuer)==msg.sender, "Not the DID controller");
        try schemaRegistry.getSchema(schemaId) {
            // létezik, mehet tovább
        } catch {
            revert("This schema does not exist.");
        }
    
        credDefId = keccak256(abi.encodePacked(issuer, schemaId, tag));

        //ha már létezik revert
        if (creddefs[credDefId].createdAt != 0){
            revert("This CredDef is already exist.");
        }

        //létrehozás
        CredDef storage c = creddefs[credDefId];
        c.issuer = issuer;
        c.schemaId = schemaId;
        c.tag = tag;
        c.createdAt = block.timestamp;

        //event kiküldés
        emit CredDefRegistered(credDefId, issuer, schemaId, tag);

        return credDefId;
    }


    function getCredDef(bytes32 credDefId) external view returns (CredDef memory){
        if(creddefs[credDefId].createdAt==0) revert("This CredDef is not exist.");
        return creddefs[credDefId];
    }

}