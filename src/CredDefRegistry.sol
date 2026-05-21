pragma solidity ^0.8.24;
import {SchemaRegistry} from "./SchemaRegistry.sol";

contract CredDefRegistry{

    struct CredDef {
        address issuer;
        bytes32 schemaId;
        string tag;
        bytes publicKeyMaterial;   // BBS+ public key, stored as opaque bytes
        bytes signParams;
        uint256 createdAt;
    }

    mapping(bytes32 => CredDef) private creddefs;

    SchemaRegistry public schemaRegistry;

    constructor(address _schemaRegistry) {
        schemaRegistry = SchemaRegistry(_schemaRegistry);
    }

    event CredDefRegistered(bytes32 indexed credDefId, address indexed issuer, bytes32 indexed schemaId, string tag);

    function registerCredDef(
        bytes32 schemaId,
        string calldata tag,
        bytes calldata publicKeyMaterial,
        bytes calldata signParams
    ) external returns (bytes32 credDefId){
        //revertek
        if (bytes(tag).length==0) revert("Tag is empty.");
        if (publicKeyMaterial.length == 0) revert("PublicKeyMaterial is empty.");
        if (signParams.length == 0) revert ("SignParams is empty");
        try schemaRegistry.getSchema(schemaId) {
            // létezik, mehet tovább
        } catch {
            revert("This schema does not exist.");
        }
    
        credDefId = keccak256(abi.encodePacked(msg.sender, schemaId, tag));

        //ha már létezik revert
        if (creddefs[credDefId].createdAt != 0){
            revert("This CredDef is already exist.");
        }

        //létrehozás
        CredDef storage c = creddefs[credDefId];
        c.issuer = msg.sender;
        c.schemaId = schemaId;
        c.tag = tag;
        c.publicKeyMaterial = publicKeyMaterial;
        c.signParams = signParams;
        c.createdAt = block.timestamp;

        //event kiküldés
        emit CredDefRegistered(credDefId, msg.sender, schemaId, tag);

        return credDefId;
    }


    function getCredDef(bytes32 credDefId) external view returns (CredDef memory){
        if(creddefs[credDefId].createdAt==0) revert("This CredDef is not exist.");
        return creddefs[credDefId];
    }

}