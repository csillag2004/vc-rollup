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
        //bytes publicKeyMaterial;   // BBS+ public key, stored as opaque bytes
        //bytes signParams; -> ezeket akarom kiszedni
        bytes32 keyId;
        uint256 createdAt;
    }

    mapping(bytes32 => CredDef) private creddefs;

    SchemaRegistry public immutable schemaRegistry;
    IEthereumDIDRegistry public immutable didRegistry;

    constructor(address _didRegistry, address _schemaRegistry) {
        if (_didRegistry == address(0) || _schemaRegistry == address(0)) revert ZeroAddress();
        didRegistry = IEthereumDIDRegistry(_didRegistry);
        schemaRegistry = SchemaRegistry(_schemaRegistry);
    }

    event CredDefRegistered(bytes32 indexed credDefId, address indexed issuer, bytes32 indexed schemaId, string tag, bytes32 keyId);

    error ZeroAddress();
    error NotDidOwner(address issuer, address caller);
    error EmptyTag();
    error EmptyKeyId();
    error UnknownSchema(bytes32 schemaId);
    error CredDefExists(bytes32 credDefId);
    error UnknownCredDef(bytes32 credDefId);
    //idáig néztem át

    modifier onlyDidOwner(address issuer) {
        if (didRegistry.identityOwner(issuer) != msg.sender) revert NotDidOwner(issuer, msg.sender);
        _;
    }

    function registerCredDef(
        address issuer,
        bytes32 schemaId,
        string calldata tag,
        bytes32 keyId
        //bytes calldata publicKeyMaterial,
        //bytes calldata signParams
    ) external onlyDidOwner(issuer) returns (bytes32 credDefId){
        //revertek
        if (bytes(tag).length==0) revert EmptyTag();
        if (keyId == bytes32(0)) revert EmptyKeyId();
        if (!schemaRegistry.exists(schemaId)) revert UnknownSchema(schemaId);
        //if (publicKeyMaterial.length == 0) revert("PublicKeyMaterial is empty.");
        //if (signParams.length == 0) revert ("SignParams is empty");
    
        credDefId = keccak256(abi.encodePacked(issuer, schemaId, tag));

        //ha már létezik revert
        if (creddefs[credDefId].createdAt != 0){
            revert CredDefExists(credDefId);
        }

        //létrehozás
        CredDef storage c = creddefs[credDefId];
        c.issuer = issuer;
        c.schemaId = schemaId;
        c.tag = tag;
        c.keyId = keyId;
        //c.publicKeyMaterial = publicKeyMaterial;
        //c.signParams = signParams;
        c.createdAt = block.timestamp;

        //event kiküldés
        emit CredDefRegistered(credDefId, issuer, schemaId, tag, keyId);

        return credDefId;
    }


    function getCredDef(bytes32 credDefId) external view returns (CredDef memory){
        if(creddefs[credDefId].createdAt==0) revert UnknownCredDef(credDefId);
        return creddefs[credDefId];
    }

    
    function exists(bytes32 credDefId) external view returns (bool) {
        return creddefs[credDefId].createdAt != 0;
    }

    // A StatusRegistry ezzel tudja ellenőrizni, ki revokálhat: identityOwner(issuerOf(id)) == msg.sender
    function issuerOf(bytes32 credDefId) external view returns (address) {
        if (creddefs[credDefId].createdAt == 0) revert UnknownCredDef(credDefId);
        return creddefs[credDefId].issuer;
    }

}