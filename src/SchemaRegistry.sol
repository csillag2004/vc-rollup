pragma solidity ^0.8.24;

contract SchemaRegistry{

    struct Schema {
        address author;
        string name;
        string version;
        string[] attributeNames;
        uint256 createdAt;
    }

    mapping(bytes32 => Schema) private schemas;

    event SchemaRegistered(bytes32 indexed schemaId, address indexed author, string name, string version);


    function registerSchema(
        string calldata name,
        string calldata version,
        string[] calldata attributeNames
    ) external returns (bytes32 schemaId){
        //előszőr revertek
        if (bytes(name).length==0) revert("Name is empty.");
        if (bytes(version).length==0) revert("Version is empty.");
        if (attributeNames.length==0) revert("AttributeNames is empty.");

        schemaId = keccak256(abi.encodePacked(msg.sender, name, version));

        //ha már létezik revert
        if(schemas[schemaId].createdAt != 0){
            revert("This Schema is already exist.");
        }

        //létrehozás
        Schema storage s = schemas[schemaId];
        s.author = msg.sender;
        s.name = name;
        s.version = version;
        s.attributeNames.push("revocation_id");
        s.attributeNames.push("link_secret");
        for (uint256 i = 0; i < attributeNames.length; i++) {
            s.attributeNames.push(attributeNames[i]);
        }
        s.createdAt = block.timestamp;

        //event kiküldés
        emit SchemaRegistered(schemaId, msg.sender, name, version);

        return schemaId;
    }


    function getSchema(bytes32 schemaId) external view returns (Schema memory){
        if(schemas[schemaId].createdAt==0) revert("This schema is not exist.");
        return schemas[schemaId];
    }

    function exists(bytes32 schemaId) external view returns (bool) {
        return schemas[schemaId].createdAt != 0;
    }


}
