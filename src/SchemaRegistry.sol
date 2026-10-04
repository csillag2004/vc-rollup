pragma solidity ^0.8.24;

contract SchemaRegistry{

    struct Schema {
        address author;
        string name;
        string version;
        bool holderBound;
        string[] attributeNames;
        uint256 createdAt;
    }

    string private constant REVOCATION_ID = "revocation_id";
    string private constant LINK_SECRET = "link_secret";
    bytes32 private constant REVOCATION_ID_HASH = keccak256(bytes(REVOCATION_ID));
    bytes32 private constant LINK_SECRET_HASH = keccak256(bytes(LINK_SECRET));

    mapping(bytes32 => Schema) private schemas;

    event SchemaRegistered(bytes32 indexed schemaId, address indexed author, string name, string version, bool holderBound);

    error EmptyName();
    error EmptyVersion();
    error NoAttributes();
    //error TooManyAttributes();
    error EmptyAttributeName(uint256 index);
    error ReservedAttributeName(uint256 index);
    error DuplicateAttribute(uint256 index);
    error SchemaExists(bytes32 schemaId);
    error UnknownSchema(bytes32 schemaId);

    function registerSchema(
        string calldata name,
        string calldata version,
        bool holderBound,
        string[] calldata attributeNames
    ) external returns (bytes32 schemaId){
        //előszőr revertek
        if (bytes(name).length==0) revert EmptyName();
        if (bytes(version).length==0) revert EmptyVersion();
        if (attributeNames.length==0) revert NoAttributes();
        
        uint256 n = attributeNames.length;
        // nevek: nem üres, nem a két protokoll-mező neve, egyedi
        bytes32[] memory hashes = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            if (bytes(attributeNames[i]).length == 0) revert EmptyAttributeName(i);
            bytes32 h = keccak256(bytes(attributeNames[i]));
            if (h == REVOCATION_ID_HASH || h == LINK_SECRET_HASH) revert ReservedAttributeName(i);
            for (uint256 j = 0; j < i; j++) {
                if (hashes[j] == h) revert DuplicateAttribute(i);
            }
            hashes[i] = h;
        }


        schemaId = keccak256(abi.encode(msg.sender, name, version, holderBound));

        //ha már létezik revert
        if(schemas[schemaId].createdAt != 0){
            revert SchemaExists(schemaId);
        }

        //létrehozás
        Schema storage s = schemas[schemaId];
        s.author = msg.sender;
        s.name = name;
        s.version = version;
        s.holderBound = holderBound;
        s.attributeNames.push(REVOCATION_ID);
        for (uint256 i = 0; i < attributeNames.length; i++) {
            s.attributeNames.push(attributeNames[i]);
        }
        if (holderBound) {
            s.attributeNames.push(LINK_SECRET);
        }
        s.createdAt = block.timestamp;
        

        //event kiküldés
        emit SchemaRegistered(schemaId, msg.sender, name, version, holderBound);

        return schemaId;
    }


    function getSchema(bytes32 schemaId) external view returns (Schema memory){
        if(schemas[schemaId].createdAt==0) revert UnknownSchema(schemaId);
        return schemas[schemaId];
    }

    function exists(bytes32 schemaId) external view returns (bool) {
        return schemas[schemaId].createdAt != 0;
    }

    function isHolderBound(bytes32 schemaId) external view returns (bool) {
        if (schemas[schemaId].createdAt == 0) revert UnknownSchema(schemaId);
        return schemas[schemaId].holderBound;
    }

}
