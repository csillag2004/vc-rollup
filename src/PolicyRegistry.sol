/*import {console} from "forge-std/console.sol";
 

contract PolicyRegistry {
    enum Operation { Issuance, Presentation, Revocation }
    enum Validation { Valid, Revoked, Invalid }
    enum DAGType { AND, OR, XOR } //inverzót még átgondolom, több kapu

    //predikátumhalmazokat akarjunk tárolni
    //predikátumot akarjunk visszaadni
    //találjuk ki a solidity-> Rust predikátum interfészt
    //Rust könyvtár létezik-e string->bool hálózat ÉS solidityben van-e létező contract rá
    //DAG (revoke, invalid) hogy néz ki, schema id
    //CSP

    struct Leaf{
        bytes32 schemaId;  //hosszútávon nem a legjobb megoldás
        Validation validation;
        address[] issuers;
    }

    struct Gate{  //ne csak két bemenete legyen (a kiértékelő tudja-e kezelni a többet)
        DAGType dagType;
        //uint16[] inputs;  
        uint16 right;
        uint16 left;
    }

    struct DAG{
        //A gyökér node id-je mindig L+G-1.
        //0-tol a levelek id-jei, L-tol a kapuk id-jei. A kapuk `left`/`right` mezője id, tehát levélre és kapura egyaránt mutathat.
        uint16 root;
        Leaf[] leaves;
        Gate[] gates;
        uint256 createdAt;
        bool valid;
    }

    address public admin;

    constructor(address _admin) {
        admin = _admin;
    }

    //schemaId => Operation => DAG (nem kell policyId, mert a policyId a schemaId + operation)
    mapping(bytes32 => mapping(Operation => DAG)) private _policies;




    event PolicySet(bytes32 indexed schemaId, Operation indexed operation, uint16 root, uint256 createdAt);
    event PolicyDeactivated(bytes32 indexed schemaId, Operation indexed operation, uint256 deactivatedAt);
    event PolicyActivated(bytes32 indexed schemaId, Operation indexed operation, uint256 activatedAt);

    function setPolicy(bytes32 schemaId, Operation operation, Leaf[] calldata leaves, Gate[] calldata gates) external {
        if(msg.sender != admin) revert("Only admin can set policy.");
        uint256 L = leaves.length;
        uint256 G = gates.length;
        if(L == 0) revert("Leaves cannot be empty.");
        if(G == 0) revert("Gates cannot be empty.");
        if (L + G > type(uint16).max) revert("Too many nodes.");

        uint16 root = uint16(L + G - 1);

        // --- validálás ---
        for (uint256 i = 0; i < L; i++) {
            address[] calldata iss = leaves[i].issuers;
            if (iss.length == 0) revert("Leaf has no issuers.");
            for (uint256 j = 1; j < iss.length; j++) {
                if (iss[j] <= iss[j - 1]) revert("Issuers must be sorted and unique.");
            }
        }


        uint32[] memory used = new uint32[](L + G);
        for (uint256 i = 0; i < G; i++) {
            uint16 id = uint16(L + i);
            // csak korábbi node -> körmentes ÉS topologikus sorrend
            if (gates[i].left >= id || gates[i].right >= id) revert("Gate input must be earlier.");
            used[gates[i].left] += 1;
            used[gates[i].right] += 1;
        }
        for (uint256 i = 0; i < L + G; i++) {
            if (uint16(i) == root) {
                if (used[i] != 0) revert("Root must not be referenced.");
            } else if (used[i] == 0) {
                revert("Dead node.");
            }
        }


        // --- írás ---
        DAG storage d = _policies[schemaId][operation];

        delete d.leaves;   // különben a régi, hosszabb tömb vége bennmarad
        delete d.gates;

        d.root = root;
        d.createdAt = block.timestamp;
        d.valid = true;

        for (uint256 i = 0; i < L; i++) {
            d.leaves.push();
            Leaf storage l = d.leaves[i];
            l.schemaId = leaves[i].schemaId;
            l.validation = leaves[i].validation;
            for (uint256 j = 0; j < leaves[i].issuers.length; j++) {
                l.issuers.push(leaves[i].issuers[j]);
            }
        }
        for (uint256 i = 0; i < G; i++) {
            d.gates.push(gates[i]);   // a Gate csak skalár, ez mehet egyben
        }
        emit PolicySet(schemaId, operation, root, block.timestamp);
    }

    function deactivatePolicy(bytes32 schemaId, Operation operation) external {
        if(msg.sender != admin) revert("Only admin can deactivate policy.");
        if(_policies[schemaId][operation].createdAt == 0) revert("Policy does not exist.");
        if(!_policies[schemaId][operation].valid) revert("Policy is already deactivated.");
        _policies[schemaId][operation].valid = false;
        emit PolicyDeactivated(schemaId, operation, block.timestamp);
    }

    function activatePolicy(bytes32 schemaId, Operation operation) external {
        if(msg.sender != admin) revert("Only admin can activate policy.");
        if(_policies[schemaId][operation].createdAt == 0) revert("Policy does not exist.");
        if(_policies[schemaId][operation].valid) revert("Policy is already activated.");
        _policies[schemaId][operation].valid = true;
        emit PolicyActivated(schemaId, operation, block.timestamp);
    }

    function getPolicy(bytes32 schemaId, Operation operation) external view returns (DAG memory) {
        if(_policies[schemaId][operation].createdAt == 0) revert("Policy does not exist.");
        return _policies[schemaId][operation];
    }
}*/