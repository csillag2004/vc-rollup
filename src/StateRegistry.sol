pragma solidity ^0.8.24;

contract StateRegistry {
    
    //ezek a konstansok a BLS12-381 szabványos generátorai, ellenőrizni kell, hogy tényleg jók-e
    bytes public constant G1_GENERATOR =
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes public constant G2_GENERATOR =
        hex"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";


    address issuer;
    bytes A; //aktív accumulator érték, G1
    bytes R; //revocation accumulator érték, G2
    bytes I; //issuer accumulator érték, G1
    bytes V0; //A kezdőértéke, G1
    bytes Qtilde; //accumulator kulcs, G2
    bytes Q; //accumulátor kulcs, G1
    bytes WIR; //I << R witness, G1
    //bytes params -> könyvtár függő, hogy kellenek-e
    uint64 version;
    bytes32 srsHash;
    uint32 srsLength;

    enum Status { None, Registered, Included, Requested, Revoked }

    /// Egy regisztrált kiadás. A commitment rejti y-t a revokálásig.
    struct Issuance {
        bytes32 credDefId;
        //AMÚGY MI EZ??? Csak revokálásra vonatkozik, később lehet kell egy issuencre is
        bytes32 guardDigest;  // 0 = feltétel nélküli; egyébként csak őrzött revokálás, ezzel a digesttel
        uint64  includedAt;   // az a version, amelyik I-jébe az ADMIN beszámolta; 0 = még nincs benne
        uint64  revokedAt;    // az a version, amelyben revokálták; 0 = nincs revokálva
        Status status;        // a commitment státusza
    }


    struct Group {
        address creator; 
        bytes32[] members;
        uint256 createdAt;
    }

    CredDefRegistry public immutable credDefRegistry;
    IEthereumDIDRegistry public immutable didRegistry; //kell DID?
    address public immutable adminDid;

    mapping(uint64 version => bytes32) private valuesHashes; //version -> hash(A,R,I)
    mapping(bytes32 commitment => Issuance) private issuances;
    // A revokedLog y szerinti indexe: y → a commitment, amely alatt revokálták (0 = nincs revokálva).
    // Ugyanazt tudja, mint a log, csak O(1)-ben kereshető; a groupVersion és a dupla-y szűrés használja.
    // Átmeneti megoldás verify on read módban: verify on write-ban (D-10) egy A elleni receipt
    // pairing-ellenőrzése váltja ki (e(C, g̃^y·Q̃) = e(A, g̃)), és az index elhagyható.
    mapping(bytes32 y => bytes32 commitment) private revokedCommitment;
    bytes32[] private revokedLog;                                // append-only (SP-L-c-22)
    mapping(bytes32 groupId => Group) private groups;


    event SrsPublished(uint32 degree, bytes32 srsHash, bytes[] g1Powers, bytes[] g2Powers);
    event IssuanceRegistered(bytes32 indexed credDefId, bytes32 indexed commitment);
    event Issued(uint64 indexed version, bytes32[] commitments, bytes newI, bytes newWIR);
    event RevocationRequested(bytes32 indexed credDefId, bytes32 indexed commitment, bytes32 guardDigest);
    event RevocationRequestCancelled(bytes32 indexed credDefId, bytes32 indexed commitment);
    event Revoked(uint64 indexed version, bytes32 indexed y, bytes32 indexed credDefId, bytes32 commitment, bytes newA, bytes newRtilde, bytes newWIR, bytes32 guardDigest);
    event GuardedAction(uint64 indexed version, address indexed consumer, bytes32 guardDigest);
    event GroupCreated(bytes32 indexed groupId, address indexed creator, bytes32 label, bytes32[] members);

    error ZeroAddress();
    error NotAdmin(address caller);
    error NotIssuer(bytes32 credDefId, address caller);
    error UnknownCredDef(bytes32 credDefId);
    error BadG1Length(uint256 length);
    error BadG2Length(uint256 length);
    error EmptyCommitment();
    error WrongStatus(bytes32 commitment, Status expected, Status actual);
    error WrongCredDef(bytes32 commitment, bytes32 expected, bytes32 actual);
    error GuardedRequest(bytes32 commitment, bytes32 guardDigest);
    error NothingToInclude();
    error EmptyRevocationId();
    error AlreadyRevoked(bytes32 y);
    error StaleVersion(uint64 expected, uint64 current);
    error StaleGroupVersion(bytes32 groupId, uint64 expected, uint64 current);
    error UnknownGroup(bytes32 groupId);
    error GroupExists(bytes32 groupId);
    error EmptyGroup();
    error MembersNotSorted(uint256 index);
    error IndexOutOfRange(uint256 index);
    error SrsAlreadyPublished();
    error SrsNotPublished();
    error BadSrsLength(uint256 g1Count, uint256 g2Count);
    error SrsMismatch(uint256 index);
    error GroupTooLarge(uint256 size, uint32 srsDegree);


    constructor(
        address _credDefRegistry,
        address _adminDid,
        bytes memory _V0,
        bytes memory _Qtilde,
        bytes memory _Q
    ) {
        if (_credDefRegistry == address(0) || _adminDid == address(0)) revert ZeroAddress();
        if (_V0.length != G1_GENERATOR.length) revert BadG1Length(_V0.length);
        if (_Qtilde.length != G2_GENERATOR.length) revert BadG2Length(_Qtilde.length);
        if (_Q.length != 0 && _Q.length != G1_GENERATOR.length) revert BadG1Length(_Q.length);

        credDefRegistry = CredDefRegistry(_credDefRegistry);
        didRegistry = CredDefRegistry(_credDefRegistry).didRegistry();
        adminDid = _adminDid;

        V0 = _V0;
        Qtilde = _Qtilde;
        Q = _Q;
        A = _V0;
        Rtilde = G2_GENERATOR;
        I = G1_GENERATOR;
        WIR = G1_GENERATOR;
        valuesHashes[0] = _valuesHash();
    }

    modifier onlyAdmin() {
        if (didRegistry.identityOwner(adminDid) != msg.sender) revert NotAdmin(msg.sender);
        _;
    }

    modifier onlyIssuerOf(bytes32 credDefId) {
        if (!credDefRegistry.exists(credDefId)) revert UnknownCredDef(credDefId);
        if (didRegistry.identityOwner(credDefRegistry.issuerOf(credDefId)) != msg.sender) {
            revert NotIssuer(credDefId, msg.sender);
        }
        _;
    }


    function _valuesHash() private view returns (bytes32) {
        return keccak256(abi.encode(A, Rtilde, I));
    }
}