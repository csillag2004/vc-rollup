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

    /// Egy regisztrált kiadás. A commitment rejti y-t a revokálásig.
    struct Issuance {
        bytes32 credDefId;
        uint64  includedAt;   // az a version, amelyik I-jébe az ADMIN beszámolta; 0 = még nincs benne
    }

        /// Egy issuer által kért, még végre nem hajtott revokálás.
    struct RevocationRequest {
        bytes32 credDefId;
        bytes32 commitment;
        bytes32 guardDigest;  // 0 = feltétel nélküli; egyébként csak őrzött revokálás, ezzel a digesttel
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
    mapping(bytes32 y => RevocationRequest) private requests;
    
}