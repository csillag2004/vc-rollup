pragma solidity ^0.8.24;

import {CredDefRegistry, IEthereumDIDRegistry} from "./CredDefRegistry.sol";

contract StateRegistry {
    
    //ezek a konstansok a BLS12-381 szabványos generátorai, ellenőrizni kell, hogy tényleg jók-e
    bytes public constant G1_GENERATOR =
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes public constant G2_GENERATOR =
        hex"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

    struct Registry{
        bytes32 credDefId;
        bytes32 label;
        bytes A; //aktív accumulator érték, G1
        bytes Rtilde; //revocation accumulator érték, G2
        bytes I; //issuer accumulator érték, G1
        bytes V0; //A kezdőértéke, G1
        bytes Qtilde; //accumulator kulcs, G2
        bytes Q; //accumulátor kulcs, G1
        bytes WIR; //I << R witness, G1
        //bytes params -> könyvtár függő, hogy kellenek-e
        uint64 version;
        bytes32 srsHash;
        uint32 srsDegree;
        uint256 createdAt;
    }


    struct Group {
        bytes32 registryId; 
        address creator; 
        bytes32[] members;
        uint256 createdAt;
    }

    CredDefRegistry public immutable credDefRegistry;
    IEthereumDIDRegistry public immutable didRegistry; //kell DID?

    mapping(bytes32 registryId => Registry) private registries;
    mapping(bytes32 credDefId => bytes32[]) private registriesOfCredDef;
    mapping(bytes32 registryId => mapping(uint64 version => bytes32)) private valuesHashes;      // keccak(A, R̃, I)
    // y → a version, amelyben revokálták (0 = nincs revokálva). A revokedLog y szerinti indexe:
    // a groupVersion és a dupla revokálás szűrése használja. Átmeneti megoldás verify on read módban:
    // verify on write-ban (D-10) egy A elleni receipt pairing-ellenőrzése váltja ki (e(C, g̃^y·Q̃) = e(A, g̃)).
    mapping(bytes32 registryId => mapping(bytes32 y => uint64)) private revokedAtVersion;
    mapping(bytes32 registryId => bytes32[]) private revokedLog;                                  // append-only (SP-L-c-22)
    mapping(bytes32 groupId => Group) private groups;


    event RegistryCreated(bytes32 indexed registryId, bytes32 indexed credDefId, bytes32 label, bytes V0, bytes Qtilde, bytes Q);
    event SrsPublished(bytes32 indexed registryId, uint32 degree, bytes32 srsHash, bytes[] g1Powers, bytes[] g2Powers);
    event Issued(bytes32 indexed registryId, uint64 indexed version, bytes newI, bytes newWIR);
    // guardDigest = 0 a nem őrzött revokálásnál; egyébként keccak256(abi.encode(query, proof))
    event Revoked(bytes32 indexed registryId, uint64 indexed version, bytes32 indexed y, bytes newA, bytes newRtilde, bytes newWIR, bytes32 guardDigest);
    event GroupCreated(bytes32 indexed groupId, bytes32 indexed registryId, address indexed creator, bytes32 label, bytes32[] members);

    error ZeroAddress();
    error UnknownCredDef(bytes32 credDefId);
    error UnknownRegistry(bytes32 registryId);
    error RegistryExists(bytes32 registryId);
    error NotIssuer(bytes32 credDefId, address caller);
    error BadG1Length(uint256 length);
    error BadG2Length(uint256 length);
    error EmptyRevocationId();
    error AlreadyRevoked(bytes32 y);
    error StaleVersion(uint64 expected, uint64 current);
    error StaleGroupVersion(bytes32 groupId, uint64 expected, uint64 current);
    error UnknownGroup(bytes32 groupId);
    error GroupExists(bytes32 groupId);
    error EmptyGroup();
    error MembersNotSorted(uint256 index);
    error GroupTooLarge(uint256 size, uint32 srsDegree);
    error IndexOutOfRange(uint256 index);
    error SrsAlreadyPublished();
    error SrsNotPublished();
    error BadSrsLength(uint256 g1Count, uint256 g2Count);
    error SrsMismatch(uint256 index);


    constructor(address _credDefRegistry) {
        if (_credDefRegistry == address(0)) revert ZeroAddress();
        credDefRegistry = CredDefRegistry(_credDefRegistry);
        // ugyanazt a DID registryt használjuk, mint a CredDefRegistry, így nem csúszhat szét a kettő
        didRegistry = CredDefRegistry(_credDefRegistry).didRegistry();
    }

    modifier onlyIssuer(bytes32 registryId) {
        _requireIssuer(_credDefOf(registryId));
        _;
    }

    modifier whenInitialized(bytes32 registryId) {
        if (registries[registryId].srsHash == bytes32(0)) revert SrsNotPublished();
        _;
    }



    ///LÉTREHOZÁS
        function createRegistry(
        bytes32 credDefId,
        bytes32 label,
        bytes calldata V0,
        bytes calldata Qtilde,
        bytes calldata Q
    ) external returns (bytes32 registryId) {
        _requireIssuer(credDefId);
        registryId = keccak256(abi.encode(credDefId, label));
        Registry storage r = registries[registryId];
        if (r.createdAt != 0) revert RegistryExists(registryId);

        _checkG1(V0);
        _checkG2(Qtilde);
        if (Q.length != 0) _checkG1(Q);

        r.credDefId = credDefId;
        r.label = label;
        r.V0 = V0;
        r.Qtilde = Qtilde;
        r.Q = Q;
        r.A = V0;
        r.Rtilde = G2_GENERATOR;
        r.I = G1_GENERATOR;
        r.WIR = G1_GENERATOR;
        r.createdAt = block.timestamp;
        valuesHashes[registryId][0] = _valuesHash(r);
        registriesOfCredDef[credDefId].push(registryId);

        emit RegistryCreated(registryId, credDefId, label, V0, Qtilde, Q);
    }


    function publishSrs(bytes32 registryId, bytes[] calldata g1Powers, bytes[] calldata g2Powers) external onlyIssuer(registryId) {
        Registry storage r = registries[registryId];
        if (r.srsHash != bytes32(0)) revert SrsAlreadyPublished();
        uint256 len = g2Powers.length;
        if (len < 2 || g1Powers.length != len) revert BadSrsLength(g1Powers.length, len);

        for (uint256 i = 0; i < len; i++) {
            _checkG1(g1Powers[i]);
            _checkG2(g2Powers[i]);
        }
        if (keccak256(g1Powers[0]) != keccak256(G1_GENERATOR)) revert SrsMismatch(0);
        if (keccak256(g2Powers[0]) != keccak256(G2_GENERATOR)) revert SrsMismatch(0);
        if (keccak256(g2Powers[1]) != keccak256(r.Qtilde)) revert SrsMismatch(1);
        if (r.Q.length != 0 && keccak256(g1Powers[1]) != keccak256(r.Q)) revert SrsMismatch(1);

        bytes32 h = keccak256(abi.encode(g1Powers, g2Powers));
        r.srsHash = h;
        r.srsDegree = uint32(len - 1);
        emit SrsPublished(registryId, r.srsDegree, h, g1Powers, g2Powers);
    }


    ///KIADÁS
    function issueUpdate(bytes32 registryId, bytes calldata newI, bytes calldata newWIR)
        external onlyIssuer(registryId) whenInitialized(registryId)
    {
        _checkG1(newI);
        _checkG1(newWIR);
        Registry storage r = registries[registryId];
        r.I = newI;
        r.WIR = newWIR;
        r.version += 1;                                  // a kiadás is új version (SP-L-c-21)
        valuesHashes[registryId][r.version] = _valuesHash(r);
        emit Issued(registryId, r.version, newI, newWIR);
    }


    ///REVOCATION
    function revoke(
        bytes32 registryId,
        bytes32 y,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR
    ) external onlyIssuer(registryId) {
        _applyRevoke(registryId, y, newA, newRtilde, newWIR, bytes32(0));
    }

    function guardedRevoke(
        bytes32 registryId,
        uint64 expectedVersion,
        bytes32 y,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR,
        bytes32 guardDigest
    ) external onlyIssuer(registryId) {
        uint64 current = registries[registryId].version;
        if (current != expectedVersion) revert StaleVersion(expectedVersion, current);   // compare
        _applyRevoke(registryId, y, newA, newRtilde, newWIR, guardDigest);                 // swap
    }

    function guardedRevokeNarrowed(
        bytes32 groupId,
        uint64 expectedVersion,
        uint64 expectedGroupVersion,
        bytes32 y,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR,
        bytes32 guardDigest
    ) external {
        _checkGroupFresh(groupId, expectedGroupVersion);
        bytes32 registryId = groups[groupId].registryId;
        _requireIssuer(_credDefOf(registryId));
        uint64 current = registries[registryId].version;
        if (current != expectedVersion) revert StaleVersion(expectedVersion, current);
        _applyRevoke(registryId, y, newA, newRtilde, newWIR, guardDigest);
    }


    ///GROUPS
    function createGroup(bytes32 registryId, bytes32 label, bytes32[] calldata members)
        external whenInitialized(registryId) returns (bytes32 groupId)
    {
        uint32 degree = registries[registryId].srsDegree;
        if (members.length == 0) revert EmptyGroup();
        if (members.length > degree) revert GroupTooLarge(members.length, degree);
        if (members[0] == bytes32(0)) revert EmptyRevocationId();
        for (uint256 i = 1; i < members.length; i++) {
            if (members[i] <= members[i - 1]) revert MembersNotSorted(i);
        }

        groupId = keccak256(abi.encode(registryId, msg.sender, label));
        Group storage g = groups[groupId];
        if (g.createdAt != 0) revert GroupExists(groupId);
        g.registryId = registryId;
        g.creator = msg.sender;
        g.createdAt = block.timestamp;
        g.members = members;

        emit GroupCreated(groupId, registryId, msg.sender, label, members);
    }


    function groupVersion(bytes32 groupId) public view returns (uint64 v) {
        Group storage g = groups[groupId];
        if (g.createdAt == 0) revert UnknownGroup(groupId);
        bytes32[] storage m = g.members;
        mapping(bytes32 => uint64) storage revokedIn = revokedAtVersion[g.registryId];
        for (uint256 i = 0; i < m.length; i++) {
            if (revokedIn[m[i]] != 0) v++;
        }
    }


    ///OLVASÓ FÜGGVÉNYEK
    function getRegistry(bytes32 registryId) external view returns (Registry memory) {
        if (registries[registryId].createdAt == 0) revert UnknownRegistry(registryId);
        return registries[registryId];
    }

    function exists(bytes32 registryId) external view returns (bool) {
        return registries[registryId].createdAt != 0;
    }

    /// Egy CredDef összes partíciója, létrehozási sorrendben.
    function registriesOf(bytes32 credDefId) external view returns (bytes32[] memory) {
        return registriesOfCredDef[credDefId];
    }

    function registryIdOf(bytes32 credDefId, bytes32 label) external pure returns (bytes32) {
        return keccak256(abi.encode(credDefId, label));
    }

    /// Az állapot és a version, amire egy proof köthető.
    function getValues(bytes32 registryId)
        external view
        returns (bytes memory A, bytes memory Rtilde, bytes memory I, bytes memory WIR, uint64 version)
    {
        Registry storage r = registries[registryId];
        if (r.createdAt == 0) revert UnknownRegistry(registryId);
        return (r.A, r.Rtilde, r.I, r.WIR, r.version);
    }

    /// Történeti érték hitelesítése (1.4, Rule 1). keccak256(abi.encode(A, Rtilde, I)); jövőbeli versionre 0.
    /// W_IR-t nem kell hash-elni: I és R̃ egyértelműen meghatározza (e(W_IR, R̃) = e(I, g̃)).
    function valuesHashAt(bytes32 registryId, uint64 version) external view returns (bytes32) {
        return valuesHashes[registryId][version];
    }

    function isRevoked(bytes32 registryId, bytes32 y) external view returns (bool) {
        return revokedAtVersion[registryId][y] != 0;
    }

    /// Melyik versionnél került y R̃-ba (0 = nincs revokálva). A free receipt a közvetlenül előtte lévő R̃.
    function revokedAt(bytes32 registryId, bytes32 y) external view returns (uint64) {
        return revokedAtVersion[registryId][y];
    }

    function revokedCount(bytes32 registryId) external view returns (uint256) {
        return revokedLog[registryId].length;
    }

    /// Lapozható olvasás a holderek receipt-frissítéséhez.
    function getRevokedLog(bytes32 registryId, uint256 start, uint256 count) external view returns (bytes32[] memory out) {
        bytes32[] storage log = revokedLog[registryId];
        if (start > log.length) revert IndexOutOfRange(start);
        uint256 end = start + count > log.length ? log.length : start + count;
        out = new bytes32[](end - start);
        for (uint256 i = start; i < end; i++) out[i - start] = log[i];
    }

    function getGroup(bytes32 groupId)
        external view
        returns (bytes32 registryId, address creator, uint256 createdAt, bytes32[] memory members)
    {
        Group storage g = groups[groupId];
        if (g.createdAt == 0) revert UnknownGroup(groupId);
        return (g.registryId, g.creator, g.createdAt, g.members);
    }

    /// A tagok rendezettek, ezért bináris kereséssel.
    function isGroupMember(bytes32 groupId, bytes32 y) external view returns (bool) {
        Group storage g = groups[groupId];
        if (g.createdAt == 0) revert UnknownGroup(groupId);
        bytes32[] storage m = g.members;
        uint256 lo = 0;
        uint256 hi = m.length;
        while (lo < hi) {
            uint256 mid = (lo + hi) / 2;
            if (m[mid] == y) return true;
            if (m[mid] < y) lo = mid + 1;
            else hi = mid;
        }
        return false;
    }

    //Masik contractnak hasznos lehet, per pillant nekünk szerintem nem kell
    //function guardedAction(bool checkVersion, uint64 expectedVersion, bytes32 guardDigest) external;

    ///SEGÉDFÜGGVÉNYEK
    function _valuesHash(Registry storage r) private view returns (bytes32) {
        return keccak256(abi.encode(r.A, r.Rtilde, r.I));
    }

    function _checkG1(bytes calldata p) private pure {
        if (p.length != G1_GENERATOR.length) revert BadG1Length(p.length);
    }

    function _checkG2(bytes calldata p) private pure {
        if (p.length != G2_GENERATOR.length) revert BadG2Length(p.length);
    }

    function _requireIssuer(bytes32 credDefId) private view {
        if (!credDefRegistry.exists(credDefId)) revert UnknownCredDef(credDefId);
        if (didRegistry.identityOwner(credDefRegistry.issuerOf(credDefId)) != msg.sender) {
            revert NotIssuer(credDefId, msg.sender);
        }
    }

    function _applyRevoke(
        bytes32 registryId,
        bytes32 y,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR,
        bytes32 guardDigest
    ) private {
        if (y == bytes32(0)) revert EmptyRevocationId();
        if (revokedAtVersion[registryId][y] != 0) revert AlreadyRevoked(y);
        _checkG1(newA);
        _checkG2(newRtilde);
        _checkG1(newWIR);

        Registry storage r = registries[registryId];
        r.A = newA;
        r.Rtilde = newRtilde;
        r.WIR = newWIR;
        r.version += 1;
        valuesHashes[registryId][r.version] = _valuesHash(r);

        revokedAtVersion[registryId][y] = r.version;
        revokedLog[registryId].push(y);

        emit Revoked(registryId, r.version, y, newA, newRtilde, newWIR, guardDigest);
    }

    function _checkGroupFresh(bytes32 groupId, uint64 expectedGroupVersion) private view {
        uint64 gv = groupVersion(groupId);
        if (gv != expectedGroupVersion) revert StaleGroupVersion(groupId, expectedGroupVersion, gv);
    }

    function _credDefOf(bytes32 registryId) private view returns (bytes32) {
        Registry storage r = registries[registryId];
        if (r.createdAt == 0) revert UnknownRegistry(registryId);
        return r.credDefId;
    }
}