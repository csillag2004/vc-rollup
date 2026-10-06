pragma solidity ^0.8.24;

import {CredDefRegistry, IEthereumDIDRegistry} from "./CredDefRegistry.sol";

contract StateRegistry {
    
    //ezek a konstansok a BLS12-381 szabványos generátorai, ellenőrizni kell, hogy tényleg jók-e
    bytes public constant G1_GENERATOR =
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes public constant G2_GENERATOR =
        hex"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";


    address issuer;
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
    uint32 srsLength;

    enum Status { None, Registered, Included, Requested, Revoked }

    /// Egy regisztrált kiadás. A commitment rejti y-t a revokálásig.
    struct Issuance {
        bytes32 credDefId;
        //AMÚGY MI EZ??? Csak revokálásra vonatkozik, később lehet kell egy issuencre is
        bytes32 guardDigest;  // 0 = feltétel nélküli; egyébként csak őrzött revokálás, ezzel a digesttel
        bytes32 guardGroup;   // a feltétel hatóköre: 0 = globális (guardedRevoke), egyébként egy publikus
                              // csoport (guardedRevokeNarrowed); így nem az ADMIN választja meg
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
    event RevocationRequested(bytes32 indexed credDefId, bytes32 indexed commitment, bytes32 guardDigest, bytes32 guardGroup);
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
    error GuardedRequest(bytes32 commitment, bytes32 guardDigest);
    error GroupWithoutGuard(bytes32 guardGroup);
    error WrongGuardScope(bytes32 commitment, bytes32 guardGroup);
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
    error GroupTooLarge(uint256 size, uint32 srsLength);


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

    modifier whenInitialized() {
        if (srsHash == bytes32(0)) revert SrsNotPublished();
        _;
    }

    function publishSrs(bytes[] calldata g1Powers, bytes[] calldata g2Powers) external onlyAdmin {
        if (srsHash != bytes32(0)) revert SrsAlreadyPublished();
        uint256 len = g2Powers.length;
        if (len < 2 || g1Powers.length != len) revert BadSrsLength(g1Powers.length, len);

        for (uint256 i = 0; i < len; i++) {
            _checkG1(g1Powers[i]);
            _checkG2(g2Powers[i]);
        }
        if (keccak256(g1Powers[0]) != G1_GENERATOR_HASH) revert SrsMismatch(0);
        if (keccak256(g2Powers[0]) != G2_GENERATOR_HASH) revert SrsMismatch(0);
        if (keccak256(g2Powers[1]) != keccak256(Qtilde)) revert SrsMismatch(1);
        if (Q.length != 0 && keccak256(g1Powers[1]) != keccak256(Q)) revert SrsMismatch(1);

        bytes32 h = keccak256(abi.encode(g1Powers, g2Powers));
        srsHash = h;
        srsLength = uint32(len - 1);
        emit SrsPublished(srsLength, h, g1Powers, g2Powers);
    }


    ///KIADÁS

    function registerIssuance(bytes32 credDefId, bytes32 commitment)
        external whenInitialized onlyIssuerOf(credDefId)
    {
        if (commitment == bytes32(0)) revert EmptyCommitment();
        Issuance storage iss = issuances[commitment];
        _expect(commitment, iss, Status.None);
        iss.credDefId = credDefId;
        iss.status = Status.Registered;
        emit IssuanceRegistered(credDefId, commitment);
    }

    /// Off-chain előfeltétel: az issuer kiadáskor privát csatornán elküldi az ADMIN-nak a (credDefId, y, salt) hármast,
    /// az ADMIN ebből és α-ból kiszámolja az új I-t és W_IR-t, a holdernek pedig átadja a kezdeti receiptet: C = A^(1/(y+α)).
    /// Ezt a függvényt az ADMIN hívja, miután a holder a commitmentet regisztrálta, és az issuer kiadta a credentialt.
    function issueUpdate(bytes32[] calldata commitments, bytes calldata newI, bytes calldata newWIR)
        external onlyAdmin
    {
        if (commitments.length == 0) revert NothingToInclude();
        _checkG1(newI);
        _checkG1(newWIR);

        uint64 v = version + 1;
        for (uint256 i = 0; i < commitments.length; i++) {
            Issuance storage iss = issuances[commitments[i]];
            _expect(commitments[i], iss, Status.Registered);
            iss.status = Status.Included;
            iss.includedAt = v;
        }

        I = newI;
        WIR = newWIR;
        version = v;
        valuesHashes[v] = _valuesHash();
        emit Issued(v, commitments, newI, newWIR);
    }


    ///REVOCATION
    //AZ issuer kéri a revokálást
    function requestRevocation(bytes32 commitment, bytes32 guardDigest, bytes32 guardGroup) external {
        Issuance storage iss = issuances[commitment];
        _expect(commitment, iss, Status.Included);   // előbb az állapot: nem létező rekordnál credDefId = 0
        _requireIssuer(iss.credDefId);
        if (guardGroup != bytes32(0)) {
            if (guardDigest == bytes32(0)) revert GroupWithoutGuard(guardGroup);
            if (groups[guardGroup].createdAt == 0) revert UnknownGroup(guardGroup);
        }

        iss.status = Status.Requested;
        iss.guardDigest = guardDigest;
        iss.guardGroup = guardGroup;
        emit RevocationRequested(iss.credDefId, commitment, guardDigest, guardGroup);
    }


    function cancelRevocationRequest(bytes32 commitment) external {
        Issuance storage iss = issuances[commitment];
        _expect(commitment, iss, Status.Requested);
        _requireIssuer(iss.credDefId);

        iss.status = Status.Included;
        iss.guardDigest = bytes32(0);
        iss.guardGroup = bytes32(0);
        emit RevocationRequestCancelled(iss.credDefId, commitment);
    }

    //ADMIN végrehajtja a revokálást
    function revoke(
        bytes32 y,
        bytes32 salt,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR
    ) external onlyAdmin {
        bytes32 c = _checkRequested(y, salt);
        if (issuances[c].guardDigest != bytes32(0)) revert GuardedRequest(c, issuances[c].guardDigest);
        _applyRevoke(y, c, newA, newRtilde, newWIR);
    }

    function guardedRevoke(
        uint64 expectedVersion,
        bytes32 y,
        bytes32 salt,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR
    ) external onlyAdmin {
        if (version != expectedVersion) revert StaleVersion(expectedVersion, version);   // compare
        _applyRevoke(y, _checkRequested(y, salt), newA, newRtilde, newWIR);              // swap
    }

    function guardedRevokeNarrowed(
        uint64 expectedVersion,
        uint64 expectedGroupVersion,
        bytes32 y,
        bytes32 salt,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR
    ) external onlyAdmin {
        if (version != expectedVersion) revert StaleVersion(expectedVersion, version);
        bytes32 c = _checkRequested(y, salt);
        bytes32 groupId = issuances[c].guardGroup;
        if (groupId == bytes32(0)) revert WrongGuardScope(c, groupId);
        _checkGroupFresh(groupId, expectedGroupVersion);
        _applyRevoke(y, c, newA, newRtilde, newWIR);
    }


    ///GROUPS
    function createGroup(bytes32 label, bytes32[] calldata members) external whenInitialized returns (bytes32 groupId) {
        if (members.length == 0) revert EmptyGroup();
        if (members.length > srsLength) revert GroupTooLarge(members.length, srsLength);

        groupId = keccak256(abi.encode(msg.sender, label));
        Group storage g = groups[groupId];
        if (g.createdAt != 0) revert GroupExists(groupId);

        if (members[0] == bytes32(0)) revert EmptyRevocationId();
        for (uint256 i = 1; i < members.length; i++) {
            if (members[i] <= members[i - 1]) revert MembersNotSorted(i);
        }
        g.creator = msg.sender;
        g.createdAt = block.timestamp;
        g.members = members;

        emit GroupCreated(groupId, msg.sender, label, members);
    }


    function groupVersion(bytes32 groupId) public view returns (uint64 v) {
        Group storage g = groups[groupId];
        if (g.createdAt == 0) revert UnknownGroup(groupId);
        bytes32[] storage m = g.members;
        for (uint256 i = 0; i < m.length; i++) {
            if (revokedCommitment[m[i]] != bytes32(0)) v++;
        }
    }

        function commitmentOf(bytes32 y, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(y, salt));
    }


    ///OLVASÓ FÜGGVÉNYEK
    // Az állapot és a version, amire egy proof köthető.
    function getValues()
        external view
        returns (bytes memory, bytes memory, bytes memory, bytes memory, uint64)
    {
        return (A, Rtilde, I, WIR, version);
    }

    // Történeti érték hitelesítése (1.4, Rule 1). keccak256(abi.encode(A, Rtilde, I)); jövőbeli versionre 0.
    // W_IR-t nem kell hash-elni: I és R̃ egyértelműen meghatározza (e(W_IR, R̃) = e(I, g̃)).
    function valuesHashAt(uint64 v) external view returns (bytes32) {
        return valuesHashes[v];
    }

    function getIssuance(bytes32 commitment) external view returns (Issuance memory) {
        return issuances[commitment];
    }

    function isRevoked(bytes32 y) external view returns (bool) {
        return revokedCommitment[y] != bytes32(0);
    }

    // y-ból a teljes Issuance rekordhoz: getIssuance(revokedCommitmentOf(y)). 0, ha y nincs revokálva.
    function revokedCommitmentOf(bytes32 y) external view returns (bytes32) {
        return revokedCommitment[y];
    }

    function revokedCount() external view returns (uint256) {
        return revokedLog.length;
    }

    function revokedAt(uint256 index) external view returns (bytes32) {
        if (index >= revokedLog.length) revert IndexOutOfRange(index);
        return revokedLog[index];
    }

    // Lapozható olvasás a holderek receipt-frissítéséhez.
    function getRevokedLog(uint256 start, uint256 count) external view returns (bytes32[] memory out) {
        if (start > revokedLog.length) revert IndexOutOfRange(start);
        uint256 end = start + count > revokedLog.length ? revokedLog.length : start + count;
        out = new bytes32[](end - start);
        for (uint256 i = start; i < end; i++) out[i - start] = revokedLog[i];
    }

    function getGroup(bytes32 groupId) external view returns (address creator, uint256 createdAt, bytes32[] memory members) {
        Group storage g = groups[groupId];
        if (g.createdAt == 0) revert UnknownGroup(groupId);
        return (g.creator, g.createdAt, g.members);
    }

    // A tagok rendezettek, ezért bináris kereséssel.
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
    function _valuesHash() private view returns (bytes32) {
        return keccak256(abi.encode(A, Rtilde, I));
    }

    function _expect(bytes32 commitment, Issuance storage iss, Status expected) private view {
        if (iss.status != expected) revert WrongStatus(commitment, expected, iss.status);
    }

    function _checkG1(bytes calldata p) private pure {
        if (p.length != G1_LEN) revert BadG1Length(p.length);
    }

    function _checkG2(bytes calldata p) private pure {
        if (p.length != G2_LEN) revert BadG2Length(p.length);
    }

    function _requireIssuer(bytes32 credDefId) private view {
        if (!credDefRegistry.exists(credDefId)) revert UnknownCredDef(credDefId);
        if (didRegistry.identityOwner(credDefRegistry.issuerOf(credDefId)) != msg.sender) {
            revert NotIssuer(credDefId, msg.sender);
        }
    }

    function _checkRequested(bytes32 y, bytes32 salt) private view returns (bytes32 c) {
        if (y == bytes32(0)) revert EmptyRevocationId();
        c = commitmentOf(y, salt);
        _expect(c, issuances[c], Status.Requested);
        if (revokedCommitment[y] != bytes32(0)) revert AlreadyRevoked(y);   // ugyanaz az y egy másik commitment alatt
    }

    function _applyRevoke(
        bytes32 y,
        bytes32 c,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR
    ) private {
        _checkG1(newA);
        _checkG2(newRtilde);
        _checkG1(newWIR);

        A = newA;
        Rtilde = newRtilde;
        WIR = newWIR;
        version += 1;
        valuesHashes[version] = _valuesHash();

        Issuance storage iss = issuances[c];
        iss.status = Status.Revoked;
        iss.revokedAt = version;
        revokedCommitment[y] = c;
        revokedLog.push(y);

        emit Revoked(version, y, iss.credDefId, c, newA, newRtilde, newWIR, iss.guardDigest);
    }

    function _checkGroupFresh(bytes32 groupId, uint64 expectedGroupVersion) private view {
        uint64 gv = groupVersion(groupId);
        if (gv != expectedGroupVersion) revert StaleGroupVersion(groupId, expectedGroupVersion, gv);
    }

    function _checkGroupFresh(bytes32 groupId, uint64 expectedGroupVersion) private view {
        uint64 gv = groupVersion(groupId);
        if (gv != expectedGroupVersion) revert StaleGroupVersion(groupId, expectedGroupVersion, gv);
    }

    function _checkRequested(bytes32 y, bytes32 salt) private view returns (bytes32 c) {
        if (y == bytes32(0)) revert EmptyRevocationId();
        c = commitmentOf(y, salt);
        _expect(c, issuances[c], Status.Requested);
        if (revokedCommitment[y] != bytes32(0)) revert AlreadyRevoked(y);   // ugyanaz az y egy másik commitment alatt
    }
}