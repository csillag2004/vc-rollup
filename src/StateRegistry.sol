// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CredDefRegistry, IEthereumDIDRegistry} from "./CredDefRegistry.sol";
import {PolicyRegistry} from "./PolicyRegistry.sol";
import {BLS} from "./lib/BLS.sol";

/// Három akkumulátoros állapotregiszter (A, R̃, I) CredDef-partíciónként.
/// Verify on write: minden frissítést a contract EIP-2537 pairinggel és a tárolóval ellenőriz.
/// A guardolt frissítésnél a policy nyilvános részét a contract kiértékeli, a bemutatott részre
/// pedig a contract által számolt osztály szerinti compare-and-swap fut.
contract StateRegistry {

    struct Registry {
        bytes32 credDefId;
        bytes32 label;
        bytes A;        // aktív oldal, G1: V0^(1/P_Rev(α)) (static add)
        bytes Rtilde;   // visszavont halmaz, G2: g̃^(P_Rev(α))
        bytes I;        // kiadott halmaz, G1: g^(P_Iss(α))
        bytes V0;       // A kezdőértéke, G1
        bytes Qtilde;   // akkumulátor kulcs, G2: g̃^α
        bytes Q;        // akkumulátor kulcs, G1: g^α
        bytes WIR;      // R̃ ⊆ I tanú, G1: g^(P_Iss/P_Rev(α))
        uint64 version;
        bytes32 g1SrsHash;
        bytes32 g2SrsHash;
        uint32 srsDegree;
        uint256 createdAt;
    }

    struct Group {
        bytes32 registryId;
        address creator;
        bytes32[] members;
        uint256 createdAt;
    }

    /// guard: melyik policy alapján, a kötések szerinti várt verziók, és a bizonyítás hash-e
    struct Guard {
        bytes32 policyId;
        uint64[] expectedVersions;
        bytes32 proofHash;
    }

    CredDefRegistry public immutable credDefRegistry;
    IEthereumDIDRegistry public immutable didRegistry;
    PolicyRegistry public immutable policyRegistry;

    mapping(bytes32 registryId => Registry) private registries;
    mapping(bytes32 credDefId => bytes32[]) private registriesOfCredDef;
    mapping(bytes32 registryId => mapping(uint64 version => bytes32)) private valuesHashes;      // keccak(A, R̃, I)
    mapping(bytes32 registryId => mapping(bytes32 y => uint64)) private revokedAtVersion;        // 0 = nincs visszavonva
    mapping(bytes32 registryId => bytes32[]) private revokedLog;                                  // append-only
    mapping(bytes32 registryId => mapping(bytes32 y => uint64)) private issuedAtVersion;         // 0 = nincs kiadva
    mapping(bytes32 registryId => bytes32[]) private issuedLog;                                   // append-only
    mapping(bytes32 groupId => Group) private groups;

    event RegistryCreated(bytes32 indexed registryId, bytes32 indexed credDefId, bytes32 label, bytes V0, bytes Qtilde, bytes Q);
    event SrsPublished(bytes32 indexed registryId, uint32 degree, bytes[] g1Powers, bytes[] g2Powers);
    // guardDigest = 0 a nem őrzött frissítésnél; egyébként keccak256(abi.encode(policyId, proofHash))
    event Issued(bytes32 indexed registryId, uint64 indexed version, bytes32 indexed y, bytes newI, bytes newWIR, bytes32 guardDigest);
    event Revoked(bytes32 indexed registryId, uint64 indexed version, bytes32 indexed y, bytes newA, bytes newRtilde, bytes newWIR, bytes32 guardDigest);
    event GroupCreated(bytes32 indexed groupId, bytes32 indexed registryId, address indexed creator, bytes32 label, bytes32[] members);

    error ZeroAddress();
    error UnknownCredDef(bytes32 credDefId);
    error UnknownRegistry(bytes32 registryId);
    error RegistryExists(bytes32 registryId);
    error NotIssuer(bytes32 credDefId, address caller);
    error EmptyRevocationId();
    error RevocationIdOutOfField(bytes32 y);
    error AlreadyRevoked(bytes32 y);
    error AlreadyIssued(bytes32 y);
    error NotIssued(bytes32 y);
    error MemberNotIssued(bytes32 y);
    error KeyMismatch();
    error InvalidPoint();
    error StepCheckFailed();
    error ConsistencyCheckFailed();
    error SubsetCheckFailed();
    error StaleVersion(uint256 index, uint64 expected, uint64 current);
    error GuardFalse(bytes32 policyId);
    error PolicyRequired(bytes32 policyId);
    error WrongPolicy(bytes32 expected, bytes32 given);
    error GuardLengthMismatch(uint256 bindings, uint256 versions);
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
    error SrsStructureInvalid();

    constructor(address _credDefRegistry, address _policyRegistry) {
        if (_credDefRegistry == address(0) || _policyRegistry == address(0)) revert ZeroAddress();
        credDefRegistry = CredDefRegistry(_credDefRegistry);
        // ugyanazt a DID registryt használjuk, mint a CredDefRegistry, így nem csúszhat szét a kettő
        didRegistry = CredDefRegistry(_credDefRegistry).didRegistry();
        policyRegistry = PolicyRegistry(_policyRegistry);
    }

    modifier onlyIssuer(bytes32 registryId) {
        _requireIssuer(_credDefOf(registryId));
        _;
    }

    modifier whenInitialized(bytes32 registryId) {
        if (registries[registryId].g1SrsHash == bytes32(0)) revert SrsNotPublished();
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

        BLS.checkG1(V0);
        BLS.checkG2(Qtilde);
        BLS.checkG1(Q);
        if (BLS.isZero(V0) || BLS.isZero(Q)) revert InvalidPoint();
        // a két kulcs ugyanaz az α: e(Q, g̃) = e(g, Q̃); a pairing a részcsoport-tagságot is ellenőrzi
        if (!BLS.pairingEq(Q, BLS.g2(), BLS.g1(), Qtilde)) revert KeyMismatch();
        BLS.g1Mul(V0, 1); // V0 a G1 részcsoportban van (különben az MSM revertál)

        r.credDefId = credDefId;
        r.label = label;
        r.V0 = V0;
        r.Qtilde = Qtilde;
        r.Q = Q;
        r.A = V0;
        r.Rtilde = BLS.g2();
        r.I = BLS.g1();
        r.WIR = BLS.g1();
        r.createdAt = block.timestamp;
        valuesHashes[registryId][0] = _valuesHash(r);
        registriesOfCredDef[credDefId].push(registryId);

        emit RegistryCreated(registryId, credDefId, label, V0, Qtilde, Q);
    }

    /// SRS: g^(α^i) és g̃^(α^i), i = 0..n. Szerkezetét két kötegelt pairing ellenőrzi:
    /// e(Σρ_i·g1[i+1], g̃) = e(Σρ_i·g1[i], Q̃) és e(Σρ_i·g1[i], g̃) = e(g, Σρ_i·g2[i]).
    function publishSrs(bytes32 registryId, bytes[] calldata g1Powers, bytes[] calldata g2Powers)
        external onlyIssuer(registryId)
    {
        Registry storage r = registries[registryId];
        if (r.g1SrsHash != bytes32(0)) revert SrsAlreadyPublished();
        uint256 len = g2Powers.length;
        if (len < 2 || g1Powers.length != len) revert BadSrsLength(g1Powers.length, len);
        for (uint256 i = 0; i < len; i++) {
            BLS.checkG1(g1Powers[i]);
            BLS.checkG2(g2Powers[i]);
        }
        if (keccak256(g1Powers[0]) != keccak256(BLS.g1())) revert SrsMismatch(0);
        if (keccak256(g2Powers[0]) != keccak256(BLS.g2())) revert SrsMismatch(0);
        if (keccak256(g2Powers[1]) != keccak256(r.Qtilde)) revert SrsMismatch(1);
        if (keccak256(g1Powers[1]) != keccak256(r.Q)) revert SrsMismatch(1);

        bytes32 g1Hash = keccak256(abi.encode(g1Powers));
        bytes32 g2Hash = keccak256(abi.encode(g2Powers));
        _checkSrsStructure(g1Powers, g2Powers, r.Qtilde, keccak256(abi.encode(g1Hash, g2Hash)));

        r.g1SrsHash = g1Hash;
        r.g2SrsHash = g2Hash;
        r.srsDegree = uint32(len - 1);
        emit SrsPublished(registryId, r.srsDegree, g1Powers, g2Powers);
    }


    ///KIADÁS
    function issueUpdate(bytes32 registryId, bytes32 y, bytes calldata newI, bytes calldata newWIR)
        external onlyIssuer(registryId) whenInitialized(registryId)
    {
        bytes32 credDefId = registries[registryId].credDefId;
        bytes32 bound = policyRegistry.boundPolicy(credDefId, PolicyRegistry.Action.Issue);
        if (bound != bytes32(0)) revert PolicyRequired(bound);
        _applyIssue(registryId, y, newI, newWIR, bytes32(0));
    }

    function guardedIssueUpdate(
        bytes32 registryId,
        bytes32 y,
        bytes calldata newI,
        bytes calldata newWIR,
        Guard calldata guard
    ) external onlyIssuer(registryId) whenInitialized(registryId) {
        bytes32 digest = _checkGuard(registries[registryId].credDefId, PolicyRegistry.Action.Issue, guard);
        _applyIssue(registryId, y, newI, newWIR, digest);
    }


    ///VISSZAVONÁS
    function revoke(
        bytes32 registryId,
        bytes32 y,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR
    ) external onlyIssuer(registryId) {
        bytes32 credDefId = registries[registryId].credDefId;
        bytes32 bound = policyRegistry.boundPolicy(credDefId, PolicyRegistry.Action.Revoke);
        if (bound != bytes32(0)) revert PolicyRequired(bound);
        _applyRevoke(registryId, y, newA, newRtilde, newWIR, bytes32(0));
    }

    function guardedRevoke(
        bytes32 registryId,
        bytes32 y,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR,
        Guard calldata guard
    ) external onlyIssuer(registryId) {
        bytes32 digest = _checkGuard(registries[registryId].credDefId, PolicyRegistry.Action.Revoke, guard);
        _applyRevoke(registryId, y, newA, newRtilde, newWIR, digest);
    }


    ///CSOPORTOK
    /// Csak kiadott ID-k, a tároló szerint; ez az α birtokosát is köti. Bárki létrehozhat csoportot.
    /// A méretkorlát az SRS foka, mert az off-chain aggregált tanúhoz [P_S]_2 kell.
    function createGroup(bytes32 registryId, bytes32 label, bytes32[] calldata members)
        external whenInitialized(registryId) returns (bytes32 groupId)
    {
        Registry storage r = registries[registryId];
        uint32 degree = r.srsDegree;
        if (members.length == 0) revert EmptyGroup();
        if (members.length > degree) revert GroupTooLarge(members.length, degree);
        if (members[0] == bytes32(0)) revert EmptyRevocationId();
        mapping(bytes32 => uint64) storage issued = issuedAtVersion[registryId];
        for (uint256 i = 0; i < members.length; i++) {
            if (uint256(members[i]) >= BLS.R) revert RevocationIdOutOfField(members[i]);
            if (i > 0 && members[i] <= members[i - 1]) revert MembersNotSorted(i);
            if (issued[members[i]] == 0) revert MemberNotIssued(members[i]);
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

    /// a csoport visszavont tagjainak száma; mivel a tagok kiadottak, csak visszavonás érintheti őket
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

    /// Történeti érték hitelesítése: keccak256(abi.encode(A, Rtilde, I)); jövőbeli versionre 0.
    function valuesHashAt(bytes32 registryId, uint64 version) external view returns (bytes32) {
        return valuesHashes[registryId][version];
    }

    function isRevoked(bytes32 registryId, bytes32 y) external view returns (bool) {
        return revokedAtVersion[registryId][y] != 0;
    }

    /// Melyik versionnél került y R̃-ba (0 = nincs visszavonva). A free receipt a közvetlenül előtte lévő R̃.
    function revokedAt(bytes32 registryId, bytes32 y) external view returns (uint64) {
        return revokedAtVersion[registryId][y];
    }

    function revokedCount(bytes32 registryId) public view returns (uint256) {
        return revokedLog[registryId].length;
    }

    function isIssued(bytes32 registryId, bytes32 y) external view returns (bool) {
        return issuedAtVersion[registryId][y] != 0;
    }

    /// Melyik versionnél került y I-be (0 = nincs kiadva).
    function issuedAt(bytes32 registryId, bytes32 y) external view returns (uint64) {
        return issuedAtVersion[registryId][y];
    }

    function issuedCount(bytes32 registryId) public view returns (uint256) {
        return issuedLog[registryId].length;
    }

    function getIssuedLog(bytes32 registryId, uint256 start, uint256 count) external view returns (bytes32[] memory out) {
        bytes32[] storage log = issuedLog[registryId];
        if (start > log.length) revert IndexOutOfRange(start);
        uint256 end = start + count > log.length ? log.length : start + count;
        out = new bytes32[](end - start);
        for (uint256 i = start; i < end; i++) out[i - start] = log[i];
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


    ///SEGÉDFÜGGVÉNYEK
    function _valuesHash(Registry storage r) private view returns (bytes32) {
        return keccak256(abi.encode(r.A, r.Rtilde, r.I));
    }

    function _requireIssuer(bytes32 credDefId) private view {
        if (!credDefRegistry.exists(credDefId)) revert UnknownCredDef(credDefId);
        if (didRegistry.identityOwner(credDefRegistry.issuerOf(credDefId)) != msg.sender) {
            revert NotIssuer(credDefId, msg.sender);
        }
    }

    function _credDefOf(bytes32 registryId) private view returns (bytes32) {
        Registry storage r = registries[registryId];
        if (r.createdAt == 0) revert UnknownRegistry(registryId);
        return r.credDefId;
    }

    /// Kiadás: I' = I^(y+α), W_IR' = W_IR^(y+α); y nyilvános.
    /// Tároló: y még nincs kiadva. I' ≠ 1, különben y = −α. Lépés: e(I', g̃) = e(I, g̃^y·Q̃); részhalmaz: e(W_IR', R̃) = e(I', g̃).
    /// A lépés-ellenőrzés I'-t egyértelműen rögzíti I-ből és y-ból, így α ismerete sem enged más értéket.
    function _applyIssue(
        bytes32 registryId,
        bytes32 y,
        bytes calldata newI,
        bytes calldata newWIR,
        bytes32 guardDigest
    ) private {
        if (y == bytes32(0)) revert EmptyRevocationId();
        if (uint256(y) >= BLS.R) revert RevocationIdOutOfField(y);
        if (issuedAtVersion[registryId][y] != 0) revert AlreadyIssued(y);
        BLS.checkG1(newI);
        BLS.checkG1(newWIR);
        if (BLS.isZero(newI)) revert InvalidPoint();

        Registry storage r = registries[registryId];
        if (!BLS.pairingEq(newI, BLS.g2(), r.I, _g2yQ(r, y))) revert StepCheckFailed();
        if (!BLS.pairingEq(newWIR, r.Rtilde, newI, BLS.g2())) revert SubsetCheckFailed();

        r.I = newI;
        r.WIR = newWIR;
        r.version += 1;                                  // a kiadás is új version
        valuesHashes[registryId][r.version] = _valuesHash(r);

        issuedAtVersion[registryId][y] = r.version;
        issuedLog[registryId].push(y);

        emit Issued(registryId, r.version, y, newI, newWIR, guardDigest);
    }

    /// Visszavonás: A' = A^(1/(y+α)), R̃' = R̃^(y+α), W_IR' = W_IR^(1/(y+α)).
    /// Lépés: e(A', g̃^y·Q̃) = e(A, g̃); konzisztencia: e(A', R̃') = e(V0, g̃); részhalmaz: e(W_IR', R̃') = e(I, g̃).
    /// A lépés-ellenőrzés egyben az értékek frissességét is garantálja: A' csak az aktuális A-ból léphet.
    /// Tároló: y kiadott és még nincs visszavonva. Kiadott y-ra α + y ≠ 0, ezért A' és R̃' nem lehet 1.
    function _applyRevoke(
        bytes32 registryId,
        bytes32 y,
        bytes calldata newA,
        bytes calldata newRtilde,
        bytes calldata newWIR,
        bytes32 guardDigest
    ) private {
        if (y == bytes32(0)) revert EmptyRevocationId();
        if (uint256(y) >= BLS.R) revert RevocationIdOutOfField(y);
        if (issuedAtVersion[registryId][y] == 0) revert NotIssued(y);
        if (revokedAtVersion[registryId][y] != 0) revert AlreadyRevoked(y);
        BLS.checkG1(newA);
        BLS.checkG2(newRtilde);
        BLS.checkG1(newWIR);

        Registry storage r = registries[registryId];
        if (!BLS.pairingEq(newA, _g2yQ(r, y), r.A, BLS.g2())) revert StepCheckFailed();
        if (!BLS.pairingEq(newA, newRtilde, r.V0, BLS.g2())) revert ConsistencyCheckFailed();
        if (!BLS.pairingEq(newWIR, newRtilde, r.I, BLS.g2())) revert SubsetCheckFailed();

        r.A = newA;
        r.Rtilde = newRtilde;
        r.WIR = newWIR;
        r.version += 1;
        valuesHashes[registryId][r.version] = _valuesHash(r);

        revokedAtVersion[registryId][y] = r.version;
        revokedLog[registryId].push(y);

        emit Revoked(registryId, r.version, y, newA, newRtilde, newWIR, guardDigest);
    }

    /// Guard: ha a CredDef-hez az adott művelethez policy van kötve, csak az fogadható el.
    /// (1) A bemutatott rész CAS-a: ha nem stable (és nem állapotfüggetlen), minden Presented klóz
    ///     registryjének globális versionje egyezzen a várttal.
    /// (2) A nyilvános rész a frissítés előtti állapotban igaz legyen; csoportra és Issued-ra számlálókkal.
    function _checkGuard(bytes32 credDefId, PolicyRegistry.Action action, Guard calldata guard)
        private view returns (bytes32)
    {
        bytes32 bound = policyRegistry.boundPolicy(credDefId, action);
        if (bound != bytes32(0) && bound != guard.policyId) revert WrongPolicy(bound, guard.policyId);
        (
            PolicyRegistry.Class cls,
            PolicyRegistry.BindingKind[] memory kinds,
            bytes32[] memory targets,
            PolicyRegistry.Op[] memory presentedOps,
            PolicyRegistry.Op[] memory publicOps
        ) = policyRegistry.guardSpec(guard.policyId);
        if (guard.expectedVersions.length != targets.length) {
            revert GuardLengthMismatch(targets.length, guard.expectedVersions.length);
        }
        if (cls == PolicyRegistry.Class.CoStable || cls == PolicyRegistry.Class.Volatile) {
            for (uint256 i = 0; i < presentedOps.length; i++) {
                if (presentedOps[i].kind != PolicyRegistry.OpKind.Clause) continue;
                uint8 b = presentedOps[i].binding;
                if (kinds[b] != PolicyRegistry.BindingKind.Registry) continue;
                bytes32 regId = targets[b];
                if (registries[regId].createdAt == 0) revert UnknownRegistry(regId);
                uint64 current = registries[regId].version;
                if (current != guard.expectedVersions[b]) revert StaleVersion(b, guard.expectedVersions[b], current);
            }
        }
        if (!_evalPublic(publicOps, targets)) revert GuardFalse(guard.policyId);
        return keccak256(abi.encode(guard.policyId, guard.proofHash));
    }

    /// Postfix kiértékelés. Klóz: n = a domain mérete, r = benne a visszavontak száma;
    /// Up törzsre m = r, Down törzsre m = n − r; ∀: m = n, ∃: m ≥ 1, atleast k: m ≥ k, atmost k: m ≤ k.
    function _evalPublic(PolicyRegistry.Op[] memory ops, bytes32[] memory targets) private view returns (bool) {
        if (ops.length == 0) return true;
        bool[] memory stack = new bool[](ops.length);
        uint256 depth = 0;
        for (uint256 i = 0; i < ops.length; i++) {
            PolicyRegistry.Op memory op = ops[i];
            if (op.kind == PolicyRegistry.OpKind.Clause) {
                stack[depth++] = _evalClause(op, targets[op.binding]);
            } else {
                bool a = stack[depth - 2];
                bool b = stack[depth - 1];
                stack[depth - 2] = op.kind == PolicyRegistry.OpKind.And ? a && b : a || b;
                depth--;
            }
        }
        return stack[0];
    }

    function _evalClause(PolicyRegistry.Op memory op, bytes32 target) private view returns (bool) {
        uint256 n;
        uint256 r;
        if (op.domain == PolicyRegistry.Domain.Group) {
            n = _group(target).members.length;
            r = groupVersion(target);
        } else {
            if (registries[target].createdAt == 0) revert UnknownRegistry(target);
            n = issuedCount(target);
            r = revokedCount(target);
        }
        uint256 m = op.body == PolicyRegistry.Polarity.Up ? r : n - r;
        if (op.quant == PolicyRegistry.Quant.All) return m == n;
        if (op.quant == PolicyRegistry.Quant.Exists) return m >= 1;
        if (op.quant == PolicyRegistry.Quant.AtLeast) return m >= op.k;
        return m <= op.k;
    }

    function _group(bytes32 groupId) private view returns (Group storage g) {
        g = groups[groupId];
        if (g.createdAt == 0) revert UnknownGroup(groupId);
    }

    /// g̃^y · Q̃
    function _g2yQ(Registry storage r, bytes32 y) private view returns (bytes memory) {
        bytes[] memory ps = new bytes[](2);
        uint256[] memory ss = new uint256[](2);
        ps[0] = BLS.g2(); ss[0] = uint256(y);
        ps[1] = r.Qtilde; ss[1] = 1;
        return BLS.g2Msm(ps, ss);
    }

    function _checkSrsStructure(bytes[] calldata g1p, bytes[] calldata g2p, bytes memory Qtilde, bytes32 seed)
        private view
    {
        uint256 n = g1p.length; // n = fok + 1
        bytes[] memory lowG1 = new bytes[](n - 1);
        bytes[] memory highG1 = new bytes[](n - 1);
        uint256[] memory rhoShift = new uint256[](n - 1);
        bytes[] memory allG1 = new bytes[](n);
        bytes[] memory allG2 = new bytes[](n);
        uint256[] memory rho = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            rho[i] = uint256(keccak256(abi.encode(seed, i))) % BLS.R;
            allG1[i] = g1p[i];
            allG2[i] = g2p[i];
            if (i + 1 < n) {
                lowG1[i] = g1p[i];
                highG1[i] = g1p[i + 1];
                rhoShift[i] = rho[i];
            }
        }
        // egymást követő hatványok: Σρ_i·g1[i+1] = α·Σρ_i·g1[i]
        if (!BLS.pairingEq(BLS.g1Msm(highG1, rhoShift), BLS.g2(), BLS.g1Msm(lowG1, rhoShift), Qtilde)) {
            revert SrsStructureInvalid();
        }
        // a G2 hatványok ugyanazok: e(Σρ_i·g1[i], g̃) = e(g, Σρ_i·g2[i])
        if (!BLS.pairingEq(BLS.g1Msm(allG1, rho), BLS.g2(), BLS.g1(), BLS.g2Msm(allG2, rho))) {
            revert SrsStructureInvalid();
        }
    }
}
