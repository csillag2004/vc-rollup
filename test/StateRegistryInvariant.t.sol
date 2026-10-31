// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EthereumDIDRegistry} from "ethr-did-registry/EthereumDIDRegistry.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {CredDefRegistry} from "../src/CredDefRegistry.sol";
import {StateRegistry} from "../src/StateRegistry.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {BLS} from "../src/lib/BLS.sol";

// A Lean-modell (verification/lean a lean-lifecycle-spec ágon) halmaz-szintű ellenőrzéseket bizonyít. Ezek a tesztek
// ugyanazokat a tulajdonságokat a contracton nézik, egy α-t ismerő kibocsátóval szemben. A megfeleltetés:
// design/LEAN-TESTS.md.

uint256 constant ALPHA = 0x1234567890abcdef1234567890abcdef;
uint256 constant V0_DLOG = 0x5eed;
uint32 constant SRS_DEGREE = 4;
uint256 constant N = 10; // az ID-univerzum: 1..N; az S csoport {1, 2, 3}

/// y + α az Fr-ben
function factor(uint256 y) pure returns (uint256) {
    return addmod(y, ALPHA, BLS.R);
}

/// ∏ (y + α) egy ID-listán: a lista halmazát kódoló kitevő
function prodOf(uint256[] memory ys) pure returns (uint256 p) {
    p = 1;
    for (uint256 i = 0; i < ys.length; i++) {
        p = mulmod(p, factor(ys[i]), BLS.R);
    }
}

/// ∏ (y + α) egy tetszőleges halmazon: a maszk i. bitje az i + 1 ID
function prodOfMask(uint256 mask) pure returns (uint256 p) {
    p = 1;
    for (uint256 i = 0; i < N; i++) {
        if ((mask >> i) & 1 == 1) p = mulmod(p, factor(i + 1), BLS.R);
    }
}

function g1Of(uint256 s) view returns (bytes memory) {
    return BLS.g1Mul(BLS.g1(), s);
}

function g2Of(uint256 s) view returns (bytes memory) {
    return BLS.g2Mul(BLS.g2(), s);
}

/// A kibocsátó, aki ismeri α-t. Véletlen sorrendben ad ki és von vissza (friss, már kiadott, kiadatlan és már
/// visszavont ID-ket), helyes, elavult és α-val tetszőleges halmazokra számolt értékekkel, csoportokat hoz létre, és
/// az S csoport tagjait csak a foglalás guardjával vonja vissza: ez a Lean ReservationPolicy S. A policy nincs kötve,
/// mert a kötés a CredDef minden visszavonására vonatkozna, a Lean-feltétel pedig csak S tagjaira.
/// Minden hívás előtt a szellem-állapotból kiszámolja, mit kell a contractnak tennie (elfogadás, vagy melyik hiba), és
/// eltérésnél revertál; a teszt fail-on-revert módban fut. Ez hívásonként a checks_exact és a honest_update.
contract IssuerHandler is Test {
    enum Status {
        Unissued,
        Active,
        Revoked
    }

    StateRegistry internal immutable registry;
    PolicyRegistry internal immutable policies;
    bytes32 internal immutable credDefId;
    bytes32 internal immutable regId;
    bytes32 internal immutable otherId;
    address internal immutable issuer;
    address internal immutable stranger;

    // szellem-állapot: a Lean VDR naplója és a version-önkénti állapot hash-e
    uint256[] internal issuedLog;
    uint256[] internal revokedLog;
    mapping(uint256 y => uint64) internal issuedAt; // 0 = nincs kiadva
    mapping(uint256 y => uint64) internal revokedAt; // 0 = nincs visszavonva
    bytes32[] internal hashAt; // hashAt[v] = keccak256(abi.encode(A, R̃, I)) a v. versionnél

    bytes32 public groupS;
    bytes32 public reservation;
    uint256[] internal sMembers;
    bytes32[] internal groupIds;
    mapping(bytes32 groupId => uint256[]) internal groupMembers;
    uint256 internal groupLabel;

    // a másik registry (S10): csak kiadás
    uint256[] internal otherIssued;
    mapping(uint256 y => bool) internal otherIsIssued;

    // egy korábbi állapot kitevői (stale_values); kezdetben a 0. version
    uint256 internal staleIss = 1;
    uint256 internal staleRev = 1;

    constructor(
        StateRegistry registry_,
        PolicyRegistry policies_,
        bytes32 credDefId_,
        bytes32 regId_,
        bytes32 otherId_,
        address issuer_
    ) {
        registry = registry_;
        policies = policies_;
        credDefId = credDefId_;
        regId = regId_;
        otherId = otherId_;
        issuer = issuer_;
        stranger = makeAddr("stranger");
    }

    /// a kezdőállapot: 1, 2 és 3 kiadva, S = {1, 2, 3}, a foglalás policyja (∀x∈S. NotRevoked(x)) regisztrálva
    function bootstrap() external {
        hashAt.push(keccak256(abi.encode(g1Of(V0_DLOG), BLS.g2(), BLS.g1())));
        bytes32[] memory m = new bytes32[](3);
        for (uint256 y = 1; y <= 3; y++) {
            (bytes memory i, bytes memory w) = _issueValues(prodOf(issuedLog), prodOf(revokedLog), y);
            _submitIssue(y, i, w);
            sMembers.push(y);
            m[y - 1] = bytes32(y);
        }
        vm.prank(issuer);
        groupS = registry.createGroup(regId, "S", m);
        groupIds.push(groupS);
        groupMembers[groupS] = sMembers;

        PolicyRegistry.Binding[] memory b = new PolicyRegistry.Binding[](1);
        b[0] = PolicyRegistry.Binding({name: "S", kind: PolicyRegistry.BindingKind.Group, target: groupS});
        PolicyRegistry.Op[] memory pub = new PolicyRegistry.Op[](1);
        pub[0] = PolicyRegistry.Op({
            kind: PolicyRegistry.OpKind.Clause,
            quant: PolicyRegistry.Quant.All,
            k: 0,
            domain: PolicyRegistry.Domain.Group,
            binding: 0,
            body: PolicyRegistry.Polarity.Down
        });
        PolicyRegistry.Op[] memory none = new PolicyRegistry.Op[](0);
        vm.prank(issuer);
        reservation = policies.registerPolicy("forall x in S. NotRevoked(x)", b, none, pub);
    }

    // ------------------------------------------------------------ műveletek (a fuzzer ezeket hívja)

    /// friss ID kiadása helyes értékekkel; ha nincs kiadatlan, egy kiadottat próbál újra
    function issueFresh(uint256 seed) external {
        uint256 y = _pick(seed, Status.Unissued);
        (bytes memory i, bytes memory w) = _issueValues(prodOf(issuedLog), prodOf(revokedLog), y);
        _submitIssue(y, i, w);
    }

    /// kiadott (aktív vagy visszavont) ID újbóli kiadása az α-val számolt, minden pairingen átmenő értékekkel
    function issueDuplicate(uint256 seed, bool revoked) external {
        uint256 y = _pick(seed, revoked ? Status.Revoked : Status.Active);
        (bytes memory i, bytes memory w) = _issueValues(prodOf(issuedLog), prodOf(revokedLog), y);
        _submitIssue(y, i, w);
    }

    /// friss ID kiadása hamis értékekkel. forgeI: I' egy tetszőleges halmazra, hozzá illő W_IR'; különben helyes I',
    /// W_IR' tetszőleges két halmaz hányadosára
    function issueForged(uint256 seed, bool forgeI, uint256 m1, uint256 m2) external {
        uint256 y = _pick(seed, Status.Unissued);
        uint256 pRev = prodOf(revokedLog);
        (bytes memory i, bytes memory w) = _issueValues(prodOf(issuedLog), pRev, y);
        if (forgeI) {
            uint256 x = prodOfMask(m1);
            i = g1Of(x);
            w = g1Of(mulmod(x, BLS.frInv(pRev), BLS.R));
        } else {
            w = g1Of(mulmod(prodOfMask(m1), BLS.frInv(prodOfMask(m2)), BLS.R));
        }
        _submitIssue(y, i, w);
    }

    /// aktív ID visszavonása helyes értékekkel, lehetőleg S-en kívül
    function revokeActive(uint256 seed) external {
        uint256 y = _pickOutsideS(seed);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(prodOf(issuedLog), prodOf(revokedLog), y);
        _submitRevoke(y, a, r, w, _inS(y), 0);
    }

    /// kiadatlan ID visszavonása az α-val számolt, minden pairingen átmenő értékekkel (W_IR' is): a tároló utasítja el
    function revokeUnissued(uint256 seed) external {
        uint256 y = _pick(seed, Status.Unissued);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(prodOf(issuedLog), prodOf(revokedLog), y);
        _submitRevoke(y, a, r, w, _inS(y), 0);
    }

    /// visszavont ID újbóli visszavonása az α-val számolt, minden pairingen átmenő értékekkel
    function revokeRevoked(uint256 seed) external {
        uint256 y = _pick(seed, Status.Revoked);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(prodOf(issuedLog), prodOf(revokedLog), y);
        _submitRevoke(y, a, r, w, _inS(y), 0);
    }

    /// aktív ID (lehetőleg S-en kívül) visszavonása hamis értékekkel. mode 0: A' és R̃' egy tetszőleges X visszavont
    /// halmazra, hozzá illő W_IR'; 1: helyes A', R̃' és W_IR' X-re; 2: helyes A' és R̃', W_IR' tetszőleges két halmaz
    /// hányadosára
    function revokeForged(uint256 seed, uint8 mode, uint256 m1, uint256 m2) external {
        uint256 y = _pickOutsideS(seed);
        uint256 pIss = prodOf(issuedLog);
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(pIss, prodOf(revokedLog), y);
        mode %= 3;
        if (mode < 2) {
            uint256 x = prodOfMask(m1);
            uint256 inv = BLS.frInv(x);
            if (mode == 0) a = g1Of(mulmod(V0_DLOG, inv, BLS.R));
            r = g2Of(x);
            w = g1Of(mulmod(pIss, inv, BLS.R));
        } else {
            w = g1Of(mulmod(prodOfMask(m1), BLS.frInv(prodOfMask(m2)), BLS.R));
        }
        _submitRevoke(y, a, r, w, _inS(y), 0);
    }

    /// S egy tagjának foglalása a guarddal, tetszőleges bizonyítási versionnel
    function reserve(uint256 seed, uint64 provedAt) external {
        uint256 y = sMembers[seed % sMembers.length];
        (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(prodOf(issuedLog), prodOf(revokedLog), y);
        _submitRevoke(y, a, r, w, true, provedAt);
    }

    /// a jelenlegi állapot megjegyzése; a postStale ebből számol
    function remember() external {
        staleIss = prodOf(issuedLog);
        staleRev = prodOf(revokedLog);
    }

    /// stale_values: egy most engedélyezett frissítés a megjegyzett állapotból számolt értékekkel
    function postStale(uint256 seed, bool revocation) external {
        if (revocation) {
            uint256 y = _pickOutsideS(seed);
            (bytes memory a, bytes memory r, bytes memory w) = _revokeValues(staleIss, staleRev, y);
            _submitRevoke(y, a, r, w, _inS(y), 0);
        } else {
            uint256 y = _pick(seed, Status.Unissued);
            (bytes memory i, bytes memory w) = _issueValues(staleIss, staleRev, y);
            _submitIssue(y, i, w);
        }
    }

    /// csoport a maszk szerinti tagokkal (legfeljebb SRS_DEGREE); issuedOnly nélkül kiadatlan tag is lehet.
    /// Csoportot bárki létrehozhat, ezért néha egy idegen hozza létre.
    function createGroup(uint256 mask, bool issuedOnly, bool byStranger) external {
        uint256[] memory ids = new uint256[](SRS_DEGREE);
        uint256 n;
        for (uint256 i = 0; i < N && n < SRS_DEGREE; i++) {
            if ((mask >> i) & 1 == 0) continue;
            if (issuedOnly && issuedAt[i + 1] == 0) continue;
            ids[n++] = i + 1;
        }
        if (n == 0) ids[n++] = issuedOnly ? issuedLog[mask % issuedLog.length] : mask % N + 1;

        bytes32[] memory m = new bytes32[](n);
        uint256[] memory members = new uint256[](n);
        bytes memory expected;
        for (uint256 i = 0; i < n; i++) {
            m[i] = bytes32(ids[i]);
            members[i] = ids[i];
            if (expected.length == 0 && issuedAt[ids[i]] == 0) {
                expected = abi.encodeWithSelector(StateRegistry.MemberNotIssued.selector, m[i]);
            }
        }
        bytes32 label = bytes32(++groupLabel);
        vm.prank(byStranger ? stranger : issuer);
        try registry.createGroup(regId, label, m) returns (bytes32 g) {
            assertEq(expected, "", "createGroup: a contract elfogadta, amit a modell elutasit");
            groupIds.push(g);
            groupMembers[g] = members;
        } catch (bytes memory err) {
            assertEq(err, expected, "createGroup: mas dontes, mint a modelle");
        }
    }

    /// S10: kiadás a másik registrybe, ugyanabból az ID-univerzumból
    function issueOther(uint256 seed) external {
        uint256 y = seed % N + 1;
        for (uint256 k = 0; k < N && otherIsIssued[y]; k++) {
            y = y % N + 1;
        }
        bytes memory i = g1Of(mulmod(prodOf(otherIssued), factor(y), BLS.R));
        bytes memory expected =
            otherIsIssued[y] ? abi.encodeWithSelector(StateRegistry.AlreadyIssued.selector, bytes32(y)) : bytes("");
        vm.prank(issuer);
        try registry.issueUpdate(otherId, bytes32(y), i, i) {
            assertEq(expected, "", "issueOther: a contract elfogadta, amit a modell elutasit");
            otherIssued.push(y);
            otherIsIssued[y] = true;
        } catch (bytes memory err) {
            assertEq(err, expected, "issueOther: mas dontes, mint a modelle");
        }
    }

    /// S1: egy idegen helyes értékekkel sem írhat
    function strangerIssues(uint256 seed) external {
        address who = address(uint160(uint256(keccak256(abi.encode("stranger", seed)))));
        uint256 y = _pick(seed, Status.Unissued);
        (bytes memory i, bytes memory w) = _issueValues(prodOf(issuedLog), prodOf(revokedLog), y);
        vm.prank(who);
        try registry.issueUpdate(regId, bytes32(y), i, w) {
            assertTrue(false, "strangerIssues: a contract elfogadta egy idegen kiadasat");
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(StateRegistry.NotIssuer.selector, credDefId, who));
        }
    }

    // ------------------------------------------------------------ a szellem-állapot olvasása

    function issuedIds() external view returns (uint256[] memory) {
        return issuedLog;
    }

    function revokedIds() external view returns (uint256[] memory) {
        return revokedLog;
    }

    function versionsOf(uint256 y) external view returns (uint64 issuedVersion, uint64 revokedVersion) {
        return (issuedAt[y], revokedAt[y]);
    }

    function hashes() external view returns (bytes32[] memory) {
        return hashAt;
    }

    function groups() external view returns (bytes32[] memory) {
        return groupIds;
    }

    function membersOf(bytes32 groupId) external view returns (uint256[] memory) {
        return groupMembers[groupId];
    }

    function sIds() external view returns (uint256[] memory) {
        return sMembers;
    }

    function otherIds() external view returns (uint256[] memory) {
        return otherIssued;
    }

    /// a szellem-halmazokból számolt helyes értékek: A = V0^(1/P_Rev), R̃ = g̃^P_Rev, I = g^P_Iss, W_IR = g^(P_Iss/P_Rev)
    function honestValues() public view returns (bytes memory A, bytes memory Rt, bytes memory I, bytes memory W) {
        uint256 pIss = prodOf(issuedLog);
        uint256 pRev = prodOf(revokedLog);
        uint256 inv = BLS.frInv(pRev);
        A = g1Of(mulmod(V0_DLOG, inv, BLS.R));
        Rt = g2Of(pRev);
        I = g1Of(pIss);
        W = g1Of(mulmod(pIss, inv, BLS.R));
    }

    // ------------------------------------------------------------ a modell

    function _status(uint256 y) internal view returns (Status) {
        if (revokedAt[y] != 0) return Status.Revoked;
        if (issuedAt[y] != 0) return Status.Active;
        return Status.Unissued;
    }

    /// az első `want` állapotú ID a seed szerinti helytől; ha nincs ilyen, a seed szerinti ID
    function _pick(uint256 seed, Status want) internal view returns (uint256) {
        for (uint256 k = 0; k < N; k++) {
            uint256 y = (seed % N + k) % N + 1;
            if (_status(y) == want) return y;
        }
        return seed % N + 1;
    }

    /// aktív ID S-en kívül; ha nincs ilyen, bármely aktív (S tagja, a foglalás után GuardFalse)
    function _pickOutsideS(uint256 seed) internal view returns (uint256) {
        for (uint256 k = 0; k < N; k++) {
            uint256 y = (seed % N + k) % N + 1;
            if (_status(y) == Status.Active && !_inS(y)) return y;
        }
        return _pick(seed, Status.Active);
    }

    function _inS(uint256 y) internal view returns (bool) {
        for (uint256 i = 0; i < sMembers.length; i++) {
            if (sMembers[i] == y) return true;
        }
        return false;
    }

    /// a P_Iss, P_Rev kitevőjű állapotból y kiadásának értékei: I' = I^(y+α), W_IR' = W_IR^(y+α)
    function _issueValues(uint256 pIss, uint256 pRev, uint256 y)
        internal
        view
        returns (bytes memory i, bytes memory w)
    {
        uint256 next = mulmod(pIss, factor(y), BLS.R);
        i = g1Of(next);
        w = g1Of(mulmod(next, BLS.frInv(pRev), BLS.R));
    }

    /// a P_Iss, P_Rev kitevőjű állapotból y visszavonásának értékei: A' = A^(1/(y+α)), R̃' = R̃^(y+α), W_IR' = W_IR^(1/(y+α))
    function _revokeValues(uint256 pIss, uint256 pRev, uint256 y)
        internal
        view
        returns (bytes memory a, bytes memory r, bytes memory w)
    {
        uint256 next = mulmod(pRev, factor(y), BLS.R);
        uint256 inv = BLS.frInv(next);
        a = g1Of(mulmod(V0_DLOG, inv, BLS.R));
        r = g2Of(next);
        w = g1Of(mulmod(pIss, inv, BLS.R));
    }

    /// a contract várt válasza egy kiadásra: a tároló dönt, aztán a pairingek pontosan a helyes értékeket engedik át
    function _issueOutcome(uint256 y, bytes memory i, bytes memory w) internal view returns (bytes memory) {
        if (issuedAt[y] != 0) return abi.encodeWithSelector(StateRegistry.AlreadyIssued.selector, bytes32(y));
        (bytes memory hi, bytes memory hw) = _issueValues(prodOf(issuedLog), prodOf(revokedLog), y);
        if (keccak256(i) != keccak256(hi)) return abi.encodeWithSelector(StateRegistry.StepCheckFailed.selector);
        if (keccak256(w) != keccak256(hw)) return abi.encodeWithSelector(StateRegistry.SubsetCheckFailed.selector);
        return "";
    }

    /// a contract várt válasza egy visszavonásra: guard, tároló, majd lépés, konzisztencia és részhalmaz
    function _revokeOutcome(uint256 y, bytes memory a, bytes memory r, bytes memory w, bool guarded)
        internal
        view
        returns (bytes memory)
    {
        if (guarded && _revokedInS() > 0) {
            return abi.encodeWithSelector(StateRegistry.GuardFalse.selector, reservation);
        }
        if (issuedAt[y] == 0) return abi.encodeWithSelector(StateRegistry.NotIssued.selector, bytes32(y));
        if (revokedAt[y] != 0) return abi.encodeWithSelector(StateRegistry.AlreadyRevoked.selector, bytes32(y));
        (bytes memory ha, bytes memory hr, bytes memory hw) = _revokeValues(prodOf(issuedLog), prodOf(revokedLog), y);
        if (keccak256(a) != keccak256(ha)) return abi.encodeWithSelector(StateRegistry.StepCheckFailed.selector);
        if (keccak256(r) != keccak256(hr)) {
            return abi.encodeWithSelector(StateRegistry.ConsistencyCheckFailed.selector);
        }
        if (keccak256(w) != keccak256(hw)) return abi.encodeWithSelector(StateRegistry.SubsetCheckFailed.selector);
        return "";
    }

    function _revokedInS() internal view returns (uint256 n) {
        for (uint256 i = 0; i < sMembers.length; i++) {
            if (revokedAt[sMembers[i]] != 0) n++;
        }
    }

    function _submitIssue(uint256 y, bytes memory i, bytes memory w) internal {
        bytes memory expected = _issueOutcome(y, i, w);
        vm.prank(issuer);
        try registry.issueUpdate(regId, bytes32(y), i, w) {
            assertEq(expected, "", "issue: a contract elfogadta, amit a modell elutasit");
            issuedLog.push(y);
            issuedAt[y] = _newVersion();
        } catch (bytes memory err) {
            assertEq(err, expected, "issue: mas dontes, mint a modelle");
        }
    }

    function _submitRevoke(uint256 y, bytes memory a, bytes memory r, bytes memory w, bool guarded, uint64 provedAt)
        internal
    {
        bytes memory expected = _revokeOutcome(y, a, r, w, guarded);
        bool ok;
        bytes memory err;
        if (guarded) {
            StateRegistry.Guard memory g;
            g.policyId = reservation;
            g.expectedVersions = new uint64[](1);
            g.expectedVersions[0] = provedAt;
            g.proof = "proof";
            vm.prank(issuer);
            try registry.guardedRevoke(regId, bytes32(y), a, r, w, g) {
                ok = true;
            } catch (bytes memory e) {
                err = e;
            }
        } else {
            vm.prank(issuer);
            try registry.revoke(regId, bytes32(y), a, r, w) {
                ok = true;
            } catch (bytes memory e) {
                err = e;
            }
        }
        if (ok) {
            assertEq(expected, "", "revoke: a contract elfogadta, amit a modell elutasit");
            revokedLog.push(y);
            revokedAt[y] = _newVersion();
        } else {
            assertEq(err, expected, "revoke: mas dontes, mint a modelle");
        }
    }

    /// egy elfogadott frissítés új versiont nyit; a hash a frissítés utáni szellem-halmazokból
    function _newVersion() internal returns (uint64) {
        (bytes memory A, bytes memory Rt, bytes memory I,) = honestValues();
        hashAt.push(keccak256(abi.encode(A, Rt, I)));
        return uint64(hashAt.length - 1);
    }
}

/// Invariánsok a Lean-célok szerint. Kis futás- és mélységszám, mert minden hívás pairinget futtat.
/// forge-config: default.invariant.runs = 64
/// forge-config: default.invariant.depth = 32
/// forge-config: default.invariant.fail-on-revert = true
contract StateRegistryInvariantTest is Test {
    StateRegistry internal registry;
    IssuerHandler internal handler;
    bytes32 internal regId;
    bytes32 internal otherId;

    function setUp() public {
        EthereumDIDRegistry didRegistry = new EthereumDIDRegistry();
        SchemaRegistry schemaRegistry = new SchemaRegistry();
        CredDefRegistry credDefRegistry = new CredDefRegistry(address(didRegistry), address(schemaRegistry));
        PolicyRegistry policies = new PolicyRegistry(address(credDefRegistry));
        registry = new StateRegistry(address(credDefRegistry), address(policies));
        address alice = makeAddr("alice");

        string[] memory attributes = new string[](1);
        attributes[0] = "flat";
        bytes32 schemaId = schemaRegistry.registerSchema("Interest", "1.0", true, attributes);
        vm.prank(alice);
        bytes32 credDefId = credDefRegistry.registerCredDef(alice, schemaId, "default", keccak256("alice#bbs-key-1"));
        regId = _createRegistry(alice, credDefId, "flat-42");
        otherId = _createRegistry(alice, credDefId, "other");

        handler = new IssuerHandler(registry, policies, credDefId, regId, otherId, alice);
        handler.bootstrap();

        bytes4[] memory selectors = new bytes4[](13);
        selectors[0] = IssuerHandler.issueFresh.selector;
        selectors[1] = IssuerHandler.issueDuplicate.selector;
        selectors[2] = IssuerHandler.issueForged.selector;
        selectors[3] = IssuerHandler.revokeActive.selector;
        selectors[4] = IssuerHandler.revokeUnissued.selector;
        selectors[5] = IssuerHandler.revokeRevoked.selector;
        selectors[6] = IssuerHandler.revokeForged.selector;
        selectors[7] = IssuerHandler.reserve.selector;
        selectors[8] = IssuerHandler.remember.selector;
        selectors[9] = IssuerHandler.postStale.selector;
        selectors[10] = IssuerHandler.createGroup.selector;
        selectors[11] = IssuerHandler.issueOther.selector;
        selectors[12] = IssuerHandler.strangerIssues.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    function _createRegistry(address issuer, bytes32 credDefId, bytes32 label) internal returns (bytes32 id) {
        bytes memory v0 = g1Of(V0_DLOG);
        bytes memory qt = g2Of(ALPHA);
        bytes memory q = g1Of(ALPHA);
        bytes[] memory p1 = new bytes[](SRS_DEGREE + 1);
        bytes[] memory p2 = new bytes[](SRS_DEGREE + 1);
        uint256 a = 1;
        for (uint256 i = 0; i <= SRS_DEGREE; i++) {
            p1[i] = g1Of(a);
            p2[i] = g2Of(a);
            a = mulmod(a, ALPHA, BLS.R);
        }
        vm.prank(issuer);
        id = registry.createRegistry(credDefId, label, v0, qt, q);
        vm.prank(issuer);
        registry.publishSrs(id, p1, p2);
    }

    function _issuedLog(bytes32 id) internal view returns (bytes32[] memory) {
        return registry.getIssuedLog(id, 0, registry.issuedCount(id));
    }

    function _revokedLog(bytes32 id) internal view returns (bytes32[] memory) {
        return registry.getRevokedLog(id, 0, registry.revokedCount(id));
    }

    function _prod(bytes32[] memory ys) internal pure returns (uint256 p) {
        p = 1;
        for (uint256 i = 0; i < ys.length; i++) {
            p = mulmod(p, factor(uint256(ys[i])), BLS.R);
        }
    }

    /// S2 (s2_lifecycle): minden visszavont ID kiadott, a kiadása korábbi version, és a tárolt értékekre
    /// R̃ ⊆ I teljesül (e(W_IR, R̃) = e(I, g̃)). Kiadatlan vagy már visszavont ID visszavonását és kiadott ID
    /// újbóli kiadását a handler hívásonként várja el elutasítottnak, α-val számolt értékekkel is.
    function invariant_revokedAreIssued() public view {
        bytes32[] memory rev = _revokedLog(regId);
        for (uint256 i = 0; i < rev.length; i++) {
            assertTrue(registry.isIssued(regId, rev[i]), "S2: visszavont, de nem kiadott ID");
            assertLt(
                registry.issuedAt(regId, rev[i]), registry.revokedAt(regId, rev[i]), "S2: visszavonas a kiadas elott"
            );
        }
        (, bytes memory Rt, bytes memory I, bytes memory W,) = registry.getValues(regId);
        assertTrue(BLS.pairingEq(W, Rt, I, BLS.g2()), "S2: a tarolt ertekekre nem R reszhalmaza I-nek");
    }

    /// S3 (s3_monotone), S4 (s4_revocation_log): a kiadási és a visszavonási napló megegyezik a szellem-naplóval.
    /// A szellem-napló csak hozzáfűzéssel nő, így a contract naplója is. A version-ök a naplóban szigorúan nőnek,
    /// ezért nincs ismétlődés; a darabszámok a hosszak. A tárolt I és R̃ pontosan a naplók halmazát kódolja.
    function invariant_logsGrowByAppending() public view {
        bytes32[] memory iss = _issuedLog(regId);
        bytes32[] memory rev = _revokedLog(regId);
        uint256[] memory ghostIss = handler.issuedIds();
        uint256[] memory ghostRev = handler.revokedIds();
        assertEq(iss.length, ghostIss.length, "S3: a kiadasi naplo hossza");
        assertEq(rev.length, ghostRev.length, "S4: a visszavonasi naplo hossza");
        for (uint256 i = 0; i < iss.length; i++) {
            assertEq(uint256(iss[i]), ghostIss[i], "S3: a kiadasi naplo elter");
            if (i > 0) {
                assertGt(registry.issuedAt(regId, iss[i]), registry.issuedAt(regId, iss[i - 1]), "S3: ismetlodo kiadas");
            }
        }
        for (uint256 i = 0; i < rev.length; i++) {
            assertEq(uint256(rev[i]), ghostRev[i], "S4: a visszavonasi naplo elter");
            if (i > 0) {
                assertGt(
                    registry.revokedAt(regId, rev[i]),
                    registry.revokedAt(regId, rev[i - 1]),
                    "S4: ismetlodo visszavonas"
                );
            }
        }
        (, bytes memory Rt, bytes memory I,,) = registry.getValues(regId);
        assertEq(I, g1Of(_prod(iss)), "S3: I nem a kiadasi naplo halmaza");
        assertEq(Rt, g2Of(_prod(rev)), "S4: R nem a visszavonasi naplo halmaza");
    }

    /// S5 (s5_log_bound), S11 (s11_history), representation, checks_exact: a tárolt értékek a szellem-halmazokból
    /// számolt helyes értékek, és a jelenlegi version hash-e ezekre vonatkozik.
    function invariant_valuesAreHonest() public view {
        (bytes memory A, bytes memory Rt, bytes memory I, bytes memory W, uint64 v) = registry.getValues(regId);
        (bytes memory hA, bytes memory hR, bytes memory hI, bytes memory hW) = handler.honestValues();
        assertEq(A, hA, "S5: A");
        assertEq(Rt, hR, "S5: R");
        assertEq(I, hI, "S5: I");
        assertEq(W, hW, "S5: W_IR");
        assertEq(registry.valuesHashAt(regId, v), keccak256(abi.encode(A, Rt, I)), "S11: a jelenlegi version hash-e");
    }

    /// S6 (s6_exclusive), amennyire a tároló kifejezi: minden ID állapota (kiadatlan, aktív, visszavont) és a
    /// version-jei megegyeznek a szellem-állapottal, így egy visszavont ID sosem lesz újra aktív. A tárolt A és R̃
    /// ugyanazt a visszavont halmazt kódolja (e(A, R̃) = e(V0, g̃)), így A pontosan a visszavontakat hagyja ki.
    function invariant_statusIsExclusive() public view {
        for (uint256 y = 1; y <= N; y++) {
            (uint64 iAt, uint64 rAt) = handler.versionsOf(y);
            assertEq(registry.issuedAt(regId, bytes32(y)), iAt, "S6: kiadasi version");
            assertEq(registry.revokedAt(regId, bytes32(y)), rAt, "S6: visszavonasi version");
            assertEq(registry.isIssued(regId, bytes32(y)), iAt != 0, "S6: kiadott-e");
            assertEq(registry.isRevoked(regId, bytes32(y)), rAt != 0, "S6: visszavont-e");
        }
        (bytes memory A, bytes memory Rt,,,) = registry.getValues(regId);
        assertTrue(BLS.pairingEq(A, Rt, g1Of(V0_DLOG), BLS.g2()), "S6: A es R mas visszavont halmazt kodol");
    }

    /// S8(2) (s8_guarded_update): a foglalás policyja alatt S-nek legfeljebb egy tagja visszavont, bármilyen
    /// sorrendben és bizonyítási versionnel; a groupVersion ezt számolja.
    function invariant_atMostOneReservation() public view {
        uint256[] memory s = handler.sIds();
        uint256 revoked;
        for (uint256 i = 0; i < s.length; i++) {
            if (registry.isRevoked(regId, bytes32(s[i]))) revoked++;
        }
        assertLe(revoked, 1, "S8: S ket tagja visszavont");
        assertEq(registry.groupVersion(handler.groupS()), revoked, "S8: groupVersion(S)");
    }

    /// S11 (s11_history), global_version: a contract versionje a szellem-version, amely csak nő; minden version egy
    /// elfogadott frissítés. Minden korábbi version hash-e változatlan, a jövőbelié 0, és két különböző version
    /// állapota különböző.
    function invariant_versionsOnlyGrow() public view {
        (,,,, uint64 v) = registry.getValues(regId);
        bytes32[] memory h = handler.hashes();
        assertEq(v, h.length - 1, "S11: version");
        assertEq(v, registry.issuedCount(regId) + registry.revokedCount(regId), "S11: version = frissitesek szama");
        for (uint256 i = 0; i <= v; i++) {
            assertEq(registry.valuesHashAt(regId, uint64(i)), h[i], "S11: egy korabbi version allapota megvaltozott");
            for (uint256 j = 0; j < i; j++) {
                assertTrue(h[i] != h[j], "global_version: ket version azonos allapottal");
            }
        }
        assertEq(registry.valuesHashAt(regId, v + 1), bytes32(0), "S11: jovobeli version");
    }

    /// group_version: minden létrehozott csoport tagjai a szellem szerintiek és mind kiadottak (GUARDS.md 1. réteg;
    /// emiatt fordul meg itt a both_rejected), a groupVersion pedig a visszavont tagok száma. A Lean-féle "a tagok
    /// frissítéseinek száma" így csak a visszavonásokat számolja.
    function invariant_groupVersionsCountRevokedMembers() public view {
        bytes32[] memory gs = handler.groups();
        for (uint256 i = 0; i < gs.length; i++) {
            uint256[] memory m = handler.membersOf(gs[i]);
            (,,, bytes32[] memory stored) = registry.getGroup(gs[i]);
            assertEq(stored.length, m.length, "group_version: tagok szama");
            uint256 revoked;
            for (uint256 k = 0; k < m.length; k++) {
                assertEq(uint256(stored[k]), m[k], "group_version: tag");
                assertTrue(registry.isIssued(regId, stored[k]), "group_version: kiadatlan tag");
                (, uint64 rAt) = handler.versionsOf(m[k]);
                if (rAt != 0) revoked++;
            }
            assertEq(registry.groupVersion(gs[i]), revoked, "group_version: visszavont tagok szama");
        }
    }

    /// S10 (s10_partitions): a másik registry pontosan a neki szóló kiadásokat tartalmazza. Az első registry
    /// értékeit az invariant_valuesAreHonest a csak neki szóló szellem-naplóból számolja.
    function invariant_partitionsIndependent() public view {
        uint256[] memory ghost = handler.otherIds();
        bytes32[] memory iss = _issuedLog(otherId);
        assertEq(iss.length, ghost.length, "S10: a masik registry naploja");
        for (uint256 i = 0; i < iss.length; i++) {
            assertEq(uint256(iss[i]), ghost[i], "S10: a masik registry naploja");
        }
        assertEq(registry.revokedCount(otherId), 0, "S10: visszavonas a masik registryben");
        (bytes memory A, bytes memory Rt, bytes memory I, bytes memory W, uint64 v) = registry.getValues(otherId);
        bytes memory hI = g1Of(prodOf(ghost));
        assertEq(A, g1Of(V0_DLOG), "S10: A");
        assertEq(Rt, BLS.g2(), "S10: R");
        assertEq(I, hI, "S10: I");
        assertEq(W, hI, "S10: W_IR");
        assertEq(v, ghost.length, "S10: version");
    }
}
