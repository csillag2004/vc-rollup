// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CredDefRegistry, IEthereumDIDRegistry} from "./CredDefRegistry.sol";

/// Policies commit to descriptive query text, bindings and validated postfix programs.
/// The programs define executable semantics; the contract computes their classes.
/// Public programs authorize updates. Presented programs are retained for off-chain
/// presentations only and cannot bind to issuance or revocation (ENFORCED-GUARDS.md).
contract PolicyRegistry {
    enum Class {
        StateIndependent,
        Stable,
        CoStable,
        Volatile
    }
    enum BindingKind {
        Group,
        Registry,
        CredDef
    }
    enum Action {
        Issue,
        Revoke,
        Present
    }
    enum Quant {
        All,
        Exists,
        AtLeast,
        AtMost
    }
    enum Domain {
        Group,
        Issued,
        Presented
    }
    enum Polarity {
        Neutral,
        Up,
        Down,
        Mixed
    }
    enum OpKind {
        Clause,
        And,
        Or
    }

    struct Binding {
        bytes32 name; // a query-ben használt név (rövid string bytes32-ként)
        BindingKind kind;
        bytes32 target; // groupId, registryId vagy credDefId
    }

    /// Clause: quant x ∈ domain(bindings[binding]). body; And / Or: a verem két felső elemének join-ja.
    struct Op {
        OpKind kind;
        Quant quant;
        uint32 k;
        Domain domain;
        uint8 binding;
        Polarity body;
    }

    struct Policy {
        address author;
        string query;
        bytes32 queryHash;
        Binding[] bindings;
        Op[] presentedOps;
        Op[] publicOps;
        Class presentedClass;
        Class publicClass;
        uint256 createdAt;
    }

    uint256 public constant MAX_OPS = 32;

    CredDefRegistry public immutable credDefRegistry;
    IEthereumDIDRegistry public immutable didRegistry;

    mapping(bytes32 policyId => Policy) private policies;
    mapping(bytes32 credDefId => mapping(Action => bytes32 policyId)) private bound;

    event PolicyRegistered(
        bytes32 indexed policyId,
        address indexed author,
        string query,
        Binding[] bindings,
        Op[] presentedOps,
        Op[] publicOps,
        Class presentedClass,
        Class publicClass
    );
    event PolicyBound(bytes32 indexed credDefId, Action indexed action, bytes32 indexed policyId);

    error ZeroAddress();
    error EmptyQuery();
    error PolicyExists(bytes32 policyId);
    error UnknownPolicy(bytes32 policyId);
    error UnknownCredDef(bytes32 credDefId);
    error NotIssuer(bytes32 credDefId, address caller);
    error DuplicateBindingName(uint256 index);
    error ProgramTooLong(uint256 length);
    error MalformedProgram();
    error BadBinding(uint256 index);
    error DomainBindingMismatch(uint256 index);
    error BadPresentedClause(uint256 index);
    error BadPublicClause(uint256 index);
    error UnsupportedPrivateGuard(bytes32 policyId);
    error PolicyLocked(bytes32 current, bytes32 requested);

    constructor(address _credDefRegistry) {
        if (_credDefRegistry == address(0)) revert ZeroAddress();
        credDefRegistry = CredDefRegistry(_credDefRegistry);
        didRegistry = CredDefRegistry(_credDefRegistry).didRegistry();
    }

    function registerPolicy(
        string calldata query,
        Binding[] calldata bindings,
        Op[] calldata presentedOps,
        Op[] calldata publicOps
    ) external returns (bytes32 policyId) {
        if (bytes(query).length == 0) revert EmptyQuery();
        for (uint256 i = 0; i < bindings.length; i++) {
            for (uint256 j = 0; j < i; j++) {
                if (bindings[j].name == bindings[i].name) revert DuplicateBindingName(i);
            }
        }
        _validate(presentedOps, bindings, true);
        _validate(publicOps, bindings, false);

        policyId = keccak256(abi.encode(msg.sender, query, bindings, presentedOps, publicOps));
        Policy storage p = policies[policyId];
        if (p.createdAt != 0) revert PolicyExists(policyId);
        p.author = msg.sender;
        p.query = query;
        p.queryHash = keccak256(bytes(query));
        for (uint256 i = 0; i < bindings.length; i++) {
            p.bindings.push(bindings[i]);
        }
        for (uint256 i = 0; i < presentedOps.length; i++) {
            p.presentedOps.push(presentedOps[i]);
        }
        for (uint256 i = 0; i < publicOps.length; i++) {
            p.publicOps.push(publicOps[i]);
        }
        p.presentedClass = classify(presentedOps);
        p.publicClass = classify(publicOps);
        p.createdAt = block.timestamp;

        emit PolicyRegistered(
            policyId, msg.sender, query, bindings, presentedOps, publicOps, p.presentedClass, p.publicClass
        );
    }

    /// Update policies are permanent once bound. Presentation policies remain mutable.
    /// Nonempty presented programs cannot authorize updates: no on-chain verifier exists.
    function bindPolicy(bytes32 credDefId, Action action, bytes32 policyId) external {
        if (!credDefRegistry.exists(credDefId)) revert UnknownCredDef(credDefId);
        if (didRegistry.identityOwner(credDefRegistry.issuerOf(credDefId)) != msg.sender) {
            revert NotIssuer(credDefId, msg.sender);
        }
        if (policyId != bytes32(0) && policies[policyId].createdAt == 0) revert UnknownPolicy(policyId);
        if (action != Action.Present) {
            bytes32 current = bound[credDefId][action];
            if (current != bytes32(0) && current != policyId) revert PolicyLocked(current, policyId);
            if (policyId != bytes32(0) && policies[policyId].presentedOps.length != 0) {
                revert UnsupportedPrivateGuard(policyId);
            }
        }
        bound[credDefId][action] = policyId;
        emit PolicyBound(credDefId, action, policyId);
    }

    function boundPolicy(bytes32 credDefId, Action action) external view returns (bytes32) {
        return bound[credDefId][action];
    }

    function exists(bytes32 policyId) external view returns (bool) {
        return policies[policyId].createdAt != 0;
    }

    function getPolicy(bytes32 policyId) external view returns (Policy memory) {
        if (policies[policyId].createdAt == 0) revert UnknownPolicy(policyId);
        return policies[policyId];
    }

    function presentedClass(bytes32 policyId) external view returns (Class) {
        if (policies[policyId].createdAt == 0) revert UnknownPolicy(policyId);
        return policies[policyId].presentedClass;
    }

    function publicClass(bytes32 policyId) external view returns (Class) {
        if (policies[policyId].createdAt == 0) revert UnknownPolicy(policyId);
        return policies[policyId].publicClass;
    }

    /// amit a StateRegistry-nek a guard ellenőrzéséhez tudnia kell
    function guardSpec(bytes32 policyId)
        external
        view
        returns (
            Class presented,
            BindingKind[] memory kinds,
            bytes32[] memory targets,
            Op[] memory presentedOps,
            Op[] memory publicOps
        )
    {
        Policy storage p = policies[policyId];
        if (p.createdAt == 0) revert UnknownPolicy(policyId);
        uint256 n = p.bindings.length;
        kinds = new BindingKind[](n);
        targets = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            kinds[i] = p.bindings[i].kind;
            targets[i] = p.bindings[i].target;
        }
        return (p.presentedClass, kinds, targets, p.presentedOps, p.publicOps);
    }

    /// A program osztálya a polaritásából (lem:closure, THESIS-CHANGES 11.): üres program = StateIndependent.
    function classify(Op[] calldata ops) public pure returns (Class) {
        if (ops.length == 0) return Class.StateIndependent;
        Polarity[] memory stack = new Polarity[](ops.length);
        uint256 depth = 0;
        for (uint256 i = 0; i < ops.length; i++) {
            Op calldata op = ops[i];
            if (op.kind == OpKind.Clause) {
                stack[depth++] = _clausePolarity(op);
            } else {
                if (depth < 2) revert MalformedProgram();
                stack[depth - 2] = _join(stack[depth - 2], stack[depth - 1]);
                depth--;
            }
        }
        if (depth != 1) revert MalformedProgram();
        Polarity p = stack[0];
        if (p == Polarity.Neutral) return Class.StateIndependent;
        if (p == Polarity.Up) return Class.Stable;
        if (p == Polarity.Down) return Class.CoStable;
        return Class.Volatile;
    }

    ///SEGÉDFÜGGVÉNYEK
    /// Csoport és Presented fix halmaz: a kvantor megtartja a törzs polaritását, az atmost megfordítja.
    /// Issued csak nő: ∀ = ↓ ⊔ törzs, ∃ / atleast = ↑ ⊔ törzs, atmost = ↓ ⊔ flip(törzs).
    function _clausePolarity(Op calldata op) private pure returns (Polarity) {
        Polarity body = op.body;
        if (op.domain == Domain.Issued) {
            if (op.quant == Quant.All) return _join(Polarity.Down, body);
            if (op.quant == Quant.AtMost) return _join(Polarity.Down, _flip(body));
            return _join(Polarity.Up, body);
        }
        return op.quant == Quant.AtMost ? _flip(body) : body;
    }

    function _flip(Polarity p) private pure returns (Polarity) {
        if (p == Polarity.Up) return Polarity.Down;
        if (p == Polarity.Down) return Polarity.Up;
        return p;
    }

    function _join(Polarity a, Polarity b) private pure returns (Polarity) {
        if (a == Polarity.Neutral) return b;
        if (b == Polarity.Neutral || a == b) return a;
        return Polarity.Mixed;
    }

    function _validate(Op[] calldata ops, Binding[] calldata bindings, bool presented) private pure {
        if (ops.length > MAX_OPS) revert ProgramTooLong(ops.length);
        uint256 depth = 0;
        for (uint256 i = 0; i < ops.length; i++) {
            Op calldata op = ops[i];
            if (op.kind != OpKind.Clause) {
                if (depth < 2) revert MalformedProgram();
                depth--;
                continue;
            }
            depth++;
            if (op.binding >= bindings.length) revert BadBinding(i);
            bool trivialQuant = op.quant == Quant.All || op.quant == Quant.Exists;
            if (presented) {
                // Presented fölött csak ∃ és atleast mond valamit (scope guard 4)
                if (op.domain != Domain.Presented) revert BadPresentedClause(i);
                if (op.quant == Quant.All || op.quant == Quant.AtMost) revert BadPresentedClause(i);
                if (trivialQuant && op.k != 0) revert BadPresentedClause(i);
            } else {
                if (op.domain == Domain.Presented) revert BadPublicClause(i);
                if (op.body != Polarity.Up && op.body != Polarity.Down) revert BadPublicClause(i);
                if (trivialQuant && op.k != 0) revert BadPublicClause(i);
            }
            BindingKind kind = bindings[op.binding].kind;
            bool fits = op.domain == Domain.Group
                ? kind == BindingKind.Group
                : op.domain == Domain.Issued
                    ? kind == BindingKind.Registry
                    : kind == BindingKind.Registry || (kind == BindingKind.CredDef && op.body == Polarity.Neutral);
            if (!fits) revert DomainBindingMismatch(i);
        }
        if (ops.length != 0 && depth != 1) revert MalformedProgram();
    }
}
