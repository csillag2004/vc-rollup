// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CredDefRegistry, IEthereumDIDRegistry} from "./CredDefRegistry.sol";

/// Policy = egy query szövege + a benne szereplő domain-nevek kötése láncon lévő objektumokhoz.
/// A query-t a contract nem értelmezi: az osztályt és a CAS-módot a szerző deklarálja,
/// a verifier off-chain újraszámolja. A contract annyit kényszerít ki, hogy a CAS-mód
/// ne legyen gyengébb annál, amit a deklarált osztály és a kötések fajtája megkövetel.
contract PolicyRegistry {

    enum Class { StateIndependent, Stable, CoStable, Volatile }
    enum CasMode { None, Group, Global }
    enum BindingKind { Group, Registry, CredDef }
    enum Action { Issue, Revoke, Present }

    struct Binding {
        bytes32 name;       // a query-ben használt név (rövid string bytes32-ként)
        BindingKind kind;
        bytes32 target;     // groupId, registryId vagy credDefId
    }

    struct Policy {
        address author;
        string query;
        bytes32 queryHash;
        Class class;
        CasMode casMode;
        Binding[] bindings;
        uint256 createdAt;
    }

    CredDefRegistry public immutable credDefRegistry;
    IEthereumDIDRegistry public immutable didRegistry;

    mapping(bytes32 policyId => Policy) private policies;
    mapping(bytes32 credDefId => mapping(Action => bytes32 policyId)) private bound;

    event PolicyRegistered(bytes32 indexed policyId, address indexed author, string query, Class class, CasMode casMode, Binding[] bindings);
    event PolicyBound(bytes32 indexed credDefId, Action indexed action, bytes32 indexed policyId);

    error ZeroAddress();
    error EmptyQuery();
    error PolicyExists(bytes32 policyId);
    error UnknownPolicy(bytes32 policyId);
    error UnknownCredDef(bytes32 credDefId);
    error NotIssuer(bytes32 credDefId, address caller);
    error CasModeTooWeak(CasMode declared, CasMode required);
    error GroupModeNeedsGroups(uint256 index);
    error DuplicateBindingName(uint256 index);

    constructor(address _credDefRegistry) {
        if (_credDefRegistry == address(0)) revert ZeroAddress();
        credDefRegistry = CredDefRegistry(_credDefRegistry);
        didRegistry = CredDefRegistry(_credDefRegistry).didRegistry();
    }

    /// a deklarált osztályhoz és kötésekhez minimálisan szükséges CAS-mód
    function requiredCasMode(Class class, Binding[] calldata bindings) public pure returns (CasMode) {
        if (class == Class.StateIndependent || class == Class.Stable) return CasMode.None;
        for (uint256 i = 0; i < bindings.length; i++) {
            if (bindings[i].kind == BindingKind.Registry) return CasMode.Global;
        }
        return CasMode.Group;
    }

    function registerPolicy(string calldata query, Class class, CasMode casMode, Binding[] calldata bindings)
        external returns (bytes32 policyId)
    {
        if (bytes(query).length == 0) revert EmptyQuery();
        for (uint256 i = 0; i < bindings.length; i++) {
            for (uint256 j = 0; j < i; j++) {
                if (bindings[j].name == bindings[i].name) revert DuplicateBindingName(i);
            }
            if (casMode == CasMode.Group && bindings[i].kind == BindingKind.Registry) revert GroupModeNeedsGroups(i);
        }
        CasMode req = requiredCasMode(class, bindings);
        if (uint8(casMode) < uint8(req)) revert CasModeTooWeak(casMode, req);

        policyId = keccak256(abi.encode(msg.sender, query, class, casMode, bindings));
        Policy storage p = policies[policyId];
        if (p.createdAt != 0) revert PolicyExists(policyId);
        p.author = msg.sender;
        p.query = query;
        p.queryHash = keccak256(bytes(query));
        p.class = class;
        p.casMode = casMode;
        for (uint256 i = 0; i < bindings.length; i++) p.bindings.push(bindings[i]);
        p.createdAt = block.timestamp;

        emit PolicyRegistered(policyId, msg.sender, query, class, casMode, bindings);
    }

    /// a CredDef issuere egy műveletet (kiadás, visszavonás, bemutatás) policyhez köt;
    /// 0 policyId-vel a kötés megszüntethető
    function bindPolicy(bytes32 credDefId, Action action, bytes32 policyId) external {
        if (!credDefRegistry.exists(credDefId)) revert UnknownCredDef(credDefId);
        if (didRegistry.identityOwner(credDefRegistry.issuerOf(credDefId)) != msg.sender) {
            revert NotIssuer(credDefId, msg.sender);
        }
        if (policyId != bytes32(0) && policies[policyId].createdAt == 0) revert UnknownPolicy(policyId);
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

    /// amit a StateRegistry-nek a guard ellenőrzéséhez tudnia kell
    function guardInfo(bytes32 policyId)
        external view
        returns (CasMode casMode, BindingKind[] memory kinds, bytes32[] memory targets)
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
        return (p.casMode, kinds, targets);
    }
}
