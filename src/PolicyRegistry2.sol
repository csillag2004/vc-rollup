// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  PolicyRegistry
/// @notice Tartalom-alapú, immutábilis tároló monoton predikátumhalmazokhoz.
///
///         Egy policy négy rétegből áll:
///           - slotCount: hány szabad változó (credential-hely) van,
///           - terms:     projekciók, amik egy slotból primitív értéket adnak,
///           - atoms:     relációk két term között — ezek a predikátumok,
///           - nodes:     monoton AND/OR DAG az atomok felett.
///
///         A visszaadott predikátum a DAG gyökere: egy (slot -> credential)
///         hozzárendelésen értelmezett igaz/hamis függvény, slotCount szabad
///         változóval.
///
/// @dev    A kontraktus kizárólag tárol és kiad. Nem értékel ki, nem lát
///         credentialt. A validáció célja kettős: a policyId <-> szemantika
///         leképezés injektív maradjon (kanonikusság), és az atomok jól
///         típusozottak legyenek.
contract PolicyRegistry {
    // -----------------------------------------------------------------------
    // Korlátok
    // -----------------------------------------------------------------------

    /// @dev Mind 256 vagy alatta, mert a validáció uint256 bitmapeket használ.
    uint256 public constant MAX_SLOTS = 32;
    uint256 public constant MAX_TERMS = 256;
    uint256 public constant MAX_ATOMS = 256;
    uint256 public constant MAX_NODES = 256;

    bytes32 private constant POLICY_DOMAIN = keccak256("PolicyRegistry.Policy.v1");
    uint16  private constant VERSION = 1;

    // -----------------------------------------------------------------------
    // Tárolt típusok
    // -----------------------------------------------------------------------

    /// @notice Egy term forrása: konstans, vagy egy slot valamelyik projekciója.
    /// @dev    Új accessor bevezetése csak új enum-érték — a struct layout és
    ///         ezzel a kanonikus kódolás változatlan marad.
    enum TermKind { CONST, SCHEMA_ID, CRED_DEF_ID, ISSUER, REVOCATION }

    /// @dev A term eredménytípusa. A CONST polimorf: a párja dönti el.
    enum TermType { POLY, ID, STATUS }

    enum CredentialStatus { VALID, REVOKED }

    enum Rel { EQ, NEQ }

    enum NodeKind { LEAF, AND, OR }

    /// @dev Egy megnézhető érték. CONST esetén a `value` a literál és a `slot`
    ///      nulla; accessor esetén fordítva.
    struct Term {
        TermKind kind;
        uint16   slot;
        bytes32  value;
    }

    /// @dev Egy predikátum, term-indexekkel. `termA < termB`, mert az EQ és a
    ///      NEQ szimmetrikus.
    struct Atom {
        Rel    rel;
        uint16 termA;
        uint16 termB;
    }

    struct Node {
        NodeKind kind;
        uint16   atomIndex;  // csak LEAF
        /// @dev AND/OR esetén: szigorúan növekvő node-indexek, mind kisebbek
        ///      a saját indexnél (topologikus rendezés).
        uint16[] children;
    }

    struct Policy {
        uint8  slotCount;    // 0 = nem létező policy
        Term[] terms;
        Atom[] atoms;
        Node[] nodes;
    }

    // -----------------------------------------------------------------------
    // Kiadott típusok
    // -----------------------------------------------------------------------

    /// @notice Egy predikátum, feloldott termekkel — önmagában olvasható.
    struct ResolvedPredicate {
        Rel  rel;
        Term termA;
        Term termB;
    }

    /// @notice A kombinátor egy csomópontja feloldott levéllel.
    /// @dev    AND/OR esetén a `predicate` nullákkal van kitöltve és nem
    ///         jelent semmit; a `children` node-indexek ugyanebbe a tömbbe.
    struct ResolvedNode {
        NodeKind          kind;
        ResolvedPredicate predicate;  // csak LEAF
        uint16[]          children;   // csak AND/OR
    }

    // -----------------------------------------------------------------------
    // Állapot
    // -----------------------------------------------------------------------

    mapping(bytes32 => Policy) private _policies;

    // -----------------------------------------------------------------------
    // Események
    // -----------------------------------------------------------------------

    event PolicyRegistered(
        bytes32 indexed policyId,
        address indexed registrar,
        uint8  slotCount,
        uint16 termCount,
        uint16 atomCount,
        uint16 nodeCount
    );

    // -----------------------------------------------------------------------
    // Hibák
    // -----------------------------------------------------------------------

    error BadSlotCount();
    error BadTermCount();
    error BadAtomCount();
    error BadNodeCount();
    error BadTerm(uint256 index);
    error TermsNotCanonical(uint256 index);
    error BadAtom(uint256 index);
    error AtomTypeMismatch(uint256 index);
    error AtomsNotCanonical(uint256 index);
    error BadNode(uint256 index);
    error NotTopologicallyOrdered(uint256 index);
    error UnusedSlot(uint256 slot);
    error UnusedTerm(uint256 index);
    error UnusedAtom(uint256 index);
    error UnreachableNode(uint256 index);
    error PolicyAlreadyRegistered(bytes32 policyId);
    error UnknownPolicy(bytes32 policyId);

    // -----------------------------------------------------------------------
    // Írás
    // -----------------------------------------------------------------------

    function registerPolicy(
        uint8 slotCount,
        Term[] calldata terms,
        Atom[] calldata atoms,
        Node[] calldata nodes
    ) external returns (bytes32 policyId) {
        // Validáció a hash előtt: az azonosító csak kanonikus alakra értelmes.
        _validate(slotCount, terms, atoms, nodes);

        policyId = computePolicyId(slotCount, terms, atoms, nodes);

        Policy storage p = _policies[policyId];
        if (p.slotCount != 0) revert PolicyAlreadyRegistered(policyId);

        p.slotCount = slotCount;

        // A Term és az Atom fix méretű, tehát közvetlenül másolható.
        for (uint256 i; i < terms.length; ++i) p.terms.push(terms[i]);
        for (uint256 i; i < atoms.length; ++i) p.atoms.push(atoms[i]);

        // A Node beágyazott dinamikus tömböt tartalmaz, azt elemenként kell.
        for (uint256 i; i < nodes.length; ++i) {
            p.nodes.push();
            Node storage n = p.nodes[i];
            n.kind = nodes[i].kind;
            n.atomIndex = nodes[i].atomIndex;
            for (uint256 j; j < nodes[i].children.length; ++j) {
                n.children.push(nodes[i].children[j]);
            }
        }

        emit PolicyRegistered(
            policyId,
            msg.sender,
            slotCount,
            uint16(terms.length),
            uint16(atoms.length),
            uint16(nodes.length)
        );
    }

    /// @notice A kanonikus policyId, regisztráció nélkül is kiszámítható.
    /// @dev    abi.encode, NEM encodePacked: a packed kódolás dinamikus
    ///         tömböknél ütköztethető. A NYERS alakon dolgozik, nem a
    ///         feloldotton — a hash arra van értelmezve.
    function computePolicyId(
        uint8 slotCount,
        Term[] calldata terms,
        Atom[] calldata atoms,
        Node[] calldata nodes
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(POLICY_DOMAIN, VERSION, slotCount, terms, atoms, nodes)
        );
    }

    // -----------------------------------------------------------------------
    // Olvasás
    // -----------------------------------------------------------------------

    function exists(bytes32 policyId) public view returns (bool) {
        return _policies[policyId].slotCount != 0;
    }

    /// @notice A nyers, tárolt alak — ez kell a computePolicyId reprodukálásához.
    function getPolicy(bytes32 policyId)
        external
        view
        returns (uint8 slotCount, Term[] memory terms, Atom[] memory atoms, Node[] memory nodes)
    {
        Policy storage p = _policies[policyId];
        if (p.slotCount == 0) revert UnknownPolicy(policyId);
        return (p.slotCount, p.terms, p.atoms, p.nodes);
    }

    /// @notice A predikátumhalmaz, feloldott termekkel.
    function getPredicates(bytes32 policyId)
        external
        view
        returns (uint8 slotCount, ResolvedPredicate[] memory predicates)
    {
        Policy storage p = _policies[policyId];
        if (p.slotCount == 0) revert UnknownPolicy(policyId);

        uint256 na = p.atoms.length;
        predicates = new ResolvedPredicate[](na);
        for (uint256 i; i < na; ++i) {
            predicates[i] = _resolve(p, i);
        }
        return (p.slotCount, predicates);
    }

    /// @notice A nagy predikátum: a kombinátor feloldott levelekkel.
    ///         A gyökér mindig az utolsó elem.
    /// @return slotCount Hány szabad változója van a predikátumnak.
    /// @return dag       A topologikusan rendezett csomópontok.
    function getRootPredicate(bytes32 policyId)
        external
        view
        returns (uint8 slotCount, ResolvedNode[] memory dag)
    {
        Policy storage p = _policies[policyId];
        if (p.slotCount == 0) revert UnknownPolicy(policyId);

        uint256 nn = p.nodes.length;
        dag = new ResolvedNode[](nn);

        for (uint256 i; i < nn; ++i) {
            Node storage n = p.nodes[i];

            uint256 cl = n.children.length;
            uint16[] memory ch = new uint16[](cl);
            for (uint256 j; j < cl; ++j) ch[j] = n.children[j];

            ResolvedPredicate memory rp;
            if (n.kind == NodeKind.LEAF) rp = _resolve(p, n.atomIndex);

            dag[i] = ResolvedNode({ kind: n.kind, predicate: rp, children: ch });
        }

        return (p.slotCount, dag);
    }

    function _resolve(Policy storage p, uint256 atomIndex)
        internal
        view
        returns (ResolvedPredicate memory)
    {
        Atom storage a = p.atoms[atomIndex];
        return ResolvedPredicate({
            rel:   a.rel,
            termA: p.terms[a.termA],
            termB: p.terms[a.termB]
        });
    }

    // -----------------------------------------------------------------------
    // Típusrendszer
    // -----------------------------------------------------------------------

    /// @notice Egy accessor eredménytípusa. A CONST polimorf.
    /// @dev    public, hogy a generátor ne duplikálja a leképezést.
    function termType(TermKind kind) public pure returns (TermType) {
        if (kind == TermKind.CONST) return TermType.POLY;
        if (kind == TermKind.REVOCATION) return TermType.STATUS;
        return TermType.ID; // SCHEMA_ID, CRED_DEF_ID, ISSUER
    }

    // -----------------------------------------------------------------------
    // Validáció
    // -----------------------------------------------------------------------

        // -----------------------------------------------------------------------
    // Validáció
    // -----------------------------------------------------------------------

    function _validate(
        uint8 ns,
        Term[] calldata terms,
        Atom[] calldata atoms,
        Node[] calldata nodes
    ) internal pure {
        if (ns == 0 || ns > MAX_SLOTS)                          revert BadSlotCount();
        if (terms.length == 0 || terms.length > MAX_TERMS)      revert BadTermCount();
        if (atoms.length == 0 || atoms.length > MAX_ATOMS)      revert BadAtomCount();
        if (nodes.length == 0 || nodes.length > MAX_NODES)      revert BadNodeCount();

        _validateTerms(ns, terms);
        _validateAtoms(terms, atoms);
        _validateNodes(atoms.length, nodes);
    }

    /// @dev Termek: belső érvényesség, kanonikus sorrend, slot-lefedettség.
    function _validateTerms(uint8 ns, Term[] calldata terms) internal pure {
        uint256 nt = terms.length;
        uint256 slotUsed;

        for (uint256 i; i < nt; ++i) {
            Term calldata t = terms[i];
            if (t.kind == TermKind.CONST) {
                if (t.slot != 0) revert BadTerm(i);
            } else {
                if (t.slot >= ns) revert BadTerm(i);
                if (t.value != bytes32(0)) revert BadTerm(i);
                slotUsed |= (uint256(1) << t.slot);
            }
            if (i > 0 && !_termLess(terms[i - 1], t)) revert TermsNotCanonical(i);
        }

        for (uint256 i; i < ns; ++i) {
            if ((slotUsed >> i) & 1 == 0) revert UnusedSlot(i);
        }
    }

    /// @dev Atomok: kanonikus sorrend és term-lefedettség. Az egyes atomok
    ///      ellenőrzése külön frame-ben fut, hogy ne fogyjon el a stack.
    function _validateAtoms(Term[] calldata terms, Atom[] calldata atoms) internal pure {
        uint256 na = atoms.length;
        uint256 termUsed;

        for (uint256 i; i < na; ++i) {
            _checkAtom(terms, atoms[i], i);
            termUsed |= (uint256(1) << atoms[i].termA);
            termUsed |= (uint256(1) << atoms[i].termB);
            if (i > 0 && !_atomLess(atoms[i - 1], atoms[i])) revert AtomsNotCanonical(i);
        }

        uint256 nt = terms.length;
        for (uint256 i; i < nt; ++i) {
            if ((termUsed >> i) & 1 == 0) revert UnusedTerm(i);
        }
    }

    function _checkAtom(Term[] calldata terms, Atom calldata a, uint256 i) internal pure {
        uint256 nt = terms.length;
        if (a.termA >= nt || a.termB >= nt) revert BadAtom(i);
        // Szimmetrikus reláció: normalizált irány, és nincs önhasonlítás.
        if (a.termA >= a.termB) revert BadAtom(i);

        TermKind ka = terms[a.termA].kind;
        TermKind kb = terms[a.termB].kind;
        // Két konstans összehasonlítása konstans kifejezés, nem policy.
        if (ka == TermKind.CONST && kb == TermKind.CONST) revert BadAtom(i);

        TermType ta = termType(ka);
        TermType tb = termType(kb);
        if (ta != TermType.POLY && tb != TermType.POLY && ta != tb) {
            revert AtomTypeMismatch(i);
        }

        // A POLY nem szűrt semmit, ezért a STATUS-hoz hasonlított literál
        // tartományát külön kell nézni — mindkét oldalon.
        if (ka == TermKind.CONST && tb == TermType.STATUS) {
            _checkStatusLiteral(terms[a.termA].value, i);
        }
        if (kb == TermKind.CONST && ta == TermType.STATUS) {
            _checkStatusLiteral(terms[a.termB].value, i);
        }
    }

    function _checkStatusLiteral(bytes32 v, uint256 i) internal pure {
        if (uint256(v) > uint256(type(CredentialStatus).max)) revert BadAtom(i);
    }

    /// @dev Node-ok: alak, topologikus rendezés, atomhasználat, elérhetőség.
    function _validateNodes(uint256 na, Node[] calldata nodes) internal pure {
        uint256 nn = nodes.length;
        uint256 atomUsed;

        for (uint256 i; i < nn; ++i) {
            atomUsed |= _checkNode(nodes[i], na, i);
        }

        for (uint256 i; i < na; ++i) {
            if ((atomUsed >> i) & 1 == 0) revert UnusedAtom(i);
        }

        _checkReachability(nodes);
    }

    /// @return usedBit A LEAF által hivatkozott atom bitje, kapunál nulla.
    function _checkNode(Node calldata n, uint256 na, uint256 i)
        internal
        pure
        returns (uint256 usedBit)
    {
        uint16[] calldata ch = n.children;

        if (n.kind == NodeKind.LEAF) {
            if (ch.length != 0) revert BadNode(i);
            if (n.atomIndex >= na) revert BadNode(i);
            return uint256(1) << n.atomIndex;
        }

        if (n.atomIndex != 0) revert BadNode(i);
        if (ch.length < 2) revert BadNode(i);
        for (uint256 j; j < ch.length; ++j) {
            // A gyerekindex < saját index egyszerre garantálja a topologikus
            // rendezést és a körmentességet.
            if (ch[j] >= i) revert NotTopologicallyOrdered(i);
            if (j > 0 && ch[j] <= ch[j - 1]) revert BadNode(i);
        }
        return 0;
    }

    /// @dev Minden node elérhető a gyökérből (a gyökér az utolsó node).
    ///      Felülről lefelé haladva minden node-ot már megjelöltek a szülei.
    function _checkReachability(Node[] calldata nodes) internal pure {
        uint256 nn = nodes.length;
        uint256 reach = uint256(1) << (nn - 1);

        for (uint256 i = nn; i > 0; --i) {
            uint256 idx = i - 1;
            if ((reach >> idx) & 1 == 0) revert UnreachableNode(idx);
            uint16[] calldata ch = nodes[idx].children;
            for (uint256 j; j < ch.length; ++j) {
                reach |= (uint256(1) << ch[j]);
            }
        }
    }

    function _termLess(Term calldata a, Term calldata b) internal pure returns (bool) {
        uint256 ka = (uint256(uint8(a.kind)) << 16) | uint256(a.slot);
        uint256 kb = (uint256(uint8(b.kind)) << 16) | uint256(b.slot);
        if (ka != kb) return ka < kb;
        return uint256(a.value) < uint256(b.value);
    }

    function _atomLess(Atom calldata a, Atom calldata b) internal pure returns (bool) {
        uint256 ka = (uint256(uint8(a.rel)) << 32) | (uint256(a.termA) << 16) | uint256(a.termB);
        uint256 kb = (uint256(uint8(b.rel)) << 32) | (uint256(b.termA) << 16) | uint256(b.termB);
        return ka < kb;
    }
}