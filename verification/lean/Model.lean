import Std

/-!
# Credential lifecycle: frozen model and targets

Set-level model of the credential lifecycle and of atomic guarded updates in
Kocsis Kamilla's TDK paper, `content/03-proposed-approach.tex`. `CONTRACT.md` records
the scope, the encoding decisions, and the claims this model cannot express.
`frozen/spec.sha256` seals this file and `CONTRACT.md`; proofs import it unchanged.

Accumulators and pairing checks are ideal. An accumulator is the set its holders
can prove membership in, and an on-chain check decides its set relation exactly.
Nothing here proves cryptography.
-/

namespace Lifecycle

/-! ## Sets of credential IDs -/

/-- Credential IDs, `𝒴` in def:registry-state. -/
abbrev CredId := Nat

/-- A set of credential IDs, given by its membership predicate. -/
abbrev IdSet := CredId → Prop

namespace IdSet

def empty : IdSet := fun _ => False

def insert (y : CredId) (s : IdSet) : IdSet := fun z => z = y ∨ s z

def erase (y : CredId) (s : IdSet) : IdSet := fun z => s z ∧ z ≠ y

def Subset (s t : IdSet) : Prop := ∀ y, s y → t y

def Finite (s : IdSet) : Prop := ∃ l : List CredId, ∀ y, s y ↔ y ∈ l

end IdSet

/-! ## Registry states and updates (sec:atomic-guarded-update) -/

/-- `Σ = (Iss, Rev)` of def:registry-state. Well-formedness is the separate `Valid`. -/
structure RegState where
  iss : IdSet
  rev : IdSet

namespace RegState

/-- def:registry-state: `Iss` and `Rev` are finite and `Rev ⊆ Iss`. -/
def Valid (σ : RegState) : Prop :=
  IdSet.Finite σ.iss ∧ IdSet.Finite σ.rev ∧ IdSet.Subset σ.rev σ.iss

/-- The initial state `Σ₀ = (∅, ∅)`. -/
def init : RegState := ⟨IdSet.empty, IdSet.empty⟩

/-- The active set `Iss \ Rev`. -/
def active (σ : RegState) : IdSet := fun y => σ.iss y ∧ ¬ σ.rev y

/-- def:state-order: `Σ ⊑ Σ'`. -/
def Le (σ σ' : RegState) : Prop :=
  IdSet.Subset σ.iss σ'.iss ∧ IdSet.Subset σ.rev σ'.rev

end RegState

/-- def:updates. -/
inductive Update where
  | issue (y : CredId)
  | revoke (y : CredId)
  deriving DecidableEq, Repr

namespace Update

/-- The credential ID an update is about. -/
def cred : Update → CredId
  | issue y => y
  | revoke y => y

def Enabled : Update → RegState → Prop
  | issue y, σ => ¬ σ.iss y
  | revoke y, σ => σ.iss y ∧ ¬ σ.rev y

def apply : Update → RegState → RegState
  | issue y, σ => { σ with iss := IdSet.insert y σ.iss }
  | revoke y, σ => { σ with rev := IdSet.insert y σ.rev }

/-- The ID an update revokes, if it is a revocation. -/
def revokedCred : Update → Option CredId
  | issue _ => none
  | revoke y => some y

end Update

/-- `Σ →u Σ'` of not:steps. -/
def Step (σ : RegState) (u : Update) (σ' : RegState) : Prop :=
  u.Enabled σ ∧ σ' = u.apply σ

/-- `Σ →* Σ'`: a finite, possibly empty, sequence of steps. -/
inductive Reach : RegState → RegState → Prop where
  | refl (σ : RegState) : Reach σ σ
  | tail {σ τ τ' : RegState} {u : Update} : Reach σ τ → Step τ u τ' → Reach σ τ'

/-- The state a sequence of updates leads to, applied without checks. -/
def replay (σ : RegState) (log : List Update) : RegState :=
  log.foldl (fun τ u => u.apply τ) σ

/-! ## Atoms, conditions, domains, quantifiers, formulas -/

/-- def:atoms. -/
inductive Atom where
  | revoked
  | notRevoked
  | issued
  | notIssued
  deriving DecidableEq, Repr

/-- not:models: `Σ ⊨ A(y)`. -/
def Atom.holds : Atom → RegState → CredId → Prop
  | revoked, σ, y => σ.rev y
  | notRevoked, σ, y => ¬ σ.rev y
  | issued, σ, y => σ.iss y
  | notIssued, σ, y => ¬ σ.iss y

/-- def:atom-classes. -/
def Atom.Monotone (a : Atom) : Prop :=
  ∀ σ σ' : RegState, ∀ y, σ.Valid → σ'.Valid → σ.Le σ' → a.holds σ y → a.holds σ' y

/-- def:atom-classes. -/
def Atom.Antitone (a : Atom) : Prop :=
  ∀ σ σ' : RegState, ∀ y, σ.Valid → σ'.Valid → σ.Le σ' → ¬ a.holds σ y → ¬ a.holds σ' y

/-- Credential variables. -/
abbrev Var := Nat

/-- An assignment of credential IDs to credential variables. -/
abbrev Env := Var → CredId

/-- `ρ` with `x` bound to `y`. -/
def bindVar (ρ : Env) (x : Var) (y : CredId) : Env := fun z => if z = x then y else ρ z

/-- def:conditions. -/
inductive Cond where
  | tt
  | ff
  | atom (a : Atom) (x : Var)
  | neg (φ : Cond)
  | conj (φ ψ : Cond)
  | disj (φ ψ : Cond)
  deriving Repr

def Cond.holds : Cond → RegState → Env → Prop
  | tt, _, _ => True
  | ff, _, _ => False
  | atom a x, σ, ρ => a.holds σ (ρ x)
  | neg φ, σ, ρ => ¬ φ.holds σ ρ
  | conj φ ψ, σ, ρ => φ.holds σ ρ ∧ ψ.holds σ ρ
  | disj φ ψ, σ, ρ => φ.holds σ ρ ∨ ψ.holds σ ρ

/-- Every variable of the condition is in `bound`. -/
def Cond.Scoped : Cond → List Var → Prop
  | tt, _ => True
  | ff, _ => True
  | atom _ x, bound => x ∈ bound
  | neg φ, bound => φ.Scoped bound
  | conj φ ψ, bound => φ.Scoped bound ∧ ψ.Scoped bound
  | disj φ ψ, bound => φ.Scoped bound ∧ ψ.Scoped bound

/-- def:stable-formulas, for conditions: stable for every assignment of its variables. -/
def Cond.Stable (φ : Cond) : Prop :=
  ∀ σ σ' : RegState, ∀ ρ, σ.Valid → σ'.Valid → σ.Le σ' → φ.holds σ ρ → φ.holds σ' ρ

/-- def:stable-formulas, for conditions. -/
def Cond.CoStable (φ : Cond) : Prop :=
  ∀ σ σ' : RegState, ∀ ρ, σ.Valid → σ'.Valid → σ.Le σ' → ¬ φ.holds σ ρ → ¬ φ.holds σ' ρ

/-- A finite set of credential IDs fixed by a party other than the prover.
Order and repetition are irrelevant; only membership is used. -/
abbrev Group := List CredId

/-- def:domains. `presented P` carries the presented set `P`. -/
inductive Domain where
  | group (S : Group)
  | presented (P : Group)
  | issued
  deriving DecidableEq, Repr

/-- `dom_Σ(D)` of def:domains. -/
def Domain.denote : Domain → RegState → IdSet
  | group S, _ => fun y => y ∈ S
  | presented P, _ => fun y => y ∈ P
  | issued, σ => σ.iss

/-- Groups and `Presented`: the domains that do not depend on the state. -/
def Domain.Fixed : Domain → Prop
  | group _ => True
  | presented _ => True
  | issued => False

/-- def:quantifiers. -/
inductive Quant where
  | all
  | ex
  | atLeast (k : Nat)
  | atMost (k : Nat)
  deriving DecidableEq, Repr

/-- At least `k` distinct members of `D` satisfy `p`. -/
def AtLeast (k : Nat) (D : IdSet) (p : CredId → Prop) : Prop :=
  ∃ l : List CredId, l.Nodup ∧ l.length = k ∧ ∀ y ∈ l, D y ∧ p y

def Quant.holds : Quant → IdSet → (CredId → Prop) → Prop
  | all, D, p => ∀ y, D y → p y
  | ex, D, p => ∃ y, D y ∧ p y
  | atLeast k, D, p => AtLeast k D p
  | atMost k, D, p => ¬ AtLeast (k + 1) D p

/-- def:formulas. -/
inductive Formula where
  | qcond (Q : Quant) (x : Var) (D : Domain) (φ : Cond)
  | qform (Q : Quant) (x : Var) (D : Domain) (Φ : Formula)
  | neg (Φ : Formula)
  | conj (Φ Ψ : Formula)
  | disj (Φ Ψ : Formula)
  deriving Repr

namespace Formula

/-- not:models-formulas, under an assignment of the free variables. -/
def holds : Formula → RegState → Env → Prop
  | qcond Q x D φ, σ, ρ => Q.holds (D.denote σ) (fun y => φ.holds σ (bindVar ρ x y))
  | qform Q x D Φ, σ, ρ => Q.holds (D.denote σ) (fun y => Φ.holds σ (bindVar ρ x y))
  | neg Φ, σ, ρ => ¬ Φ.holds σ ρ
  | conj Φ Ψ, σ, ρ => Φ.holds σ ρ ∧ Ψ.holds σ ρ
  | disj Φ Ψ, σ, ρ => Φ.holds σ ρ ∨ Ψ.holds σ ρ

/-- Every variable of the formula is bound by an enclosing quantifier or is in `bound`. -/
def Scoped : Formula → List Var → Prop
  | qcond _ x _ φ, bound => φ.Scoped (x :: bound)
  | qform _ x _ Φ, bound => Φ.Scoped (x :: bound)
  | neg Φ, bound => Φ.Scoped bound
  | conj Φ Ψ, bound => Φ.Scoped bound ∧ Ψ.Scoped bound
  | disj Φ Ψ, bound => Φ.Scoped bound ∧ Ψ.Scoped bound

/-- def:formulas: a closed formula. -/
def Closed (Φ : Formula) : Prop := Φ.Scoped []

/-- def:formula-domains: `𝒟(Φ)`. -/
def domains : Formula → List Domain
  | qcond _ _ D _ => [D]
  | qform _ _ D Φ => D :: Φ.domains
  | neg Φ => Φ.domains
  | conj Φ Ψ => Φ.domains ++ Ψ.domains
  | disj Φ Ψ => Φ.domains ++ Ψ.domains

/-- Every domain of the formula is a group. -/
def AllGroups (Φ : Formula) : Prop := ∀ D ∈ Φ.domains, ∃ S, D = Domain.group S

end Formula

/-- `Σ ⊨ Φ`. The assignment is irrelevant when `Φ` is closed. -/
def Models (σ : RegState) (Φ : Formula) : Prop := Φ.holds σ (fun _ => 0)

/-- def:stable-formulas. -/
def Formula.Stable (Φ : Formula) : Prop :=
  ∀ σ σ' : RegState, σ.Valid → σ'.Valid → σ.Le σ' → Models σ Φ → Models σ' Φ

/-- def:stable-formulas. -/
def Formula.CoStable (Φ : Formula) : Prop :=
  ∀ σ σ' : RegState, σ.Valid → σ'.Valid → σ.Le σ' → ¬ Models σ Φ → ¬ Models σ' Φ

/-- The running example's guard `∀ x ∈ S. NotRevoked(x)`. -/
def reservationGuard (S : Group) : Formula :=
  .qcond .all 0 (.group S) (.atom .notRevoked 0)

/-! ## Three accumulators as ideal sets (def:representation, sec:plain-comparison) -/

/-- The stored values of `I`, `A` and `R̃`, each as the set of IDs its group element encodes.
`I` encodes the issued IDs and `R̃` the revoked IDs. With static add, `A` does not change on
issuance: its value encodes the revoked IDs (`Arev`), and a holder can prove that `y` is in
`A` when `y` is issued and not in `Arev`. -/
structure Accs where
  I : IdSet
  Arev : IdSet
  R : IdSet

namespace Accs

def init : Accs := ⟨IdSet.empty, IdSet.empty, IdSet.empty⟩

/-- The active set `A`: the IDs a holder can prove membership of. -/
def A (a : Accs) : IdSet := fun y => a.I y ∧ ¬ a.Arev y

/-- The values that encode a registry state exactly. -/
def ofState (σ : RegState) : Accs := ⟨σ.iss, σ.rev, σ.rev⟩

/-- def:representation, with `acc` the identity on the encoded sets. -/
def Represents (a : Accs) (σ : RegState) : Prop :=
  (∀ y, a.I y ↔ σ.iss y) ∧ (∀ y, a.Arev y ↔ σ.rev y) ∧ (∀ y, a.R y ↔ σ.rev y)

/-- def:accumulator-updates: the honest new values, computed from the stored ones. -/
def update : Update → Accs → Accs
  | .issue y, a => { a with I := IdSet.insert y a.I }
  | .revoke y, a => { a with Arev := IdSet.insert y a.Arev, R := IdSet.insert y a.R }

/-- The stored values after an update that proposes the values `p`. An issuance writes `I`;
a revocation writes `A` and `R̃`; the other stored values stay. -/
def write : Update → Accs → Accs → Accs
  | .issue _, a, p => { a with I := p.I }
  | .revoke _, a, p => { a with Arev := p.Arev, R := p.R }

/-- The registry state `(Iss, Rev)` the stored values encode, read from `I` and `R̃`. -/
def reg (a : Accs) : RegState := ⟨a.I, a.R⟩

/-- Issuance check, proposed by this model and not in the paper: the set reading of
`e(I', g̃) = e(I, g̃^y · Q̃)`, with a fresh `y`. -/
def IssueCheck (a : Accs) (u : Update) (p : Accs) : Prop :=
  match u with
  | .issue y => ¬ a.I y ∧ ∀ z, p.I z ↔ z = y ∨ a.I z
  | .revoke _ => True

/-- Step check (sec:plain-comparison (3)): the set reading of
`e(A', g̃^y · Q̃) = e(A, g̃)`; the revoked set `A` encodes gains `y`, which it lacked. -/
def StepCheck (a : Accs) (u : Update) (p : Accs) : Prop :=
  match u with
  | .issue _ => True
  | .revoke y => ¬ a.Arev y ∧ ∀ z, p.Arev z ↔ z = y ∨ a.Arev z

/-- Consistency check (4) on stored values: `A` and `R̃` encode the same revoked set. -/
def ConsistencyCheck (a : Accs) : Prop := ∀ z, a.Arev z ↔ a.R z

/-- Revoked ⊆ issued (5) on stored values. -/
def SubsetCheck (a : Accs) : Prop := IdSet.Subset a.R a.I

end Accs

/-! ## The VDR: versions, guarded updates, single writer -/

/-- Parties, identified by their authenticated sender account (I6). -/
abbrev Party := Nat

/-- A guard: the formula `Φ` and the global version of the state `Σ_g` it was proved against. -/
structure Guard where
  formula : Formula
  provedAt : Nat

/-- A submitted update with the new accumulator values its sender proposes. Only the values
the update writes are read (`Accs.write`). -/
structure Tx where
  sender : Party
  update : Update
  values : Accs
  guard : Option Guard

/-- The checks the VDR runs. The VDR runs all of them; switching one off is a mutation that
the necessity targets use. -/
structure Checks where
  sender : Bool := true
  issue : Bool := true
  step : Bool := true
  consistency : Bool := true
  subset : Bool := true
  guard : Bool := true

def Checks.all : Checks := {}

/-- The VDR of one registry: the stored accumulator values and the public log of
accepted updates. The global version is the log's length. -/
structure Vdr where
  acc : Accs
  log : List Update

/-- The group version of `S` after a log: the number of its updates of IDs in `S`. -/
def groupVersion (log : List Update) (S : Group) : Nat :=
  log.countP (fun u => S.contains u.cred)

/-- The public revocation log: revoked IDs in the order they were revoked. -/
def revocationLog (log : List Update) : List CredId :=
  log.filterMap Update.revokedCred

namespace Vdr

def init : Vdr := ⟨Accs.init, []⟩

/-- def:global-version. -/
def version (c : Vdr) : Nat := c.log.length

/-- The current registry state, read from the stored accumulators. -/
def reg (c : Vdr) : RegState := c.acc.reg

/-- The authenticated history: the registry state at global version `v`. -/
def history (c : Vdr) (v : Nat) : RegState := replay RegState.init (c.log.take v)

/-- def:fresh-guard. `Σ_g` is `c.history g.provedAt`, `Σ'` is the current state, and
"proved in `Σ_g`" is `Σ_g ⊨ Φ` (ideal proofs). Case (a) uses the semantic stability
of def:stable-formulas. -/
def FreshGuard (c : Vdr) (g : Guard) : Prop :=
  g.formula.Closed ∧ g.provedAt ≤ c.version ∧ Models (c.history g.provedAt) g.formula ∧
  (g.formula.Stable ∨
    (g.formula.AllGroups ∧
      ∀ S, Domain.group S ∈ g.formula.domains →
        groupVersion (c.log.take g.provedAt) S = groupVersion c.log S) ∨
    g.provedAt = c.version)

/-- Acceptance: the sender is the issuer (S1), the proposed values pass the on-chain checks,
and the guard, if any, is fresh (def:fresh-guard). There is no check of the version the values
were computed from: the step and issuance checks compare them with the stored values. -/
def Accepts (k : Checks) (issuer : Party) (c : Vdr) (t : Tx) : Prop :=
  (k.sender → t.sender = issuer) ∧
  (k.issue → Accs.IssueCheck c.acc t.update t.values) ∧
  (k.step → Accs.StepCheck c.acc t.update t.values) ∧
  (k.consistency → Accs.ConsistencyCheck (Accs.write t.update c.acc t.values)) ∧
  (k.subset → Accs.SubsetCheck (Accs.write t.update c.acc t.values)) ∧
  (k.guard → ∀ g, t.guard = some g → FreshGuard c g)

open Classical in
/-- An accepted update writes its values and is appended to the log; a rejected one
changes nothing. -/
noncomputable def submit (k : Checks) (issuer : Party) (c : Vdr) (t : Tx) : Vdr :=
  if Accepts k issuer c t then ⟨Accs.write t.update c.acc t.values, c.log ++ [t.update]⟩
  else c

/-- The VDR after a sequence of submitted transactions, from the initial state. -/
noncomputable def runWith (k : Checks) (issuer : Party) (txs : List Tx) : Vdr :=
  txs.foldl (submit k issuer) init

/-- The VDR that runs every check. -/
noncomputable def run (issuer : Party) (txs : List Tx) : Vdr := runWith Checks.all issuer txs

end Vdr

/-! ## Independent registries (S10) -/

abbrev RegId := Nat

/-- A transaction addressed to one registry. -/
structure SysTx where
  registry : RegId
  tx : Tx

/-- Every registry after a sequence of transactions; `issuers r` is the issuer of `r`. -/
noncomputable def sysRun (issuers : RegId → Party) (txs : List SysTx) : RegId → Vdr :=
  txs.foldl
    (fun sys t r =>
      if r = t.registry then Vdr.submit Checks.all (issuers r) (sys r) t.tx else sys r)
    (fun _ => Vdr.init)

/-! ## Frozen targets: paper lemmas -/

/-- lem:state-order (a)–(d). -/
def StateOrderSpec : Prop :=
  (∀ σ : RegState, σ.Le σ) ∧
  (∀ σ σ' : RegState, σ.Le σ' → σ'.Le σ → σ = σ') ∧
  (∀ σ σ' σ'' : RegState, σ.Le σ' → σ'.Le σ'' → σ.Le σ'') ∧
  RegState.init.Valid ∧ (∀ σ : RegState, RegState.init.Le σ) ∧
  (∀ (σ : RegState) (u : Update) (σ' : RegState), Step σ u σ' → σ.Le σ') ∧
  (∀ σ σ' : RegState, Reach σ σ' → σ.Le σ') ∧
  (∀ σ σ' : RegState, σ.Valid → σ'.Valid → σ.Le σ' → Reach σ σ')

/-- lem:atom-classes. -/
def AtomClassesSpec : Prop :=
  Atom.revoked.Monotone ∧ ¬ Atom.revoked.Antitone ∧
  Atom.issued.Monotone ∧ ¬ Atom.issued.Antitone ∧
  Atom.notRevoked.Antitone ∧ ¬ Atom.notRevoked.Monotone ∧
  Atom.notIssued.Antitone ∧ ¬ Atom.notIssued.Monotone

/-- lem:closure (a)–(d). -/
def ClosureSpec : Prop :=
  (∀ Φ Ψ : Formula, Φ.Stable → Ψ.Stable →
    (Formula.conj Φ Ψ).Stable ∧ (Formula.disj Φ Ψ).Stable) ∧
  (∀ Φ Ψ : Formula, Φ.CoStable → Ψ.CoStable →
    (Formula.conj Φ Ψ).CoStable ∧ (Formula.disj Φ Ψ).CoStable) ∧
  (∀ Φ : Formula,
    (Φ.Stable ↔ (Formula.neg Φ).CoStable) ∧ (Φ.CoStable ↔ (Formula.neg Φ).Stable)) ∧
  (∀ (x : Var) (D : Domain) (φ : Cond) (k : Nat), D.Fixed → φ.Stable →
    (Formula.qcond .all x D φ).Stable ∧ (Formula.qcond .ex x D φ).Stable ∧
    (Formula.qcond (.atLeast k) x D φ).Stable ∧ (Formula.qcond (.atMost k) x D φ).CoStable) ∧
  (∀ (x : Var) (D : Domain) (φ : Cond) (k : Nat), D.Fixed → φ.CoStable →
    (Formula.qcond .all x D φ).CoStable ∧ (Formula.qcond .ex x D φ).CoStable ∧
    (Formula.qcond (.atLeast k) x D φ).CoStable ∧ (Formula.qcond (.atMost k) x D φ).Stable) ∧
  (∀ (x : Var) (φ : Cond) (k : Nat), φ.Stable →
    (Formula.qcond .ex x .issued φ).Stable ∧ (Formula.qcond (.atLeast k) x .issued φ).Stable ∧
    (Formula.qcond (.atMost k) x .issued φ).CoStable) ∧
  (∀ (x : Var) (φ : Cond), φ.CoStable → (Formula.qcond .all x .issued φ).CoStable)

/-- lem:narrowing. -/
def NarrowingSpec : Prop :=
  ∀ (Φ : Formula) (σ : RegState) (u : Update) (σ' : RegState),
    Φ.Closed → (∀ D ∈ Φ.domains, D ≠ Domain.issued) → Step σ u σ' →
    (∀ D ∈ Φ.domains, ¬ D.denote σ u.cred) →
    (Models σ Φ ↔ Models σ' Φ)

/-- lem:global-version (a) and (b), with versions as positions in the VDR's log. -/
def GlobalVersionSpec : Prop :=
  ∀ (issuer : Party) (txs : List Tx) (v w : Nat),
    let c := Vdr.run issuer txs
    v ≤ c.version → w ≤ c.version →
    (c.history v = c.history w ↔ v = w) ∧ (Reach (c.history v) (c.history w) ↔ v ≤ w)

/-- lem:group-version, between two versions of the VDR's history. -/
def GroupVersionSpec : Prop :=
  ∀ (issuer : Party) (txs : List Tx) (v w : Nat) (Φ : Formula),
    let c := Vdr.run issuer txs
    v ≤ w → w ≤ c.version → Φ.Closed → Φ.AllGroups →
    (∀ S, Domain.group S ∈ Φ.domains →
      groupVersion (c.log.take v) S = groupVersion (c.log.take w) S) →
    (Models (c.history v) Φ ↔ Models (c.history w) Φ)

/-- lem:fresh-guard, against the current state of the VDR. -/
def FreshGuardSpec : Prop :=
  ∀ (issuer : Party) (txs : List Tx) (g : Guard),
    let c := Vdr.run issuer txs
    c.FreshGuard g → Models c.reg g.formula

/-- lem:representation: the honest values of an enabled update represent the next state. -/
def RepresentationSpec : Prop :=
  ∀ (a : Accs) (σ : RegState) (u : Update) (σ' : RegState),
    σ.Valid → a.Represents σ → Step σ u σ' → (a.update u).Represents σ'

/-- Missing from the paper: the on-chain checks accept exactly the honest values of an enabled
update. This links sec:plain-comparison to def:accumulator-updates. -/
def ChecksExactSpec : Prop :=
  ∀ (a : Accs) (σ : RegState) (u : Update) (p : Accs),
    σ.Valid → a.Represents σ →
    ((Accs.IssueCheck a u p ∧ Accs.StepCheck a u p ∧
        Accs.ConsistencyCheck (Accs.write u a p) ∧ Accs.SubsetCheck (Accs.write u a p)) ↔
      (u.Enabled σ ∧ Accs.write u a p = a.update u))

/-- The checks are complete on the VDR: an issuer's enabled, unguarded update with the honest
values is accepted in every reachable VDR. -/
def HonestUpdateSpec : Prop :=
  ∀ (issuer : Party) (txs : List Tx) (u : Update),
    let c := Vdr.run issuer txs
    u.Enabled c.reg → Vdr.Accepts Checks.all issuer c ⟨issuer, u, c.acc.update u, none⟩

/-! ## Frozen targets: design-level claims (tab:design-claims)

The claims whose necessity targets switch a check off are stated for any `Checks`
(`…With k`); the claim target is the instance `Checks.all`. -/

/-- S1 Single writer: a transaction from anyone but the issuer changes nothing. -/
def S1SingleWriterWith (k : Checks) : Prop :=
  ∀ (issuer : Party) (pre : List Tx) (t : Tx),
    t.sender ≠ issuer → Vdr.runWith k issuer (pre ++ [t]) = Vdr.runWith k issuer pre

def S1SingleWriterSpec : Prop := S1SingleWriterWith Checks.all

/-- S2 Lifecycle discipline: `A ⊆ I`, `R̃ ⊆ I`, `A ∪ R̃ = I`; no update is accepted twice;
every revocation in the log follows the issuance of the same ID; only an active credential
can be revoked; only a fresh ID can be issued. -/
def S2LifecycleWith (k : Checks) : Prop :=
  ∀ (issuer : Party) (txs : List Tx),
    let c := Vdr.runWith k issuer txs
    IdSet.Subset c.acc.A c.acc.I ∧ IdSet.Subset c.acc.R c.acc.I ∧
    (∀ y, c.acc.I y ↔ c.acc.A y ∨ c.acc.R y) ∧
    c.log.Nodup ∧
    (∀ (j : Nat) (y : CredId), c.log[j]? = some (Update.revoke y) →
      ∃ i < j, c.log[i]? = some (Update.issue y)) ∧
    (∀ (t : Tx) (y : CredId), t.update = Update.revoke y → Vdr.Accepts k issuer c t →
      c.acc.A y) ∧
    (∀ (t : Tx) (y : CredId), t.update = Update.issue y → Vdr.Accepts k issuer c t →
      ¬ c.acc.I y)

def S2LifecycleSpec : Prop := S2LifecycleWith Checks.all

/-- S3 Monotone growth: `I` and `R̃` only grow; a credential leaves the active set only
by being revoked, and a revoked credential is never active again. -/
def S3MonotoneWith (k : Checks) : Prop :=
  ∀ (issuer : Party) (pre post : List Tx) (y : CredId),
    let c := Vdr.runWith k issuer pre; let c' := Vdr.runWith k issuer (pre ++ post)
    (c.acc.I y → c'.acc.I y) ∧ (c.acc.R y → c'.acc.R y) ∧
    (c.acc.A y → ¬ c'.acc.A y → c'.acc.R y) ∧ (c.acc.R y → ¬ c'.acc.A y)

def S3MonotoneSpec : Prop := S3MonotoneWith Checks.all

/-- S4 Public state and revocation log: the ordered revocation log lists exactly the
members of `R̃`, each once, and only grows by appending. -/
def S4RevocationLogSpec : Prop :=
  ∀ (issuer : Party) (pre post : List Tx),
    let c := Vdr.run issuer pre; let c' := Vdr.run issuer (pre ++ post)
    (∀ y, c.acc.R y ↔ y ∈ revocationLog c.log) ∧ (revocationLog c.log).Nodup ∧
    revocationLog c.log <+: revocationLog c'.log

/-- S5 Log-bound updates: every logged update is enabled in the state the log prefix
determines, the stored values represent the state the whole log determines, and an update
that fails a check changes nothing. -/
def S5LogBoundSpec : Prop :=
  (∀ (issuer : Party) (txs : List Tx),
    let c := Vdr.run issuer txs
    (∀ (j : Nat) (u : Update),
      c.log[j]? = some u → u.Enabled (replay RegState.init (c.log.take j))) ∧
    c.acc.Represents (replay RegState.init c.log)) ∧
  (∀ (issuer : Party) (pre : List Tx) (t : Tx),
    ¬ Vdr.Accepts Checks.all issuer (Vdr.run issuer pre) t →
    Vdr.run issuer (pre ++ [t]) = Vdr.run issuer pre)

/-- S6 Two-sided, exclusive status: no ID is in `R̃` at some state and in `A` at the same
or any later state. -/
def S6ExclusiveWith (k : Checks) : Prop :=
  ∀ (issuer : Party) (pre post : List Tx) (y : CredId),
    ¬ ((Vdr.runWith k issuer pre).acc.R y ∧ (Vdr.runWith k issuer (pre ++ post)).acc.A y)

def S6ExclusiveSpec : Prop := S6ExclusiveWith Checks.all

/-- S7 Freshness by monotonicity, on the VDR: a stable statement proved against any earlier
authentic state stays an acceptable guard in every later state; a statement that is not
stable can be true in an earlier authentic state and false in the current one. -/
def S7FreshnessSpec : Prop :=
  (∀ (issuer : Party) (pre post : List Tx) (g : Guard),
    let c := Vdr.run issuer pre
    g.formula.Closed → g.formula.Stable → g.provedAt ≤ c.version →
    Models (c.history g.provedAt) g.formula →
    (Vdr.run issuer (pre ++ post)).FreshGuard g) ∧
  (∀ Φ : Formula, Φ.Closed → ¬ Φ.Stable →
    ∃ (issuer : Party) (txs : List Tx) (v : Nat),
      v ≤ (Vdr.run issuer txs).version ∧ Models ((Vdr.run issuer txs).history v) Φ ∧
      ¬ Models (Vdr.run issuer txs).reg Φ)

/-- The running example's policy: every transaction that revokes a member of `S` carries
the guard `reservationGuard S`. -/
def ReservationPolicy (S : Group) (txs : List Tx) : Prop :=
  ∀ t ∈ txs, ∀ y ∈ S, t.update = Update.revoke y →
    ∃ g, t.guard = some g ∧ g.formula = reservationGuard S

/-- S8 Atomic guarded updates, in the reading the design supports: a guarded update takes
effect only in a state where its guard holds; and in the running example, with every
revocation of a member of `S` guarded by `∀ x ∈ S. NotRevoked(x)`, at most one member of `S`
is ever revoked, under any interleaving and any proof versions. -/
def S8GuardedUpdateWith (k : Checks) : Prop :=
  (∀ (issuer : Party) (pre : List Tx) (t : Tx) (g : Guard),
    t.guard = some g → Vdr.Accepts k issuer (Vdr.runWith k issuer pre) t →
    Models (Vdr.runWith k issuer pre).reg g.formula) ∧
  (∀ (issuer : Party) (txs : List Tx) (S : Group), ReservationPolicy S txs →
    ∀ y z : CredId, y ∈ S → z ∈ S →
      (Vdr.runWith k issuer txs).acc.R y → (Vdr.runWith k issuer txs).acc.R z → y = z)

def S8GuardedUpdateSpec : Prop := S8GuardedUpdateWith Checks.all

/-- S10 Independent partitions: each registry evolves exactly as if only the transactions
addressed to it had been submitted. -/
def S10PartitionsSpec : Prop :=
  ∀ (issuers : RegId → Party) (txs : List SysTx) (r : RegId),
    sysRun issuers txs r =
      Vdr.run (issuers r) ((txs.filter (fun t => t.registry == r)).map SysTx.tx)

/-- S11 Authenticated history (proposed claim): versions only grow, the state at every
version stays the same as the log grows, and the stored values encode the state at the
current version. -/
def S11HistorySpec : Prop :=
  ∀ (issuer : Party) (pre post : List Tx),
    let c := Vdr.run issuer pre; let c' := Vdr.run issuer (pre ++ post)
    c.version ≤ c'.version ∧
    (∀ v, v ≤ c.version → c'.history v = c.history v) ∧
    c.acc.Represents (c.history c.version)

/-! ## Frozen targets: every check is needed

Switching one check off makes a named claim false. -/

def SenderCheckNeededSpec : Prop := ¬ S1SingleWriterWith { Checks.all with sender := false }

def IssueCheckNeededSpec : Prop := ¬ S3MonotoneWith { Checks.all with issue := false }

def StepCheckNeededSpec : Prop := ¬ S3MonotoneWith { Checks.all with step := false }

def ConsistencyCheckNeededSpec : Prop :=
  ¬ S6ExclusiveWith { Checks.all with consistency := false }

def SubsetCheckNeededSpec : Prop := ¬ S2LifecycleWith { Checks.all with subset := false }

def GuardCheckNeededSpec : Prop := ¬ S8GuardedUpdateWith { Checks.all with guard := false }

/-! ## Frozen targets: witnesses -/

/-- S8's literal wording fails, case (a): a guard that is not over groups only, proved against
an earlier state that differs from the current one, is accepted. -/
def StaleStableGuardWitness : Prop :=
  ∃ (issuer : Party) (pre : List Tx) (t : Tx) (g : Guard),
    t.guard = some g ∧ Vdr.Accepts Checks.all issuer (Vdr.run issuer pre) t ∧
    ¬ g.formula.AllGroups ∧ (Vdr.run issuer pre).history g.provedAt ≠ (Vdr.run issuer pre).reg

/-- S8's literal wording and S7's "must be proved against the current state" fail, case (b):
a guard that is not stable, proved against an earlier state that differs from the current one,
is accepted. -/
def StaleVolatileGuardWitness : Prop :=
  ∃ (issuer : Party) (pre : List Tx) (t : Tx) (g : Guard),
    t.guard = some g ∧ Vdr.Accepts Checks.all issuer (Vdr.run issuer pre) t ∧
    ¬ g.formula.Stable ∧ (Vdr.run issuer pre).history g.provedAt ≠ (Vdr.run issuer pre).reg

/-- Alice and Bob reserve against the same state with guards proved at the same version: both
transactions are acceptable there. After Alice's is accepted, Bob's is rejected whatever values
it carries, and his guard is false. -/
def AliceBobWitness : Prop :=
  ∃ (issuer : Party) (pre : List Tx) (S : Group) (tA tB : Tx) (gA gB : Guard) (y z : CredId),
    y ≠ z ∧ y ∈ S ∧ z ∈ S ∧ tA.update = Update.revoke y ∧ tB.update = Update.revoke z ∧
    tA.guard = some gA ∧ tB.guard = some gB ∧
    gA.formula = reservationGuard S ∧ gB.formula = reservationGuard S ∧
    gA.provedAt = gB.provedAt ∧
    Vdr.Accepts Checks.all issuer (Vdr.run issuer pre) tA ∧
    Vdr.Accepts Checks.all issuer (Vdr.run issuer pre) tB ∧
    (∀ p : Accs,
      ¬ Vdr.Accepts Checks.all issuer (Vdr.run issuer (pre ++ [tA])) { tB with values := p }) ∧
    ¬ Models (Vdr.run issuer (pre ++ [tA])).reg (reservationGuard S)

/-- Without the policy, S8's bound fails: two members of a group end up revoked. -/
def UnguardedRaceWitness : Prop :=
  ∃ (issuer : Party) (txs : List Tx) (S : Group) (y z : CredId),
    y ≠ z ∧ y ∈ S ∧ z ∈ S ∧ (Vdr.run issuer txs).acc.R y ∧ (Vdr.run issuer txs).acc.R z

/-- S8's bound is reached: under the policy, a member of the group can be revoked. -/
def OneReservationWitness : Prop :=
  ∃ (issuer : Party) (txs : List Tx) (S : Group) (y : CredId),
    ReservationPolicy S txs ∧ y ∈ S ∧ (Vdr.run issuer txs).acc.R y

/-- "Exactly one" does not hold: two reservations acceptable against the same state are both
rejected, whatever values they carry, after an issuance into the group, although the guard
still holds. -/
def BothRejectedWitness : Prop :=
  ∃ (issuer : Party) (pre mid : List Tx) (S : Group) (tA tB : Tx) (gA gB : Guard),
    tA.guard = some gA ∧ tB.guard = some gB ∧
    gA.formula = reservationGuard S ∧ gB.formula = reservationGuard S ∧
    Vdr.Accepts Checks.all issuer (Vdr.run issuer pre) tA ∧
    Vdr.Accepts Checks.all issuer (Vdr.run issuer pre) tB ∧
    (∀ p : Accs,
      ¬ Vdr.Accepts Checks.all issuer (Vdr.run issuer (pre ++ mid)) { tA with values := p }) ∧
    (∀ p : Accs,
      ¬ Vdr.Accepts Checks.all issuer (Vdr.run issuer (pre ++ mid)) { tB with values := p }) ∧
    Models (Vdr.run issuer (pre ++ mid)).reg (reservationGuard S)

/-- The checks reject stale values without a version check: an enabled update from the
issuer, with the honest values of an earlier state, is rejected. -/
def StaleValuesWitness : Prop :=
  ∃ (issuer : Party) (pre : List Tx) (t : Tx) (v : Nat),
    v < (Vdr.run issuer pre).version ∧ t.sender = issuer ∧ t.guard = none ∧
    t.values = (Accs.ofState ((Vdr.run issuer pre).history v)).update t.update ∧
    t.update.Enabled (Vdr.run issuer pre).reg ∧
    ¬ Vdr.Accepts Checks.all issuer (Vdr.run issuer pre) t

end Lifecycle
