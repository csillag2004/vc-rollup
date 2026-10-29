import Model

/-!
# Every check is needed

For each check, a concrete run of the VDR with that check switched off that falsifies the
claim the check carries. Issuer `0` sends every transaction, and every transaction other than
the one that exploits the missing check carries the honest values. Helpers live in
`Lifecycle.Necessity`; the targets are in `Lifecycle`. This module does not import
`Lifecycle.Witnesses`.
-/

namespace Lifecycle

namespace Necessity

/-! ## Generic facts about submitting transactions, for any set of checks -/

theorem submit_pos {k : Checks} {i : Party} {c : Vdr} {t : Tx} (h : Vdr.Accepts k i c t) :
    Vdr.submit k i c t = ⟨Accs.write t.update c.acc t.values, c.log ++ [t.update]⟩ := by
  unfold Vdr.submit; rw [if_pos h]

/-- Issuer `0`'s unguarded transaction applying `u` with the honest values computed from `a`. -/
def honest (a : Accs) (u : Update) : Tx := ⟨0, u, a.update u, none⟩

theorem honest_issue_accepts (k : Checks) (a : Accs) (log : List Update) (y : CredId)
    (hy : ¬ a.I y) (hc : Accs.ConsistencyCheck a) (hs : Accs.SubsetCheck a) :
    Vdr.Accepts k 0 ⟨a, log⟩ (honest a (.issue y)) := by
  refine ⟨fun _ => rfl, fun _ => ?_, fun _ => trivial, fun _ => hc, fun _ => ?_, ?_⟩
  · exact ⟨hy, fun _ => Iff.rfl⟩
  · exact fun z hz => Or.inr (hs z hz)
  · intro _ g hg; cases hg

theorem honest_revoke_accepts (k : Checks) (a : Accs) (log : List Update) (y : CredId)
    (hy : a.I y) (hr : ¬ a.Arev y) (hc : Accs.ConsistencyCheck a) (hs : Accs.SubsetCheck a) :
    Vdr.Accepts k 0 ⟨a, log⟩ (honest a (.revoke y)) := by
  refine ⟨fun _ => rfl, fun _ => trivial, fun _ => ?_, fun _ => ?_, fun _ => ?_, ?_⟩
  · exact ⟨hr, fun _ => Iff.rfl⟩
  · exact fun z => or_congr Iff.rfl (hc z)
  · rintro z (rfl | hz)
    · exact hy
    · exact hs z hz
  · intro _ g hg; cases hg

theorem submit_honest {k : Checks} {a : Accs} {log : List Update} {u : Update}
    (h : Vdr.Accepts k 0 ⟨a, log⟩ (honest a u)) :
    Vdr.submit k 0 ⟨a, log⟩ (honest a u) = ⟨a.update u, log ++ [u]⟩ := by
  rw [submit_pos h]; cases u <;> rfl

theorem init_eq : Vdr.init = ⟨Accs.init, []⟩ := rfl

theorem init_consistent : Accs.ConsistencyCheck Accs.init := fun _ => Iff.rfl

theorem init_subset : Accs.SubsetCheck Accs.init := fun _ hz => hz

/-! ## Common states: issue `0`, then issue `1` -/

def a1 : Accs := Accs.init.update (.issue 0)
def a2 : Accs := a1.update (.issue 1)

def i0 : Tx := honest Accs.init (.issue 0)
def i1 : Tx := honest a1 (.issue 1)

theorem step_i0 (k : Checks) : Vdr.submit k 0 Vdr.init i0 = ⟨a1, [.issue 0]⟩ := by
  rw [init_eq]
  exact submit_honest (honest_issue_accepts k _ _ 0 (fun h => h) init_consistent init_subset)

theorem a1_consistent : Accs.ConsistencyCheck a1 := fun _ => Iff.rfl

theorem a1_subset : Accs.SubsetCheck a1 := fun _ hz => hz.elim

theorem step_i1 (k : Checks) :
    Vdr.submit k 0 ⟨a1, [.issue 0]⟩ i1 = ⟨a2, [.issue 0, .issue 1]⟩ :=
  submit_honest (honest_issue_accepts k a1 _ 1
    (by simp [a1, Accs.update, Accs.init, IdSet.insert, IdSet.empty]) a1_consistent a1_subset)

/-! ## Sender check off: a transaction from party `1` is accepted -/

def kSender : Checks := { Checks.all with sender := false }

def tSender : Tx := ⟨1, .issue 0, Accs.init.update (.issue 0), none⟩

theorem accepts_tSender : Vdr.Accepts kSender 0 Vdr.init tSender := by
  refine ⟨fun h => absurd h (by decide), fun _ => ?_, fun _ => trivial, fun _ => init_consistent,
    fun _ => fun z hz => Or.inr hz, ?_⟩
  · exact ⟨fun h => h, fun _ => Iff.rfl⟩
  · intro _ g hg; cases hg

/-! ## Issuance check off: an issuance drops `0` from `I` -/

def kIssue : Checks := { Checks.all with issue := false }

/-- Issues `1` and proposes `I = {1}`. -/
def tIssue : Tx := ⟨0, .issue 1, ⟨fun z => z = 1, IdSet.empty, IdSet.empty⟩, none⟩

theorem accepts_tIssue : Vdr.Accepts kIssue 0 ⟨a1, [.issue 0]⟩ tIssue := by
  refine ⟨fun _ => rfl, fun h => absurd h (by decide), fun _ => trivial, fun _ => fun _ => Iff.rfl,
    fun _ => fun _ hz => False.elim hz, ?_⟩
  intro _ g hg; cases hg

/-! ## Step check off: a revocation drops `0` from `R̃` -/

def kStep : Checks := { Checks.all with step := false }

def r0 : Tx := honest a1 (.revoke 0)
def b2 : Accs := a1.update (.revoke 0)

/-- Revokes `0` again and proposes `Arev = R = ∅`. -/
def tStep : Tx := ⟨0, .revoke 0, ⟨IdSet.empty, IdSet.empty, IdSet.empty⟩, none⟩

theorem step_r0 (k : Checks) :
    Vdr.submit k 0 ⟨a1, [.issue 0]⟩ r0 = ⟨b2, [.issue 0, .revoke 0]⟩ :=
  submit_honest (honest_revoke_accepts k a1 _ 0 (Or.inl rfl) (fun h => h) a1_consistent a1_subset)

theorem accepts_tStep : Vdr.Accepts kStep 0 ⟨b2, [.issue 0, .revoke 0]⟩ tStep := by
  refine ⟨fun _ => rfl, fun _ => trivial, fun h => absurd h (by decide), fun _ => fun _ => Iff.rfl,
    fun _ => fun _ hz => False.elim hz, ?_⟩
  intro _ g hg; cases hg

/-! ## Consistency check off: `1` ends up in both `R̃` and `A` -/

def kConsistency : Checks := { Checks.all with consistency := false }

/-- Revokes `0` and proposes `Arev = {0}`, `R = {0, 1}`. -/
def tConsistency : Tx :=
  ⟨0, .revoke 0, ⟨IdSet.empty, fun z => z = 0, fun z => z = 0 ∨ z = 1⟩, none⟩

theorem accepts_tConsistency :
    Vdr.Accepts kConsistency 0 ⟨a2, [.issue 0, .issue 1]⟩ tConsistency := by
  refine ⟨fun _ => rfl, fun _ => trivial, fun _ => ?_, fun h => absurd h (by decide), fun _ => ?_, ?_⟩
  · simp [Accs.StepCheck, tConsistency, a2, a1, Accs.update, Accs.init, IdSet.empty]
  · intro z hz
    have hz' : z = 0 ∨ z = 1 := hz
    show IdSet.insert 1 (IdSet.insert 0 IdSet.empty) z
    rcases hz' with rfl | rfl
    · exact Or.inr (Or.inl rfl)
    · exact Or.inl rfl
  · intro _ g hg; cases hg

/-! ## Subset check off: a never-issued ID is revoked -/

def kSubset : Checks := { Checks.all with subset := false }

/-- Revokes `5`, never issued, and proposes `Arev = R = {5}`. -/
def tSubset : Tx := ⟨0, .revoke 5, ⟨IdSet.empty, fun z => z = 5, fun z => z = 5⟩, none⟩

theorem accepts_tSubset : Vdr.Accepts kSubset 0 Vdr.init tSubset := by
  refine ⟨fun _ => rfl, fun _ => trivial, fun _ => ?_, fun _ => fun _ => Iff.rfl,
    fun h => absurd h (by decide), ?_⟩
  · simp [Accs.StepCheck, tSubset, Vdr.init, Accs.init, IdSet.empty]
  · intro _ g hg; cases hg

/-! ## Guard check off: an update with a false guard is accepted -/

def kGuard : Checks := { Checks.all with guard := false }

/-- `∃ x ∈ []. ⊤`, false in every state. -/
def gFalse : Guard := ⟨.qcond .ex 0 (.group []) .tt, 0⟩

def tGuard : Tx := ⟨0, .issue 0, Accs.init.update (.issue 0), some gFalse⟩

theorem accepts_tGuard : Vdr.Accepts kGuard 0 Vdr.init tGuard :=
  ⟨fun _ => rfl, fun _ => ⟨fun h => h, fun _ => Iff.rfl⟩, fun _ => trivial,
    fun _ => init_consistent, fun _ => fun z hz => Or.inr hz, fun h => absurd h (by decide)⟩

end Necessity

open Necessity in
theorem sender_check_needed : SenderCheckNeededSpec := by
  intro h
  have h1 : Vdr.submit kSender 0 Vdr.init tSender = Vdr.init := h 0 [] tSender (by decide)
  rw [submit_pos accepts_tSender] at h1
  have := congrArg (fun c : Vdr => c.log.length) h1
  simp [Vdr.init] at this

open Necessity in
theorem issue_check_needed : IssueCheckNeededSpec := by
  intro h
  replace h : S3MonotoneWith kIssue := h
  have h1 := (h 0 [i0] [tIssue] 0).1
  have e1 : Vdr.runWith kIssue 0 [i0] = ⟨a1, [.issue 0]⟩ := step_i0 kIssue
  have e2 : Vdr.runWith kIssue 0 ([i0] ++ [tIssue]) =
      ⟨Accs.write tIssue.update a1 tIssue.values, [.issue 0] ++ [tIssue.update]⟩ := by
    show Vdr.submit kIssue 0 (Vdr.submit kIssue 0 Vdr.init i0) tIssue = _
    rw [step_i0, submit_pos accepts_tIssue]
  rw [e1, e2] at h1
  have h2 := h1 (Or.inl rfl)
  simp [Accs.write, tIssue] at h2

open Necessity in
theorem step_check_needed : StepCheckNeededSpec := by
  intro h
  replace h : S3MonotoneWith kStep := h
  have h1 := (h 0 [i0, r0] [tStep] 0).2.1
  have e1 : Vdr.runWith kStep 0 [i0, r0] = ⟨b2, [.issue 0, .revoke 0]⟩ := by
    show Vdr.submit kStep 0 (Vdr.submit kStep 0 Vdr.init i0) r0 = _
    rw [step_i0, step_r0]
  have e2 : Vdr.runWith kStep 0 ([i0, r0] ++ [tStep]) =
      ⟨Accs.write tStep.update b2 tStep.values, [.issue 0, .revoke 0] ++ [tStep.update]⟩ := by
    show Vdr.submit kStep 0 (Vdr.submit kStep 0 (Vdr.submit kStep 0 Vdr.init i0) r0) tStep = _
    rw [step_i0, step_r0, submit_pos accepts_tStep]
  rw [e1, e2] at h1
  have h2 := h1 (Or.inl rfl)
  simp [Accs.write, tStep, IdSet.empty] at h2

open Necessity in
theorem consistency_check_needed : ConsistencyCheckNeededSpec := by
  intro h
  replace h : S6ExclusiveWith kConsistency := h
  have e : Vdr.runWith kConsistency 0 [i0, i1, tConsistency] =
      ⟨Accs.write (.revoke 0) a2 tConsistency.values, [.issue 0, .issue 1] ++ [.revoke 0]⟩ := by
    show Vdr.submit kConsistency 0 (Vdr.submit kConsistency 0
      (Vdr.submit kConsistency 0 Vdr.init i0) i1) tConsistency = _
    rw [step_i0, step_i1, submit_pos accepts_tConsistency]
    rfl
  have e' : Vdr.runWith kConsistency 0 ([i0, i1, tConsistency] ++ []) =
      ⟨Accs.write (.revoke 0) a2 tConsistency.values, [.issue 0, .issue 1] ++ [.revoke 0]⟩ := e
  apply h 0 [i0, i1, tConsistency] [] 1
  rw [e, e']
  simp [Accs.write, Accs.A, tConsistency, a2, a1, Accs.update, Accs.init, IdSet.insert,
    IdSet.empty]

open Necessity in
theorem subset_check_needed : SubsetCheckNeededSpec := by
  intro h
  replace h : S2LifecycleWith kSubset := h
  have h1 := (h 0 [tSubset]).2.1 5
  have e : Vdr.runWith kSubset 0 [tSubset] =
      ⟨Accs.write tSubset.update Accs.init tSubset.values, [] ++ [tSubset.update]⟩ := by
    show Vdr.submit kSubset 0 Vdr.init tSubset = _
    rw [submit_pos accepts_tSubset]
    rfl
  rw [e] at h1
  have h2 := h1 rfl
  simp [Accs.write, Accs.init, tSubset, IdSet.empty] at h2

open Necessity in
theorem guard_check_needed : GuardCheckNeededSpec := by
  intro h
  replace h : S8GuardedUpdateWith kGuard := h
  have h1 : Models Vdr.init.reg gFalse.formula := h.1 0 [] tGuard gFalse rfl accepts_tGuard
  simp [Models, gFalse, Formula.holds, Quant.holds, Domain.denote] at h1

end Lifecycle
