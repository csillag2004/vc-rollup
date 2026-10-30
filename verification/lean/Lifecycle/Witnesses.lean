import Model

/-!
# Witnesses

Concrete runs of the VDR behind the witness targets. Issuer `0` sends every transaction.
"Honest" values are the stored values updated by `Accs.update`, so every check reduces by
unfolding. Helpers live in `Lifecycle.Witnesses`; the targets are in `Lifecycle`.
-/

namespace Lifecycle

namespace Witnesses

/-! ## Generic facts about submitting transactions -/

theorem submit_pos {k : Checks} {i : Party} {c : Vdr} {t : Tx} (h : Vdr.Accepts k i c t) :
    Vdr.submit k i c t = ⟨Accs.write t.update c.acc t.values, c.log ++ [t.update]⟩ := by
  unfold Vdr.submit; rw [if_pos h]

theorem run_snoc (i : Party) (pre : List Tx) (t : Tx) :
    Vdr.run i (pre ++ [t]) = Vdr.submit Checks.all i (Vdr.run i pre) t := by
  simp only [Vdr.run, Vdr.runWith, List.foldl_append, List.foldl_cons, List.foldl_nil]

/-- Issuer `0`'s transaction applying `u` with the honest values computed from `a`. -/
def honest (a : Accs) (u : Update) (g : Option Guard := none) : Tx := ⟨0, u, a.update u, g⟩

theorem honest_issue_accepts (a : Accs) (log : List Update) (y : CredId) (g : Option Guard)
    (hy : ¬ a.I y) (hc : Accs.ConsistencyCheck a) (hs : Accs.SubsetCheck a)
    (hg : ∀ g', g = some g' → Vdr.FreshGuard ⟨a, log⟩ g') :
    Vdr.Accepts Checks.all 0 ⟨a, log⟩ (honest a (.issue y) g) := by
  refine ⟨fun _ => rfl, fun _ => ?_, fun _ => trivial, fun _ => hc, fun _ => ?_, fun _ => hg⟩
  · exact ⟨hy, fun _ => Iff.rfl⟩
  · exact fun z hz => Or.inr (hs z hz)

theorem honest_revoke_accepts (a : Accs) (log : List Update) (y : CredId) (g : Option Guard)
    (hy : a.I y) (hr : ¬ a.Arev y) (hc : Accs.ConsistencyCheck a) (hs : Accs.SubsetCheck a)
    (hg : ∀ g', g = some g' → Vdr.FreshGuard ⟨a, log⟩ g') :
    Vdr.Accepts Checks.all 0 ⟨a, log⟩ (honest a (.revoke y) g) := by
  refine ⟨fun _ => rfl, fun _ => trivial, fun _ => ?_, fun _ => ?_, fun _ => ?_, fun _ => hg⟩
  · exact ⟨hr, fun _ => Iff.rfl⟩
  · exact fun z => or_congr Iff.rfl (hc z)
  · rintro z (rfl | hz)
    · exact hy
    · exact hs z hz

theorem submit_honest {a : Accs} {log : List Update} {u : Update} {g : Option Guard}
    (h : Vdr.Accepts Checks.all 0 ⟨a, log⟩ (honest a u g)) :
    Vdr.submit Checks.all 0 ⟨a, log⟩ (honest a u g) = ⟨a.update u, log ++ [u]⟩ := by
  rw [submit_pos h]; cases u <;> rfl

/-! ## Formulas -/

/-- `∃ x ∈ Issued. Issued(x)`: stable, and its domain is not a group. -/
def phiIssued : Formula := .qcond .ex 0 .issued (.atom .issued 0)

theorem phiIssued_closed : phiIssued.Closed := by
  simp [phiIssued, Formula.Closed, Formula.Scoped, Cond.Scoped]

theorem phiIssued_stable : phiIssued.Stable := by
  intro σ σ' _ _ hle h
  simp only [Models, phiIssued, Formula.holds, Quant.holds, Domain.denote, Cond.holds,
    Atom.holds, bindVar, if_pos] at h ⊢
  obtain ⟨y, hy, -⟩ := h
  exact ⟨y, hle.1 y hy, hle.1 y hy⟩

theorem phiIssued_not_allGroups : ¬ phiIssued.AllGroups := by
  intro h
  obtain ⟨S, hS⟩ := h .issued (by simp [phiIssued, Formula.domains])
  cases hS

theorem reservationGuard_closed (S : Group) : (reservationGuard S).Closed := by
  simp [reservationGuard, Formula.Closed, Formula.Scoped, Cond.Scoped]

/-- `reservationGuard S` is not stable when `S` has a member `y`: it holds in `Σ₀` and fails
once `y` is issued and revoked. -/
theorem reservationGuard_not_stable {S : Group} {y : CredId} (hy : y ∈ S) :
    ¬ (reservationGuard S).Stable := by
  intro h
  have h0 : RegState.init.Valid :=
    ⟨⟨[], by simp [RegState.init, IdSet.empty]⟩, ⟨[], by simp [RegState.init, IdSet.empty]⟩,
      fun _ hz => hz⟩
  have h1 : RegState.Valid ⟨fun z => z = y, fun z => z = y⟩ :=
    ⟨⟨[y], by simp⟩, ⟨[y], by simp⟩, fun _ hz => hz⟩
  have hle : RegState.init.Le ⟨fun z => z = y, fun z => z = y⟩ :=
    ⟨fun _ hz => hz.elim, fun _ hz => hz.elim⟩
  have hm := h _ _ h0 h1 hle (by
    simp [Models, reservationGuard, Formula.holds, Quant.holds, Domain.denote, Cond.holds,
      Atom.holds, RegState.init, IdSet.empty])
  simp [Models, reservationGuard, Formula.holds, Quant.holds, Domain.denote, Cond.holds,
    Atom.holds, bindVar] at hm
  exact hm y hy rfl

/-! ## The common prefix: issue `0`, then issue `1` -/

def a1 : Accs := Accs.init.update (.issue 0)
def a2 : Accs := a1.update (.issue 1)

def i0 : Tx := honest Accs.init (.issue 0)
def i1 : Tx := honest a1 (.issue 1)
def pre : List Tx := [i0, i1]

def v1 : Vdr := ⟨a1, [.issue 0]⟩
def v2 : Vdr := ⟨a2, [.issue 0, .issue 1]⟩

theorem init_eq : Vdr.init = ⟨Accs.init, []⟩ := rfl

theorem step_i0 : Vdr.submit Checks.all 0 Vdr.init i0 = v1 := by
  rw [init_eq]
  exact submit_honest (honest_issue_accepts _ _ 0 none (by simp [Accs.init, IdSet.empty])
    (by simp [Accs.ConsistencyCheck, Accs.init]) (by simp [Accs.SubsetCheck, IdSet.Subset,
      Accs.init, IdSet.empty]) (by simp))

theorem step_i1 : Vdr.submit Checks.all 0 v1 i1 = v2 :=
  submit_honest (honest_issue_accepts a1 [.issue 0] 1 none
    (by simp [a1, Accs.init, Accs.update, IdSet.insert, IdSet.empty])
    (by simp [Accs.ConsistencyCheck, a1, Accs.update, Accs.init])
    (by simp [Accs.SubsetCheck, IdSet.Subset, a1, Accs.update, Accs.init, IdSet.empty])
    (by simp))

theorem run_pre : Vdr.run 0 pre = v2 := by
  show Vdr.submit Checks.all 0 (Vdr.submit Checks.all 0 Vdr.init i0) i1 = v2
  rw [step_i0, step_i1]

/-- The history of the common prefix and its current state, evaluated. -/
theorem v2_history_1 : v2.history 1 = ⟨IdSet.insert 0 IdSet.empty, IdSet.empty⟩ := rfl

theorem v2_history_2 :
    v2.history 2 = ⟨IdSet.insert 1 (IdSet.insert 0 IdSet.empty), IdSet.empty⟩ := rfl

theorem v2_reg : v2.reg = ⟨IdSet.insert 1 (IdSet.insert 0 IdSet.empty), IdSet.empty⟩ := rfl

theorem v2_history_1_ne : v2.history 1 ≠ v2.reg := by
  intro h
  have := congrArg (fun σ : RegState => σ.iss 1) h
  simp [v2_history_1, v2_reg, IdSet.insert, IdSet.empty] at this

theorem a2_consistent : Accs.ConsistencyCheck a2 := by
  simp [Accs.ConsistencyCheck, a2, a1, Accs.update, Accs.init]

theorem a2_subset : Accs.SubsetCheck a2 := by
  simp [Accs.SubsetCheck, IdSet.Subset, a2, a1, Accs.update, Accs.init, IdSet.empty]

/-- A reservation guard holds in every state with no revoked ID. -/
theorem models_reservationGuard_of_rev_empty (S : Group) (σ : RegState)
    (h : σ.rev = IdSet.empty) : Models σ (reservationGuard S) := by
  simp [Models, reservationGuard, Formula.holds, Quant.holds, Domain.denote, Cond.holds,
    Atom.holds, h, IdSet.empty]

/-! ## Case (a): a stable guard proved against an earlier state -/

def gStable : Guard := ⟨phiIssued, 1⟩
def tStable : Tx := honest a2 (.issue 2) (some gStable)

theorem accepts_stable : Vdr.Accepts Checks.all 0 v2 tStable := by
  refine honest_issue_accepts a2 _ 2 _ (by simp [a2, a1, Accs.update, Accs.init, IdSet.insert,
    IdSet.empty]) a2_consistent a2_subset ?_
  rintro g ⟨⟩
  refine ⟨phiIssued_closed, by decide, ?_, Or.inl phiIssued_stable⟩
  show Models (v2.history 1) phiIssued
  rw [v2_history_1]
  simp [Models, phiIssued, Formula.holds, Quant.holds, Domain.denote, Cond.holds, Atom.holds,
    bindVar, IdSet.insert, IdSet.empty]

/-! ## Case (b): a volatile group guard proved against an earlier state -/

def gVolatile : Guard := ⟨reservationGuard [0], 1⟩
def tVolatile : Tx := honest a2 (.issue 2) (some gVolatile)

theorem accepts_volatile : Vdr.Accepts Checks.all 0 v2 tVolatile := by
  refine honest_issue_accepts a2 _ 2 _ (by simp [a2, a1, Accs.update, Accs.init, IdSet.insert,
    IdSet.empty]) a2_consistent a2_subset ?_
  rintro g ⟨⟩
  refine ⟨reservationGuard_closed _, by decide, ?_, Or.inr (Or.inl ⟨?_, ?_⟩)⟩
  · exact models_reservationGuard_of_rev_empty _ _ rfl
  · intro D hD
    simp [gVolatile, reservationGuard, Formula.domains] at hD
    exact ⟨[0], hD⟩
  · intro S hS
    simp [gVolatile, reservationGuard, Formula.domains] at hS
    subst hS
    rfl

/-! ## Alice and Bob reserve against the same state -/

def gAB : Guard := ⟨reservationGuard [0, 1], 2⟩
def tA : Tx := honest a2 (.revoke 0) (some gAB)
def tB : Tx := honest a2 (.revoke 1) (some gAB)

def a3 : Accs := a2.update (.revoke 0)
def v3 : Vdr := ⟨a3, [.issue 0, .issue 1, .revoke 0]⟩

theorem fresh_gAB : Vdr.FreshGuard v2 gAB :=
  ⟨reservationGuard_closed _, by decide, models_reservationGuard_of_rev_empty _ _ rfl,
    Or.inr (Or.inr rfl)⟩

theorem accepts_tA : Vdr.Accepts Checks.all 0 v2 tA := by
  refine honest_revoke_accepts a2 _ 0 _ (by simp [a2, a1, Accs.update, Accs.init, IdSet.insert])
    (by simp [a2, a1, Accs.update, Accs.init, IdSet.empty]) a2_consistent a2_subset ?_
  rintro g ⟨⟩
  exact fresh_gAB

theorem accepts_tB : Vdr.Accepts Checks.all 0 v2 tB := by
  refine honest_revoke_accepts a2 _ 1 _ (by simp [a2, a1, Accs.update, Accs.init, IdSet.insert])
    (by simp [a2, a1, Accs.update, Accs.init, IdSet.empty]) a2_consistent a2_subset ?_
  rintro g ⟨⟩
  exact fresh_gAB

theorem run_pre_tA : Vdr.run 0 (pre ++ [tA]) = v3 := by
  rw [run_snoc, run_pre]
  exact submit_honest accepts_tA

/-- After a revocation of a member of `[0, 1]`, a reservation guard proved at version `2` is
no longer fresh: it is not stable, the group version moved, and the global version moved. -/
theorem not_fresh_v3 : ¬ Vdr.FreshGuard v3 gAB := by
  rintro ⟨-, -, -, hst | ⟨-, hgv⟩ | hv⟩
  · exact reservationGuard_not_stable (y := 0) (by simp) hst
  · exact absurd (hgv [0, 1] (by simp [gAB, reservationGuard, Formula.domains])) (by decide)
  · exact absurd hv (by decide)

theorem v3_violates : ¬ Models v3.reg (reservationGuard [0, 1]) := by
  intro h
  simp [Models, reservationGuard, Formula.holds, Quant.holds, Domain.denote, Cond.holds,
    Atom.holds, bindVar, v3, Vdr.reg, Accs.reg, a3, a2, a1, Accs.update, Accs.init,
    IdSet.insert, IdSet.empty] at h

/-! ## Two unguarded revocations of one group -/

def r0 : Tx := honest a2 (.revoke 0)
def r1 : Tx := honest a3 (.revoke 1)
def a4 : Accs := a3.update (.revoke 1)
def v4 : Vdr := ⟨a4, [.issue 0, .issue 1, .revoke 0, .revoke 1]⟩

theorem step_r0 : Vdr.submit Checks.all 0 v2 r0 = v3 :=
  submit_honest (honest_revoke_accepts a2 _ 0 none
    (by simp [a2, a1, Accs.update, Accs.init, IdSet.insert])
    (by simp [a2, a1, Accs.update, Accs.init, IdSet.empty]) a2_consistent a2_subset (by simp))

theorem step_r1 : Vdr.submit Checks.all 0 v3 r1 = v4 :=
  submit_honest (honest_revoke_accepts a3 _ 1 none
    (by simp [a3, a2, a1, Accs.update, Accs.init, IdSet.insert])
    (by simp [a3, a2, a1, Accs.update, Accs.init, IdSet.insert, IdSet.empty])
    (by simp [Accs.ConsistencyCheck, a3, a2, a1, Accs.update, Accs.init])
    (by simp [Accs.SubsetCheck, IdSet.Subset, a3, a2, a1, Accs.update, Accs.init,
      IdSet.insert, IdSet.empty])
    (by simp))

theorem run_race : Vdr.run 0 [i0, i1, r0, r1] = v4 := by
  show Vdr.submit Checks.all 0 (Vdr.submit Checks.all 0
    (Vdr.submit Checks.all 0 (Vdr.submit Checks.all 0 Vdr.init i0) i1) r0) r1 = v4
  rw [step_i0, step_i1, step_r0, step_r1]

/-! ## One reservation under the policy -/

def gOne : Guard := ⟨reservationGuard [0], 1⟩
def rOne : Tx := honest a1 (.revoke 0) (some gOne)
def vOne : Vdr := ⟨a1.update (.revoke 0), [.issue 0, .revoke 0]⟩

theorem step_rOne : Vdr.submit Checks.all 0 v1 rOne = vOne := by
  refine submit_honest (honest_revoke_accepts a1 _ 0 _
    (by simp [a1, Accs.update, Accs.init, IdSet.insert])
    (by simp [a1, Accs.update, Accs.init, IdSet.empty])
    (by simp [Accs.ConsistencyCheck, a1, Accs.update, Accs.init])
    (by simp [Accs.SubsetCheck, IdSet.Subset, a1, Accs.update, Accs.init, IdSet.empty]) ?_)
  rintro g ⟨⟩
  exact ⟨reservationGuard_closed _, by decide, models_reservationGuard_of_rev_empty _ _ rfl,
    Or.inr (Or.inr rfl)⟩

theorem run_one : Vdr.run 0 [i0, rOne] = vOne := by
  show Vdr.submit Checks.all 0 (Vdr.submit Checks.all 0 Vdr.init i0) rOne = vOne
  rw [step_i0, step_rOne]

theorem policy_one : ReservationPolicy [0] [i0, rOne] := by
  intro t ht y _ hu
  simp only [List.mem_cons, List.mem_nil_iff, or_false] at ht
  rcases ht with rfl | rfl
  · cases hu
  · exact ⟨_, rfl, rfl⟩

/-! ## Both reservations rejected after an issuance into the group -/

def gBoth : Guard := ⟨reservationGuard [0, 1, 2], 2⟩
def tA' : Tx := honest a2 (.revoke 0) (some gBoth)
def tB' : Tx := honest a2 (.revoke 1) (some gBoth)
def i2 : Tx := honest a2 (.issue 2)
def v3' : Vdr := ⟨a2.update (.issue 2), [.issue 0, .issue 1, .issue 2]⟩

theorem fresh_gBoth : Vdr.FreshGuard v2 gBoth :=
  ⟨reservationGuard_closed _, by decide, models_reservationGuard_of_rev_empty _ _ rfl,
    Or.inr (Or.inr rfl)⟩

theorem accepts_tA' : Vdr.Accepts Checks.all 0 v2 tA' := by
  refine honest_revoke_accepts a2 _ 0 _ (by simp [a2, a1, Accs.update, Accs.init, IdSet.insert])
    (by simp [a2, a1, Accs.update, Accs.init, IdSet.empty]) a2_consistent a2_subset ?_
  rintro g ⟨⟩
  exact fresh_gBoth

theorem accepts_tB' : Vdr.Accepts Checks.all 0 v2 tB' := by
  refine honest_revoke_accepts a2 _ 1 _ (by simp [a2, a1, Accs.update, Accs.init, IdSet.insert])
    (by simp [a2, a1, Accs.update, Accs.init, IdSet.empty]) a2_consistent a2_subset ?_
  rintro g ⟨⟩
  exact fresh_gBoth

theorem run_pre_i2 : Vdr.run 0 (pre ++ [i2]) = v3' := by
  rw [run_snoc, run_pre]
  exact submit_honest (honest_issue_accepts a2 _ 2 none
    (by simp [a2, a1, Accs.update, Accs.init, IdSet.insert, IdSet.empty])
    a2_consistent a2_subset (by simp))

theorem not_fresh_v3' : ¬ Vdr.FreshGuard v3' gBoth := by
  rintro ⟨-, -, -, hst | ⟨-, hgv⟩ | hv⟩
  · exact reservationGuard_not_stable (y := 0) (by simp) hst
  · exact absurd (hgv [0, 1, 2] (by simp [gBoth, reservationGuard, Formula.domains]))
      (by decide)
  · exact absurd hv (by decide)

end Witnesses

open Witnesses in
theorem stale_stable_guard : StaleStableGuardWitness := by
  refine ⟨0, pre, tStable, gStable, rfl, ?_, phiIssued_not_allGroups, ?_⟩
  · rw [run_pre]; exact accepts_stable
  · rw [run_pre]; exact v2_history_1_ne

open Witnesses in
theorem stale_volatile_guard : StaleVolatileGuardWitness := by
  refine ⟨0, pre, tVolatile, gVolatile, rfl, ?_, reservationGuard_not_stable (y := 0) (by simp),
    ?_⟩
  · rw [run_pre]; exact accepts_volatile
  · rw [run_pre]; exact v2_history_1_ne

open Witnesses in
theorem alice_bob : AliceBobWitness := by
  refine ⟨0, pre, [0, 1], tA, tB, gAB, gAB, 0, 1, by decide, by simp, by simp, rfl, rfl, rfl,
    rfl, rfl, rfl, rfl, ?_, ?_, ?_, ?_⟩
  · rw [run_pre]; exact accepts_tA
  · rw [run_pre]; exact accepts_tB
  · intro p h
    rw [run_pre_tA] at h
    exact not_fresh_v3 (h.2.2.2.2.2 rfl gAB rfl)
  · rw [run_pre_tA]; exact v3_violates

open Witnesses in
theorem unguarded_race : UnguardedRaceWitness := by
  refine ⟨0, [i0, i1, r0, r1], [0, 1], 0, 1, by decide, by simp, by simp, ?_, ?_⟩ <;>
  · rw [run_race]
    simp [v4, a4, a3, a2, a1, Accs.update, Accs.init, IdSet.insert]

open Witnesses in
theorem one_reservation : OneReservationWitness := by
  refine ⟨0, [i0, rOne], [0], 0, policy_one, by simp, ?_⟩
  rw [run_one]
  simp [vOne, a1, Accs.update, Accs.init, IdSet.insert]

open Witnesses in
theorem both_rejected : BothRejectedWitness := by
  refine ⟨0, pre, [i2], [0, 1, 2], tA', tB', gBoth, gBoth, rfl, rfl, rfl, rfl, ?_, ?_, ?_, ?_,
    ?_⟩
  · rw [run_pre]; exact accepts_tA'
  · rw [run_pre]; exact accepts_tB'
  · intro p h
    rw [run_pre_i2] at h
    exact not_fresh_v3' (h.2.2.2.2.2 rfl gBoth rfl)
  · intro p h
    rw [run_pre_i2] at h
    exact not_fresh_v3' (h.2.2.2.2.2 rfl gBoth rfl)
  · rw [run_pre_i2]
    exact models_reservationGuard_of_rev_empty _ _ rfl

open Witnesses in
theorem stale_values : StaleValuesWitness := by
  refine ⟨0, pre,
    ⟨0, .issue 2, (Accs.ofState ((Vdr.run 0 pre).history 1)).update (.issue 2), none⟩, 1,
    ?_, rfl, rfl, rfl, ?_, ?_⟩
  · rw [run_pre]; decide
  · rw [run_pre]
    simp [Update.Enabled, v2_reg, IdSet.insert, IdSet.empty]
  · rw [run_pre]
    intro h
    have := (h.2.1 rfl).2 1
    rw [v2_history_1] at this
    simp [Accs.ofState, Accs.update, v2, a2, a1, Accs.init, IdSet.insert, IdSet.empty] at this

end Lifecycle
