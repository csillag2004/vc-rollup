import Lifecycle.Vdr
import Lifecycle.Formulas
import Lifecycle.Registry

/-!
# Group versions, fresh guards, S7 and S8

lem:group-version follows from `narrowing`, one logged update at a time; lem:fresh-guard from
it, the stability of case (a) and the history; S7's backward half builds runs from
`state_order` (d) and `honest_update`; S8's bound is an induction over the submitted list.
-/

namespace Lifecycle

open V

namespace C

theorem gv_le_succ (c : Vdr) (j : Nat) (S : Group) :
    groupVersion (c.log.take j) S ≤ groupVersion (c.log.take (j + 1)) S := by
  simp [groupVersion, List.take_succ, List.countP_append]

theorem gv_lt_succ {c : Vdr} {j : Nat} {u : Update} (h : c.log[j]? = some u) {S : Group}
    (hS : u.cred ∈ S) :
    groupVersion (c.log.take j) S < groupVersion (c.log.take (j + 1)) S := by
  simp [groupVersion, List.take_succ, h, List.countP_append, hS]

theorem gv_mono (c : Vdr) (S : Group) (v d : Nat) :
    groupVersion (c.log.take v) S ≤ groupVersion (c.log.take (v + d)) S := by
  induction d with
  | zero => exact Nat.le_refl _
  | succ d ih => exact Nat.le_trans ih (gv_le_succ c (v + d) S)

theorem group_version_inv {c : Vdr} (hinv : Inv c) {Φ : Formula} (hc : Φ.Closed)
    (hg : Φ.AllGroups) (v d : Nat) (hle : v + d ≤ c.version)
    (heq : ∀ S, Domain.group S ∈ Φ.domains →
      groupVersion (c.log.take v) S = groupVersion (c.log.take (v + d)) S) :
    Models (c.history v) Φ ↔ Models (c.history (v + d)) Φ := by
  induction d with
  | zero => exact Iff.rfl
  | succ d ih =>
    have hlt : v + d < c.log.length := by simp only [Vdr.version] at hle; omega
    have hu : c.log[v + d]? = some c.log[v + d] := List.getElem?_eq_getElem hlt
    have heq' : ∀ S, Domain.group S ∈ Φ.domains →
        groupVersion (c.log.take v) S = groupVersion (c.log.take (v + d)) S := by
      intro S hS
      have h1 := gv_mono c S v d
      have h2 := gv_le_succ c (v + d) S
      have h3 := heq S hS
      rw [← Nat.add_assoc] at h3
      omega
    have hout : ∀ S, Domain.group S ∈ Φ.domains → c.log[v + d].cred ∉ S := by
      intro S hS hmem
      have h1 := gv_mono c S v d
      have h2 := gv_lt_succ hu hmem
      have h3 := heq S hS
      rw [← Nat.add_assoc] at h3
      omega
    rw [ih (by omega) heq', ← Nat.add_assoc, history_succ hu]
    refine narrowing Φ _ _ _ hc ?_ (step_of_enabled (hinv.enabled _ _ hu)) ?_
    · intro D hD hiss
      obtain ⟨S, rfl⟩ := hg D hD
      cases hiss
    · intro D hD hden
      obtain ⟨S, rfl⟩ := hg D hD
      exact hout S hD hden

theorem fresh_guard_inv {c : Vdr} (hinv : Inv c) {g : Guard} (h : c.FreshGuard g) :
    Models c.reg g.formula := by
  obtain ⟨hcl, hle, hm, hcase⟩ := h
  rw [reg_eq hinv, ← history_version]
  rcases hcase with hs | ⟨hg, hgv⟩ | heq
  · exact hs _ _ (history_valid hinv _) (history_valid hinv _)
      (reach_le (history_reach hinv hle)) hm
  · obtain ⟨d, hd⟩ := Nat.exists_eq_add_of_le hle
    have hgv' : ∀ S, Domain.group S ∈ g.formula.domains →
        groupVersion (c.log.take g.provedAt) S =
          groupVersion (c.log.take (g.provedAt + d)) S := by
      intro S hS
      rw [← hd, hgv S hS]
      simp [Vdr.version, List.take_length]
    rw [hd]
    exact (group_version_inv hinv hcl hg g.provedAt d (by omega) hgv').1 hm
  · rw [← heq]
    exact hm

theorem reach_run (i : Party) {σ τ : RegState} (h : Reach σ τ) :
    ∀ txs : List Tx, replay RegState.init (Vdr.runWith Checks.all i txs).log = σ →
      ∃ txs' : List Tx,
        replay RegState.init (Vdr.runWith Checks.all i (txs ++ txs')).log = τ := by
  induction h with
  | refl => exact fun txs h => ⟨[], by simpa using h⟩
  | @tail τ0 τ1 u _ hs ih =>
    intro txs h
    obtain ⟨txs', h'⟩ := ih txs h
    obtain ⟨he, rfl⟩ := hs
    have hinv := inv_run i (txs ++ txs')
    have hen : u.Enabled (Vdr.run i (txs ++ txs')).reg := by
      show u.Enabled (Vdr.runWith Checks.all i (txs ++ txs')).reg
      rw [reg_eq hinv, h']
      exact he
    have hacc : Vdr.Accepts Checks.all i (Vdr.runWith Checks.all i (txs ++ txs'))
        ⟨i, u, (Vdr.runWith Checks.all i (txs ++ txs')).acc.update u, none⟩ :=
      honest_update i (txs ++ txs') u hen
    refine ⟨txs' ++ [⟨i, u, (Vdr.runWith Checks.all i (txs ++ txs')).acc.update u, none⟩], ?_⟩
    rw [← List.append_assoc, runWith_snoc, submit_pos hacc]
    show replay RegState.init ((Vdr.runWith Checks.all i (txs ++ txs')).log ++ [u]) = _
    rw [replay_snoc, h']

/-- No two distinct members of `S` are in `R̃`. -/
def AtMostOne (S : Group) (c : Vdr) : Prop :=
  ∀ y z : CredId, y ∈ S → z ∈ S → c.acc.R y → c.acc.R z → y = z

theorem amo_submit {i : Party} {S : Group} {c : Vdr} {t : Tx} (hinv : Inv c)
    (hamo : AtMostOne S c)
    (hpol : ∀ y ∈ S, t.update = Update.revoke y →
      ∃ g, t.guard = some g ∧ g.formula = reservationGuard S) :
    AtMostOne S (Vdr.submit Checks.all i c t) := by
  by_cases h : Vdr.Accepts Checks.all i c t
  · obtain ⟨-, hw⟩ := accepted_honest hinv h
    have hfresh := (checks_of_accepts h).2.2.2.2.2
    rw [submit_pos h, hw]
    cases hu : t.update with
    | issue y => exact hamo
    | revoke y =>
      by_cases hyS : y ∈ S
      · obtain ⟨g, hg, hgf⟩ := hpol y hyS hu
        have hm := fresh_guard_inv hinv (hfresh g hg)
        rw [hgf] at hm
        have hnone : ∀ x ∈ S, ¬ c.acc.R x := by
          intro x hx hR
          simp only [Models, reservationGuard, Formula.holds, Quant.holds, Domain.denote,
            Cond.holds, Atom.holds, bindVar, Vdr.reg, Accs.reg, if_pos] at hm
          exact hm x hx hR
        intro a b ha hb hRa hRb
        simp only [Accs.update, IdSet.insert] at hRa hRb
        rcases hRa with rfl | hRa
        · rcases hRb with rfl | hRb
          · rfl
          · exact absurd hRb (hnone b hb)
        · exact absurd hRa (hnone a ha)
      · intro a b ha hb hRa hRb
        simp only [Accs.update, IdSet.insert] at hRa hRb
        rcases hRa with rfl | hRa
        · exact absurd ha hyS
        · rcases hRb with rfl | hRb
          · exact absurd hb hyS
          · exact hamo a b ha hb hRa hRb
  · rw [submit_neg h]
    exact hamo

theorem amo_foldl {i : Party} {S : Group} :
    ∀ (txs : List Tx) (c : Vdr), Inv c → AtMostOne S c → ReservationPolicy S txs →
      AtMostOne S (txs.foldl (Vdr.submit Checks.all i) c)
  | [], _, _, h, _ => h
  | t :: ts, c, hinv, h, hpol =>
    amo_foldl ts _ (inv_submit t hinv)
      (amo_submit hinv h fun y hy hu => hpol t (by simp) y hy hu)
      (fun t' ht' => hpol t' (List.mem_cons_of_mem _ ht'))

end C

open C

theorem group_version : GroupVersionSpec := by
  intro i txs v w Φ
  dsimp only
  intro hvw hw hc hg heq
  obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le hvw
  exact group_version_inv (inv_run i txs) hc hg v d hw heq

theorem fresh_guard_sound : FreshGuardSpec := by
  intro i txs g
  dsimp only
  intro h
  exact fresh_guard_inv (inv_run i txs) h

theorem s7_freshness : S7FreshnessSpec := by
  refine ⟨fun i pre post g => ?_, fun Φ _ hns => ?_⟩
  · dsimp only
    intro hcl hst hle hm
    unfold Vdr.run at hle hm ⊢
    refine ⟨hcl, Nat.le_trans hle (version_mono Checks.all i pre post), ?_, Or.inl hst⟩
    rw [history_extend i pre post hle]
    exact hm
  · refine Classical.byContradiction fun hno => hns ?_
    intro σ σ' hv hv' hle hm
    refine Classical.byContradiction fun hnm => hno ?_
    have h0 : Reach RegState.init σ :=
      state_order.2.2.2.2.2.2.2 _ _ V.valid_init hv (state_order.2.2.2.2.1 σ)
    have h01 : Reach σ σ' := state_order.2.2.2.2.2.2.2 _ _ hv hv' hle
    obtain ⟨txs1, h1⟩ := reach_run 0 h0 [] rfl
    obtain ⟨txs2, h2⟩ := reach_run 0 h01 ([] ++ txs1) h1
    simp only [List.nil_append] at h1 h2
    refine ⟨0, txs1 ++ txs2, (Vdr.runWith Checks.all 0 txs1).version, ?_, ?_, ?_⟩
    · exact version_mono Checks.all 0 txs1 txs2
    · show Models ((Vdr.runWith Checks.all 0 (txs1 ++ txs2)).history _) Φ
      rw [history_extend 0 txs1 txs2 (Nat.le_refl _), history_version, h1]
      exact hm
    · show ¬ Models (Vdr.runWith Checks.all 0 (txs1 ++ txs2)).reg Φ
      rw [reg_eq (inv_run 0 (txs1 ++ txs2)), h2]
      exact hnm

theorem s8_guarded_update : S8GuardedUpdateSpec := by
  refine ⟨fun i pre t g hg hacc => ?_, fun i txs S hpol => ?_⟩
  · exact fresh_guard_inv (inv_run i pre) ((checks_of_accepts hacc).2.2.2.2.2 g hg)
  · exact amo_foldl txs Vdr.init inv_init (fun _ _ _ _ h => h.elim) hpol

end Lifecycle
