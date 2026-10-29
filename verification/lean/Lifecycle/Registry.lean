import Model

/-!
# Registry layer: the state order and the atom classes

`state_order` (lem:state-order) and `atom_classes` (lem:atom-classes). Helper lemmas live in
`Lifecycle.Registry`.
-/

namespace Lifecycle

namespace Registry

/-- Registry states with pointwise-equal sets are equal. -/
theorem ext {σ τ : RegState} (hi : ∀ y, σ.iss y ↔ τ.iss y) (hr : ∀ y, σ.rev y ↔ τ.rev y) :
    σ = τ := by
  cases σ with
  | mk i r =>
    cases τ with
    | mk i' r' =>
      have h1 : i = i' := funext fun y => propext (hi y)
      have h2 : r = r' := funext fun y => propext (hr y)
      subst h1
      subst h2
      rfl

theorem le_refl (σ : RegState) : σ.Le σ := ⟨fun _ h => h, fun _ h => h⟩

theorem le_antisymm {σ σ' : RegState} (h : σ.Le σ') (h' : σ'.Le σ) : σ = σ' :=
  ext (fun y => ⟨h.1 y, h'.1 y⟩) (fun y => ⟨h.2 y, h'.2 y⟩)

theorem le_trans {σ σ' σ'' : RegState} (h : σ.Le σ') (h' : σ'.Le σ'') : σ.Le σ'' :=
  ⟨fun y hy => h'.1 y (h.1 y hy), fun y hy => h'.2 y (h.2 y hy)⟩

theorem init_valid : RegState.init.Valid :=
  ⟨⟨[], fun _ => ⟨False.elim, fun h => nomatch h⟩⟩,
   ⟨[], fun _ => ⟨False.elim, fun h => nomatch h⟩⟩,
   fun _ h => h⟩

theorem init_le (σ : RegState) : RegState.init.Le σ :=
  ⟨fun _ h => False.elim h, fun _ h => False.elim h⟩

/-- An update only adds to the sets. -/
theorem le_apply (u : Update) (σ : RegState) : σ.Le (u.apply σ) := by
  cases u with
  | issue y => exact ⟨fun _ hz => Or.inr hz, fun _ hz => hz⟩
  | revoke y => exact ⟨fun _ hz => hz, fun _ hz => Or.inr hz⟩

theorem step_le {σ σ' : RegState} {u : Update} (h : Step σ u σ') : σ.Le σ' := by
  obtain ⟨_, rfl⟩ := h
  exact le_apply u σ

theorem reach_le {σ σ' : RegState} (h : Reach σ σ') : σ.Le σ' := by
  induction h with
  | refl => exact le_refl _
  | tail _ hs ih => exact le_trans ih (step_le hs)

theorem reach_trans {a b c : RegState} (h1 : Reach a b) (h2 : Reach b c) : Reach a c := by
  induction h2 with
  | refl => exact h1
  | tail _ hs ih => exact Reach.tail ih hs

theorem reach_head {a b c : RegState} {u : Update} (hs : Step a u b) (h : Reach b c) :
    Reach a c :=
  reach_trans (Reach.tail (Reach.refl a) hs) h

/-- Issuing the members of `l` that are not yet issued reaches a state whose issued set gains
exactly `l` and whose revoked set is unchanged. -/
theorem issue_all (l : List CredId) : ∀ τ : RegState, ∃ τ', Reach τ τ' ∧
    (∀ y, τ'.iss y ↔ τ.iss y ∨ y ∈ l) ∧ (∀ y, τ'.rev y ↔ τ.rev y) := by
  induction l with
  | nil =>
    intro τ
    exact ⟨τ, Reach.refl τ, fun y => by simp, fun _ => Iff.rfl⟩
  | cons x l ih =>
    intro τ
    by_cases hx : τ.iss x
    · obtain ⟨τ', hr, hi, hv⟩ := ih τ
      refine ⟨τ', hr, fun y => ?_, hv⟩
      rw [hi y, List.mem_cons]
      constructor
      · rintro (h | h)
        · exact Or.inl h
        · exact Or.inr (Or.inr h)
      · rintro (h | rfl | h)
        · exact Or.inl h
        · exact Or.inl hx
        · exact Or.inr h
    · obtain ⟨τ', hr, hi, hv⟩ := ih ((Update.issue x).apply τ)
      refine ⟨τ', reach_head (u := .issue x) ⟨hx, rfl⟩ hr, fun y => ?_, hv⟩
      rw [hi y, List.mem_cons]
      show ((y = x ∨ τ.iss y) ∨ y ∈ l) ↔ τ.iss y ∨ y = x ∨ y ∈ l
      constructor
      · rintro ((h | h) | h)
        · exact Or.inr (Or.inl h)
        · exact Or.inl h
        · exact Or.inr (Or.inr h)
      · rintro (h | h | h)
        · exact Or.inl (Or.inr h)
        · exact Or.inl (Or.inl h)
        · exact Or.inr h

/-- Revoking the members of `l` that are not yet revoked, all of them issued, reaches a state
whose revoked set gains exactly `l` and whose issued set is unchanged. -/
theorem revoke_all (l : List CredId) : ∀ τ : RegState, (∀ y ∈ l, τ.iss y) → ∃ τ', Reach τ τ' ∧
    (∀ y, τ'.iss y ↔ τ.iss y) ∧ (∀ y, τ'.rev y ↔ τ.rev y ∨ y ∈ l) := by
  induction l with
  | nil =>
    intro τ _
    exact ⟨τ, Reach.refl τ, fun _ => Iff.rfl, fun y => by simp⟩
  | cons x l ih =>
    intro τ hl
    have hl' : ∀ y ∈ l, τ.iss y := fun y hy => hl y (List.mem_cons_of_mem x hy)
    by_cases hx : τ.rev x
    · obtain ⟨τ', hr, hi, hv⟩ := ih τ hl'
      refine ⟨τ', hr, hi, fun y => ?_⟩
      rw [hv y, List.mem_cons]
      constructor
      · rintro (h | h)
        · exact Or.inl h
        · exact Or.inr (Or.inr h)
      · rintro (h | rfl | h)
        · exact Or.inl h
        · exact Or.inl hx
        · exact Or.inr h
    · obtain ⟨τ', hr, hi, hv⟩ := ih ((Update.revoke x).apply τ) hl'
      refine ⟨τ', reach_head (u := .revoke x) ⟨⟨hl x List.mem_cons_self, hx⟩, rfl⟩ hr, hi, fun y => ?_⟩
      rw [hv y, List.mem_cons]
      show ((y = x ∨ τ.rev y) ∨ y ∈ l) ↔ τ.rev y ∨ y = x ∨ y ∈ l
      constructor
      · rintro ((h | h) | h)
        · exact Or.inr (Or.inl h)
        · exact Or.inl h
        · exact Or.inr (Or.inr h)
      · rintro (h | h | h)
        · exact Or.inl (Or.inr h)
        · exact Or.inl (Or.inl h)
        · exact Or.inr h

/-- lem:state-order (d): every larger valid state is reachable. Only the target's validity is
used: its lists bound the issuances and revocations. -/
theorem reach_of_le {σ σ' : RegState} (hv' : σ'.Valid) (hle : σ.Le σ') : Reach σ σ' := by
  obtain ⟨⟨li, hli⟩, ⟨lr, hlr⟩, hsub⟩ := hv'
  obtain ⟨τ1, r1, i1, v1⟩ := issue_all li σ
  have hiss : ∀ y ∈ lr, τ1.iss y :=
    fun y hy => (i1 y).2 (Or.inr ((hli y).1 (hsub y ((hlr y).2 hy))))
  obtain ⟨τ2, r2, i2, v2⟩ := revoke_all lr τ1 hiss
  have heq : τ2 = σ' := by
    apply ext
    · intro y
      rw [i2 y, i1 y]
      constructor
      · rintro (h | h)
        · exact hle.1 y h
        · exact (hli y).2 h
      · intro h
        exact Or.inr ((hli y).1 h)
    · intro y
      rw [v2 y, v1 y]
      constructor
      · rintro (h | h)
        · exact hle.2 y h
        · exact (hlr y).2 h
      · intro h
        exact Or.inr ((hlr y).1 h)
  subst heq
  exact reach_trans r1 r2

/-- The valid state `({0}, {0})`: credential `0` issued and revoked. -/
def σ00 : RegState := ⟨fun y => y = 0, fun y => y = 0⟩

/-- The valid state `({0}, ∅)`: credential `0` issued and active. -/
def σ0 : RegState := ⟨fun y => y = 0, IdSet.empty⟩

theorem σ00_valid : σ00.Valid :=
  ⟨⟨[0], fun y => by simp [σ00]⟩, ⟨[0], fun y => by simp [σ00]⟩, fun _ h => h⟩

theorem σ0_valid : σ0.Valid :=
  ⟨⟨[0], fun y => by simp [σ0]⟩, ⟨[], fun _ => ⟨False.elim, fun h => nomatch h⟩⟩,
   fun _ h => False.elim h⟩

theorem init_le_σ00 : RegState.init.Le σ00 := init_le σ00

theorem init_le_σ0 : RegState.init.Le σ0 := init_le σ0

end Registry

open Registry in
/-- lem:state-order. -/
theorem state_order : StateOrderSpec :=
  ⟨le_refl,
   fun _ _ h h' => le_antisymm h h',
   fun _ _ _ h h' => le_trans h h',
   init_valid,
   init_le,
   fun _ _ _ h => step_le h,
   fun _ _ h => reach_le h,
   fun _ _ _ hv' hle => reach_of_le hv' hle⟩

open Registry in
/-- lem:atom-classes. The counterexamples go from `Σ₀` to `({0}, {0})` and to `({0}, ∅)`. -/
theorem atom_classes : AtomClassesSpec := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro σ σ' y _ _ hle h
    exact hle.2 y h
  · intro h
    exact h RegState.init σ00 0 init_valid σ00_valid init_le_σ00 (fun h => nomatch h) rfl
  · intro σ σ' y _ _ hle h
    exact hle.1 y h
  · intro h
    exact h RegState.init σ0 0 init_valid σ0_valid init_le_σ0 (fun h => nomatch h) rfl
  · intro σ σ' y _ _ hle h h'
    exact h (fun hr => h' (hle.2 y hr))
  · intro h
    exact h RegState.init σ00 0 init_valid σ00_valid init_le_σ00 (fun h => nomatch h) rfl
  · intro σ σ' y _ _ hle h h'
    exact h (fun hr => h' (hle.1 y hr))
  · intro h
    exact h RegState.init σ0 0 init_valid σ0_valid init_le_σ0 (fun h => nomatch h) rfl

end Lifecycle
