import Model

/-!
# Formula layer: closure and narrowing

`closure` (lem:closure) and `narrowing` (lem:narrowing). Helper lemmas live in
`Lifecycle.Formulas`. This module does not import `Lifecycle.Registry`.
-/

namespace Lifecycle

namespace Formulas

/-! ## Domains and quantifiers -/

/-- A domain other than `Issued` denotes the same set in every state. -/
theorem denote_ne_issued {D : Domain} (h : D ≠ Domain.issued) (σ σ' : RegState) :
    D.denote σ = D.denote σ' := by
  cases D with
  | group _ => rfl
  | presented _ => rfl
  | issued => exact absurd rfl h

/-- A fixed domain denotes the same set in every state. -/
theorem denote_fixed {D : Domain} (h : D.Fixed) (σ σ' : RegState) :
    D.denote σ = D.denote σ' := by
  cases D with
  | group _ => rfl
  | presented _ => rfl
  | issued => exact False.elim h

/-- `∃≥k` is monotone in the domain and the condition: the same witness list serves. -/
theorem atLeast_mono {k : Nat} {D D' : IdSet} {p p' : CredId → Prop}
    (h : ∀ y, D y → p y → D' y ∧ p' y) : AtLeast k D p → AtLeast k D' p' := by
  rintro ⟨l, hnd, hlen, hl⟩
  exact ⟨l, hnd, hlen, fun y hy => h y (hl y hy).1 (hl y hy).2⟩

/-- A quantifier only reads its condition on the members of its domain. -/
theorem quant_congr (Q : Quant) {D : IdSet} {p p' : CredId → Prop}
    (h : ∀ y, D y → (p y ↔ p' y)) : Q.holds D p ↔ Q.holds D p' := by
  have hal : ∀ k, AtLeast k D p ↔ AtLeast k D p' := fun _ =>
    ⟨atLeast_mono fun y hy hp => ⟨hy, (h y hy).1 hp⟩,
     atLeast_mono fun y hy hp => ⟨hy, (h y hy).2 hp⟩⟩
  cases Q with
  | all => exact ⟨fun H y hy => (h y hy).1 (H y hy), fun H y hy => (h y hy).2 (H y hy)⟩
  | ex =>
    exact ⟨fun ⟨y, hy, hp⟩ => ⟨y, hy, (h y hy).1 hp⟩, fun ⟨y, hy, hp⟩ => ⟨y, hy, (h y hy).2 hp⟩⟩
  | atLeast k => exact hal k
  | atMost k => exact not_congr (hal (k + 1))

/-! ## lem:closure -/

theorem stable_conj {Φ Ψ : Formula} (hΦ : Φ.Stable) (hΨ : Ψ.Stable) :
    (Formula.conj Φ Ψ).Stable :=
  fun σ σ' hv hv' hle h => ⟨hΦ σ σ' hv hv' hle h.1, hΨ σ σ' hv hv' hle h.2⟩

theorem stable_disj {Φ Ψ : Formula} (hΦ : Φ.Stable) (hΨ : Ψ.Stable) :
    (Formula.disj Φ Ψ).Stable :=
  fun σ σ' hv hv' hle h => h.elim (fun h => Or.inl (hΦ σ σ' hv hv' hle h))
    (fun h => Or.inr (hΨ σ σ' hv hv' hle h))

theorem costable_conj {Φ Ψ : Formula} (hΦ : Φ.CoStable) (hΨ : Ψ.CoStable) :
    (Formula.conj Φ Ψ).CoStable :=
  fun σ σ' hv hv' hle h h' => h
    ⟨Classical.byContradiction fun hn => hΦ σ σ' hv hv' hle hn h'.1,
     Classical.byContradiction fun hn => hΨ σ σ' hv hv' hle hn h'.2⟩

theorem costable_disj {Φ Ψ : Formula} (hΦ : Φ.CoStable) (hΨ : Ψ.CoStable) :
    (Formula.disj Φ Ψ).CoStable :=
  fun σ σ' hv hv' hle h h' => h'.elim
    (hΦ σ σ' hv hv' hle (fun hn => h (Or.inl hn)))
    (hΨ σ σ' hv hv' hle (fun hn => h (Or.inr hn)))

theorem stable_iff_neg_costable (Φ : Formula) : Φ.Stable ↔ (Formula.neg Φ).CoStable :=
  ⟨fun hs σ σ' hv hv' hle h h' => h' (hs σ σ' hv hv' hle (Classical.byContradiction h)),
   fun hc σ σ' hv hv' hle h =>
    Classical.byContradiction fun hn => hc σ σ' hv hv' hle (fun hn' => hn' h) hn⟩

theorem costable_iff_neg_stable (Φ : Formula) : Φ.CoStable ↔ (Formula.neg Φ).Stable :=
  ⟨fun h => h, fun h => h⟩

/-- A co-stable condition, read contrapositively: true in the larger state, true before. -/
theorem costable_back {φ : Cond} (hφ : φ.CoStable) {σ σ' : RegState} {ρ : Env}
    (hv : σ.Valid) (hv' : σ'.Valid) (hle : σ.Le σ') (h : φ.holds σ' ρ) : φ.holds σ ρ :=
  Classical.byContradiction fun hn => hφ σ σ' ρ hv hv' hle hn h

/-- Fixed domain, stable condition: `∀`, `∃`, `∃≥k` stable, `∃≤k` co-stable. -/
theorem fixed_stable (x : Var) (D : Domain) (φ : Cond) (k : Nat) (hD : D.Fixed)
    (hφ : φ.Stable) :
    (Formula.qcond .all x D φ).Stable ∧ (Formula.qcond .ex x D φ).Stable ∧
    (Formula.qcond (.atLeast k) x D φ).Stable ∧ (Formula.qcond (.atMost k) x D φ).CoStable := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro σ σ' hv hv' hle h y hy
    rw [denote_fixed hD σ' σ] at hy
    exact hφ σ σ' _ hv hv' hle (h y hy)
  · intro σ σ' hv hv' hle h
    obtain ⟨y, hy, hp⟩ := h
    refine ⟨y, ?_, hφ σ σ' _ hv hv' hle hp⟩
    rw [denote_fixed hD σ' σ]
    exact hy
  · intro σ σ' hv hv' hle h
    refine atLeast_mono (fun y hy hp => ⟨?_, hφ σ σ' _ hv hv' hle hp⟩) h
    rw [denote_fixed hD σ' σ]
    exact hy
  · intro σ σ' hv hv' hle h h'
    refine h fun hal => h' (atLeast_mono (fun y hy hp => ⟨?_, hφ σ σ' _ hv hv' hle hp⟩) hal)
    rw [denote_fixed hD σ' σ]
    exact hy

/-- Fixed domain, co-stable condition: `∀`, `∃`, `∃≥k` co-stable, `∃≤k` stable. -/
theorem fixed_costable (x : Var) (D : Domain) (φ : Cond) (k : Nat) (hD : D.Fixed)
    (hφ : φ.CoStable) :
    (Formula.qcond .all x D φ).CoStable ∧ (Formula.qcond .ex x D φ).CoStable ∧
    (Formula.qcond (.atLeast k) x D φ).CoStable ∧ (Formula.qcond (.atMost k) x D φ).Stable := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro σ σ' hv hv' hle h h'
    refine h fun y hy => costable_back hφ hv hv' hle (h' y ?_)
    rw [denote_fixed hD σ' σ]
    exact hy
  · intro σ σ' hv hv' hle h h'
    obtain ⟨y, hy, hp⟩ := h'
    refine h ⟨y, ?_, costable_back hφ hv hv' hle hp⟩
    rw [denote_fixed hD σ σ']
    exact hy
  · intro σ σ' hv hv' hle h h'
    refine h (atLeast_mono (fun y hy hp => ⟨?_, costable_back hφ hv hv' hle hp⟩) h')
    rw [denote_fixed hD σ σ']
    exact hy
  · intro σ σ' hv hv' hle h h'
    refine h (atLeast_mono (fun y hy hp => ⟨?_, costable_back hφ hv hv' hle hp⟩) h')
    rw [denote_fixed hD σ σ']
    exact hy

/-- Domain `Issued`, stable condition: `∃`, `∃≥k` stable, `∃≤k` co-stable. -/
theorem issued_stable (x : Var) (φ : Cond) (k : Nat) (hφ : φ.Stable) :
    (Formula.qcond .ex x .issued φ).Stable ∧ (Formula.qcond (.atLeast k) x .issued φ).Stable ∧
    (Formula.qcond (.atMost k) x .issued φ).CoStable := by
  refine ⟨?_, ?_, ?_⟩
  · intro σ σ' hv hv' hle h
    obtain ⟨y, hy, hp⟩ := h
    exact ⟨y, hle.1 y hy, hφ σ σ' _ hv hv' hle hp⟩
  · intro σ σ' hv hv' hle h
    exact atLeast_mono (fun y hy hp => ⟨hle.1 y hy, hφ σ σ' _ hv hv' hle hp⟩) h
  · intro σ σ' hv hv' hle h h'
    exact h fun hal =>
      h' (atLeast_mono (fun y hy hp => ⟨hle.1 y hy, hφ σ σ' _ hv hv' hle hp⟩) hal)

/-- Domain `Issued`, co-stable condition: `∀` co-stable. -/
theorem issued_costable (x : Var) (φ : Cond) (hφ : φ.CoStable) :
    (Formula.qcond .all x .issued φ).CoStable := by
  intro σ σ' hv hv' hle h h'
  exact h fun y hy => costable_back hφ hv hv' hle (h' y (hle.1 y hy))

/-! ## lem:narrowing -/

/-- An update changes the atoms of its own credential ID only. -/
theorem atom_apply_ne (a : Atom) (u : Update) (σ : RegState) {y : CredId} (hy : y ≠ u.cred) :
    a.holds (u.apply σ) y ↔ a.holds σ y := by
  cases u with
  | issue c =>
    have hy' : ¬ y = c := hy
    cases a <;> simp [Atom.holds, Update.apply, IdSet.insert, hy']
  | revoke c =>
    have hy' : ¬ y = c := hy
    cases a <;> simp [Atom.holds, Update.apply, IdSet.insert, hy']

/-- Binding `x` to an ID other than `c` keeps every variable of `x :: bound` away from `c`. -/
theorem bindVar_avoid {ρ : Env} {bound : List Var} {c : CredId} (x : Var) {y : CredId}
    (hρ : ∀ z ∈ bound, ρ z ≠ c) (hy : y ≠ c) : ∀ z ∈ x :: bound, bindVar ρ x y z ≠ c := by
  intro z hz
  unfold bindVar
  split
  · exact hy
  · rename_i hne
    exact hρ z ((List.mem_cons.1 hz).resolve_left hne)

/-- A condition whose variables avoid the updated ID has the same truth value after the
update. -/
theorem cond_apply (u : Update) (σ : RegState) :
    ∀ (φ : Cond) (bound : List Var) (ρ : Env), φ.Scoped bound →
      (∀ x ∈ bound, ρ x ≠ u.cred) → (φ.holds (u.apply σ) ρ ↔ φ.holds σ ρ)
  | .tt, _, _, _, _ => Iff.rfl
  | .ff, _, _, _, _ => Iff.rfl
  | .atom a x, _, _, hs, hρ => atom_apply_ne a u σ (hρ x hs)
  | .neg φ, bound, ρ, hs, hρ => not_congr (cond_apply u σ φ bound ρ hs hρ)
  | .conj φ ψ, bound, ρ, hs, hρ =>
    and_congr (cond_apply u σ φ bound ρ hs.1 hρ) (cond_apply u σ ψ bound ρ hs.2 hρ)
  | .disj φ ψ, bound, ρ, hs, hρ =>
    or_congr (cond_apply u σ φ bound ρ hs.1 hρ) (cond_apply u σ ψ bound ρ hs.2 hρ)

/-- Generalized narrowing: a formula scoped in `bound`, under an assignment that keeps `bound`
away from the updated ID, with no `Issued` domain and no domain containing that ID, has the
same truth value after the update. -/
theorem formula_apply (u : Update) (σ : RegState) :
    ∀ (Φ : Formula) (bound : List Var) (ρ : Env), Φ.Scoped bound →
      (∀ x ∈ bound, ρ x ≠ u.cred) →
      (∀ D ∈ Φ.domains, D ≠ Domain.issued) →
      (∀ D ∈ Φ.domains, ¬ D.denote σ u.cred) →
      (Φ.holds (u.apply σ) ρ ↔ Φ.holds σ ρ)
  | .qcond Q x D φ, bound, ρ, hs, hρ, hD, hn => by
    have hmem : D ∈ (Formula.qcond Q x D φ).domains := List.mem_singleton_self D
    show Q.holds (D.denote (u.apply σ)) _ ↔ Q.holds (D.denote σ) _
    rw [denote_ne_issued (hD D hmem) (u.apply σ) σ]
    apply quant_congr
    intro y hy
    have hyne : y ≠ u.cred := fun e => hn D hmem (e ▸ hy)
    exact cond_apply u σ φ (x :: bound) _ hs (bindVar_avoid x hρ hyne)
  | .qform Q x D Φ, bound, ρ, hs, hρ, hD, hn => by
    have hmem : D ∈ (Formula.qform Q x D Φ).domains := List.mem_cons_self
    have hsub : ∀ E ∈ Φ.domains, E ∈ (Formula.qform Q x D Φ).domains :=
      fun E hE => List.mem_cons_of_mem D hE
    show Q.holds (D.denote (u.apply σ)) _ ↔ Q.holds (D.denote σ) _
    rw [denote_ne_issued (hD D hmem) (u.apply σ) σ]
    apply quant_congr
    intro y hy
    have hyne : y ≠ u.cred := fun e => hn D hmem (e ▸ hy)
    exact formula_apply u σ Φ (x :: bound) _ hs (bindVar_avoid x hρ hyne)
      (fun E hE => hD E (hsub E hE)) (fun E hE => hn E (hsub E hE))
  | .neg Φ, bound, ρ, hs, hρ, hD, hn => not_congr (formula_apply u σ Φ bound ρ hs hρ hD hn)
  | .conj Φ Ψ, bound, ρ, hs, hρ, hD, hn =>
    and_congr
      (formula_apply u σ Φ bound ρ hs.1 hρ (fun E hE => hD E (List.mem_append_left _ hE))
        (fun E hE => hn E (List.mem_append_left _ hE)))
      (formula_apply u σ Ψ bound ρ hs.2 hρ (fun E hE => hD E (List.mem_append_right _ hE))
        (fun E hE => hn E (List.mem_append_right _ hE)))
  | .disj Φ Ψ, bound, ρ, hs, hρ, hD, hn =>
    or_congr
      (formula_apply u σ Φ bound ρ hs.1 hρ (fun E hE => hD E (List.mem_append_left _ hE))
        (fun E hE => hn E (List.mem_append_left _ hE)))
      (formula_apply u σ Ψ bound ρ hs.2 hρ (fun E hE => hD E (List.mem_append_right _ hE))
        (fun E hE => hn E (List.mem_append_right _ hE)))

end Formulas

open Formulas in
/-- lem:closure (a)–(d). -/
theorem closure : ClosureSpec :=
  ⟨fun _ _ hΦ hΨ => ⟨stable_conj hΦ hΨ, stable_disj hΦ hΨ⟩,
   fun _ _ hΦ hΨ => ⟨costable_conj hΦ hΨ, costable_disj hΦ hΨ⟩,
   fun Φ => ⟨stable_iff_neg_costable Φ, costable_iff_neg_stable Φ⟩,
   fun x D φ k hD hφ => fixed_stable x D φ k hD hφ,
   fun x D φ k hD hφ => fixed_costable x D φ k hD hφ,
   fun x φ k hφ => issued_stable x φ k hφ,
   fun x φ hφ => issued_costable x φ hφ⟩

/-- lem:narrowing. A closed formula is scoped in `[]`, so any assignment serves. -/
theorem narrowing : NarrowingSpec := by
  intro Φ σ u σ' hc hD hstep hn
  obtain ⟨_, rfl⟩ := hstep
  exact (Formulas.formula_apply u σ Φ [] _ hc (fun _ h => nomatch h) hD hn).symm

end Lifecycle
