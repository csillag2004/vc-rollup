import Model

/-!
# The VDR under every check

Registry facts used by the VDR, the run invariant (the stored values encode the state the log
determines, every logged update was enabled, the log has no repetition), the lemmas the paper
lacks (`checks_exact`, `honest_update`), lem:representation and lem:global-version, and the
claims that need no formula lemma: S1–S6, S10, S11. `group_version`, `fresh_guard_sound` and
S7–S8 take the formula lemmas as hypotheses here and are closed in `Lifecycle.Claims`.
-/

namespace Lifecycle

namespace V

/-! ## Extensionality -/

theorem regState_ext {σ τ : RegState} (hi : ∀ y, σ.iss y ↔ τ.iss y)
    (hr : ∀ y, σ.rev y ↔ τ.rev y) : σ = τ := by
  obtain ⟨i, r⟩ := σ
  obtain ⟨i', r'⟩ := τ
  simp only [RegState.mk.injEq]
  exact ⟨funext fun y => propext (hi y), funext fun y => propext (hr y)⟩

theorem accs_ext {a b : Accs} (hi : ∀ y, a.I y ↔ b.I y) (ha : ∀ y, a.Arev y ↔ b.Arev y)
    (hr : ∀ y, a.R y ↔ b.R y) : a = b := by
  obtain ⟨i, x, r⟩ := a
  obtain ⟨i', x', r'⟩ := b
  simp only [Accs.mk.injEq]
  exact ⟨funext fun y => propext (hi y), funext fun y => propext (ha y),
    funext fun y => propext (hr y)⟩

/-! ## Replaying updates -/

theorem replay_cons (σ : RegState) (u : Update) (l : List Update) :
    replay σ (u :: l) = replay (u.apply σ) l := rfl

theorem replay_append (σ : RegState) (l l' : List Update) :
    replay σ (l ++ l') = replay (replay σ l) l' := by
  simp [replay, List.foldl_append]

theorem replay_snoc (σ : RegState) (l : List Update) (u : Update) :
    replay σ (l ++ [u]) = u.apply (replay σ l) := by
  simp [replay, List.foldl_append]

theorem le_refl (σ : RegState) : σ.Le σ := ⟨fun _ h => h, fun _ h => h⟩

theorem le_trans {σ τ ρ : RegState} (h₁ : σ.Le τ) (h₂ : τ.Le ρ) : σ.Le ρ :=
  ⟨fun y h => h₂.1 y (h₁.1 y h), fun y h => h₂.2 y (h₁.2 y h)⟩

theorem le_antisymm {σ τ : RegState} (h₁ : σ.Le τ) (h₂ : τ.Le σ) : σ = τ :=
  regState_ext (fun y => ⟨h₁.1 y, h₂.1 y⟩) (fun y => ⟨h₁.2 y, h₂.2 y⟩)

theorem apply_le (u : Update) (σ : RegState) : σ.Le (u.apply σ) := by
  cases u <;>
    exact ⟨fun y h => by simp [Update.apply, IdSet.insert, h],
      fun y h => by simp [Update.apply, IdSet.insert, h]⟩

theorem replay_le (σ : RegState) (l : List Update) : σ.Le (replay σ l) := by
  induction l generalizing σ with
  | nil => exact le_refl σ
  | cons u l ih => exact le_trans (apply_le u σ) (ih (u.apply σ))

theorem replay_le_append (σ : RegState) (l l' : List Update) :
    (replay σ l).Le (replay σ (l ++ l')) := by
  rw [replay_append]; exact replay_le _ _

theorem issue_mem_replay {y : CredId} {l : List Update} (σ : RegState)
    (h : Update.issue y ∈ l) : (replay σ l).iss y := by
  induction l generalizing σ with
  | nil => cases h
  | cons u l ih =>
    rw [replay_cons]
    rcases List.mem_cons.mp h with h | h
    · subst h; exact (replay_le _ l).1 y (by simp [Update.apply, IdSet.insert])
    · exact ih _ h

theorem revoke_mem_replay {y : CredId} {l : List Update} (σ : RegState)
    (h : Update.revoke y ∈ l) : (replay σ l).rev y := by
  induction l generalizing σ with
  | nil => cases h
  | cons u l ih =>
    rw [replay_cons]
    rcases List.mem_cons.mp h with h | h
    · subst h; exact (replay_le _ l).2 y (by simp [Update.apply, IdSet.insert])
    · exact ih _ h

theorem replay_iss_cases {σ : RegState} {l : List Update} {y : CredId}
    (h : (replay σ l).iss y) : σ.iss y ∨ Update.issue y ∈ l := by
  induction l generalizing σ with
  | nil => exact Or.inl h
  | cons u l ih =>
    rcases ih (σ := u.apply σ) h with h' | h'
    · cases u with
      | issue z =>
        simp only [Update.apply, IdSet.insert] at h'
        rcases h' with rfl | h'
        · exact Or.inr (by simp)
        · exact Or.inl h'
      | revoke z => exact Or.inl (by simpa [Update.apply] using h')
    · exact Or.inr (List.mem_cons_of_mem _ h')

theorem replay_rev_cases {σ : RegState} {l : List Update} {y : CredId}
    (h : (replay σ l).rev y) : σ.rev y ∨ Update.revoke y ∈ l := by
  induction l generalizing σ with
  | nil => exact Or.inl h
  | cons u l ih =>
    rcases ih (σ := u.apply σ) h with h' | h'
    · cases u with
      | issue z => exact Or.inl (by simpa [Update.apply] using h')
      | revoke z =>
        simp only [Update.apply, IdSet.insert] at h'
        rcases h' with rfl | h'
        · exact Or.inr (by simp)
        · exact Or.inl h'
    · exact Or.inr (List.mem_cons_of_mem _ h')

theorem init_iss_iff {l : List Update} {y : CredId} :
    (replay RegState.init l).iss y ↔ Update.issue y ∈ l := by
  constructor
  · intro h
    rcases replay_iss_cases h with h | h
    · exact absurd h (by simp [RegState.init, IdSet.empty])
    · exact h
  · exact issue_mem_replay _

theorem init_rev_iff {l : List Update} {y : CredId} :
    (replay RegState.init l).rev y ↔ Update.revoke y ∈ l := by
  constructor
  · intro h
    rcases replay_rev_cases h with h | h
    · exact absurd h (by simp [RegState.init, IdSet.empty])
    · exact h
  · exact revoke_mem_replay _

/-! ## Validity -/

theorem valid_init : RegState.init.Valid :=
  ⟨⟨[], by simp [RegState.init, IdSet.empty]⟩, ⟨[], by simp [RegState.init, IdSet.empty]⟩,
    fun _ h => h⟩

theorem valid_apply {σ : RegState} {u : Update} (hv : σ.Valid) (he : u.Enabled σ) :
    (u.apply σ).Valid := by
  obtain ⟨⟨li, hi⟩, ⟨lr, hr⟩, hs⟩ := hv
  cases u with
  | issue y =>
    refine ⟨⟨y :: li, fun z => ?_⟩, ⟨lr, fun z => ?_⟩, fun z hz => ?_⟩
    · simp [Update.apply, IdSet.insert, hi]
    · simpa [Update.apply] using hr z
    · simp only [Update.apply, IdSet.insert] at hz ⊢
      exact Or.inr (hs z hz)
  | revoke y =>
    refine ⟨⟨li, fun z => ?_⟩, ⟨y :: lr, fun z => ?_⟩, fun z hz => ?_⟩
    · simpa [Update.apply] using hi z
    · simp [Update.apply, IdSet.insert, hr]
    · simp only [Update.apply, IdSet.insert] at hz ⊢
      rcases hz with rfl | hz
      · exact he.1
      · exact hs z hz

theorem step_of_enabled {σ : RegState} {u : Update} (he : u.Enabled σ) :
    Step σ u (u.apply σ) := ⟨he, rfl⟩

end V

/-! ## The paper's lemmas about the accumulators -/

theorem representation : RepresentationSpec := by
  intro a σ u σ' _ hrep hstep
  obtain ⟨_, rfl⟩ := hstep
  obtain ⟨hI, hA, hR⟩ := hrep
  cases u with
  | issue y =>
    refine ⟨fun z => ?_, fun z => ?_, fun z => ?_⟩ <;>
      simp [Accs.update, Update.apply, IdSet.insert, hI z, hA z, hR z]
  | revoke y =>
    refine ⟨fun z => ?_, fun z => ?_, fun z => ?_⟩ <;>
      simp [Accs.update, Update.apply, IdSet.insert, hI z, hA z, hR z]

theorem checks_exact : ChecksExactSpec := by
  intro a σ u p hv hrep
  obtain ⟨hI, hA, hR⟩ := hrep
  obtain ⟨aI, aA, aR⟩ := a
  obtain ⟨pI, pA, pR⟩ := p
  simp only at hI hA hR
  cases u with
  | issue y =>
    simp only [Accs.IssueCheck, Accs.StepCheck, Accs.ConsistencyCheck, Accs.SubsetCheck,
      Accs.write, Accs.update, Update.Enabled, Accs.mk.injEq, IdSet.Subset, true_and, and_true]
    constructor
    · rintro ⟨⟨hy, hp⟩, -, -⟩
      exact ⟨fun h => hy ((hI y).2 h), funext fun z => propext (hp z)⟩
    · rintro ⟨hy, rfl⟩
      refine ⟨⟨fun h => hy ((hI y).1 h), fun z => Iff.rfl⟩, fun z => ?_, fun z hz => ?_⟩
      · rw [hA z, hR z]
      · exact Or.inr ((hI z).2 (hv.2.2 z ((hR z).1 hz)))
  | revoke y =>
    simp only [Accs.IssueCheck, Accs.StepCheck, Accs.ConsistencyCheck, Accs.SubsetCheck,
      Accs.write, Accs.update, Update.Enabled, Accs.mk.injEq, IdSet.Subset, true_and]
    constructor
    · rintro ⟨⟨hy, hp⟩, hc, hs⟩
      have hpA : pA = IdSet.insert y aA := funext fun z => propext (hp z)
      have hpR : pR = IdSet.insert y aR := by
        funext z
        apply propext
        rw [← hc z, hp z]
        simp only [IdSet.insert]
        rw [hA z, hR z]
      subst hpA hpR
      refine ⟨⟨(hI y).1 (hs y (Or.inl rfl)), fun h => hy ((hA y).2 h)⟩, rfl, rfl⟩
    · rintro ⟨⟨hiy, hry⟩, rfl, rfl⟩
      refine ⟨⟨fun h => hry ((hA y).1 h), fun z => Iff.rfl⟩, fun z => ?_, fun z hz => ?_⟩
      · simp only [IdSet.insert]; rw [hA z, hR z]
      · simp only [IdSet.insert] at hz
        rcases hz with rfl | hz
        · exact (hI _).2 hiy
        · exact (hI z).2 (hv.2.2 z ((hR z).1 hz))

/-! ## Runs and the invariant -/

namespace V

theorem submit_pos {k : Checks} {i : Party} {c : Vdr} {t : Tx} (h : Vdr.Accepts k i c t) :
    Vdr.submit k i c t = ⟨Accs.write t.update c.acc t.values, c.log ++ [t.update]⟩ := by
  simp [Vdr.submit, h]

theorem submit_neg {k : Checks} {i : Party} {c : Vdr} {t : Tx} (h : ¬ Vdr.Accepts k i c t) :
    Vdr.submit k i c t = c := by
  simp [Vdr.submit, h]

theorem runWith_append (k : Checks) (i : Party) (pre post : List Tx) :
    Vdr.runWith k i (pre ++ post) = post.foldl (Vdr.submit k i) (Vdr.runWith k i pre) := by
  simp [Vdr.runWith, List.foldl_append]

theorem runWith_snoc (k : Checks) (i : Party) (pre : List Tx) (t : Tx) :
    Vdr.runWith k i (pre ++ [t]) = Vdr.submit k i (Vdr.runWith k i pre) t := by
  simp [Vdr.runWith, List.foldl_append]

theorem foldl_log (k : Checks) (i : Party) (c : Vdr) (txs : List Tx) :
    ∃ l, (txs.foldl (Vdr.submit k i) c).log = c.log ++ l := by
  induction txs generalizing c with
  | nil => exact ⟨[], by simp⟩
  | cons t ts ih =>
    obtain ⟨l, hl⟩ := ih (Vdr.submit k i c t)
    simp only [List.foldl_cons]
    by_cases h : Vdr.Accepts k i c t
    · refine ⟨t.update :: l, ?_⟩
      rw [hl, submit_pos h]
      simp
    · exact ⟨l, by rw [hl, submit_neg h]⟩

theorem log_prefix (k : Checks) (i : Party) (pre post : List Tx) :
    ∃ l, (Vdr.runWith k i (pre ++ post)).log = (Vdr.runWith k i pre).log ++ l := by
  rw [runWith_append]; exact foldl_log _ _ _ _

/-- What every VDR that runs all checks satisfies. -/
structure Inv (c : Vdr) : Prop where
  rep : c.acc.Represents (replay RegState.init c.log)
  valid : (replay RegState.init c.log).Valid
  enabled : ∀ (j : Nat) (u : Update), c.log[j]? = some u →
    u.Enabled (replay RegState.init (c.log.take j))
  nodup : c.log.Nodup

theorem inv_init : Inv Vdr.init := by
  refine ⟨⟨fun _ => Iff.rfl, fun _ => Iff.rfl, fun _ => Iff.rfl⟩, valid_init, ?_, List.nodup_nil⟩
  intro j u h
  simp [Vdr.init] at h

theorem checks_of_accepts {i : Party} {c : Vdr} {t : Tx} (h : Vdr.Accepts Checks.all i c t) :
    t.sender = i ∧ Accs.IssueCheck c.acc t.update t.values ∧
    Accs.StepCheck c.acc t.update t.values ∧
    Accs.ConsistencyCheck (Accs.write t.update c.acc t.values) ∧
    Accs.SubsetCheck (Accs.write t.update c.acc t.values) ∧
    (∀ g, t.guard = some g → c.FreshGuard g) :=
  ⟨h.1 rfl, h.2.1 rfl, h.2.2.1 rfl, h.2.2.2.1 rfl, h.2.2.2.2.1 rfl, h.2.2.2.2.2 rfl⟩

theorem accepted_honest {i : Party} {c : Vdr} {t : Tx} (hinv : Inv c)
    (h : Vdr.Accepts Checks.all i c t) :
    t.update.Enabled (replay RegState.init c.log) ∧
      Accs.write t.update c.acc t.values = c.acc.update t.update := by
  obtain ⟨-, h1, h2, h3, h4, -⟩ := checks_of_accepts h
  exact (checks_exact c.acc _ t.update t.values hinv.valid hinv.rep).1 ⟨h1, h2, h3, h4⟩

theorem inv_submit {i : Party} {c : Vdr} (t : Tx) (hinv : Inv c) :
    Inv (Vdr.submit Checks.all i c t) := by
  by_cases h : Vdr.Accepts Checks.all i c t
  · obtain ⟨he, hw⟩ := accepted_honest hinv h
    rw [submit_pos h, hw]
    refine ⟨?_, ?_, ?_, ?_⟩
    · show (c.acc.update t.update).Represents (replay RegState.init (c.log ++ [t.update]))
      rw [replay_snoc]
      exact representation _ _ _ _ hinv.valid hinv.rep (step_of_enabled he)
    · show (replay RegState.init (c.log ++ [t.update])).Valid
      rw [replay_snoc]
      exact valid_apply hinv.valid he
    · intro j u hj
      show u.Enabled (replay RegState.init ((c.log ++ [t.update]).take j))
      simp only at hj
      rcases Nat.lt_or_ge j c.log.length with hlt | hge
      · rw [List.getElem?_append_left hlt] at hj
        rw [List.take_append_of_le_length (Nat.le_of_lt hlt)]
        exact hinv.enabled j u hj
      · rcases Nat.eq_or_lt_of_le hge with heq | hgt
        · subst heq
          rw [List.getElem?_concat_length] at hj
          cases hj
          rw [List.take_append_of_le_length (Nat.le_refl _), List.take_length]
          exact he
        · rw [List.getElem?_append_right (Nat.le_of_lt hgt)] at hj
          have hpos : j - c.log.length ≠ 0 := by omega
          obtain ⟨m, hm⟩ := Nat.exists_eq_succ_of_ne_zero hpos
          rw [hm] at hj
          simp at hj
    · show (c.log ++ [t.update]).Nodup
      rw [List.nodup_append]
      refine ⟨hinv.nodup, by simp, ?_⟩
      intro a ha b hb hab
      simp only [List.mem_singleton] at hb
      subst hb hab
      cases hu : t.update with
      | issue y =>
        rw [hu] at he ha
        exact he (issue_mem_replay _ ha)
      | revoke y =>
        rw [hu] at he ha
        exact he.2 (revoke_mem_replay _ ha)
  · rw [submit_neg h]
    exact hinv

theorem inv_foldl {i : Party} (c : Vdr) (hc : Inv c) (txs : List Tx) :
    Inv (txs.foldl (Vdr.submit Checks.all i) c) := by
  induction txs generalizing c with
  | nil => exact hc
  | cons t ts ih => exact ih _ (inv_submit t hc)

theorem inv_run (i : Party) (txs : List Tx) : Inv (Vdr.runWith Checks.all i txs) :=
  inv_foldl _ inv_init txs

theorem reg_eq {c : Vdr} (hinv : Inv c) : c.reg = replay RegState.init c.log :=
  regState_ext (fun y => hinv.rep.1 y) (fun y => hinv.rep.2.2 y)

/-! ## The authenticated history -/

theorem history_version (c : Vdr) : c.history c.version = replay RegState.init c.log := by
  simp [Vdr.history, Vdr.version, List.take_length]

theorem history_succ {c : Vdr} {j : Nat} {u : Update} (h : c.log[j]? = some u) :
    c.history (j + 1) = u.apply (c.history j) := by
  simp [Vdr.history, List.take_succ, h, replay_snoc]

theorem history_succ_none {c : Vdr} {j : Nat} (h : c.log[j]? = none) :
    c.history (j + 1) = c.history j := by
  have hge : c.log.length ≤ j := List.getElem?_eq_none_iff.mp h
  simp [Vdr.history, List.take_of_length_le hge, List.take_of_length_le (Nat.le_succ_of_le hge)]

theorem history_valid {c : Vdr} (hinv : Inv c) (j : Nat) : (c.history j).Valid := by
  induction j with
  | zero => simpa [Vdr.history, replay] using valid_init
  | succ j ih =>
    cases hj : c.log[j]? with
    | none => rw [history_succ_none hj]; exact ih
    | some u => rw [history_succ hj]; exact valid_apply ih (hinv.enabled j u hj)

theorem history_reach {c : Vdr} (hinv : Inv c) {v w : Nat} (hvw : v ≤ w) :
    Reach (c.history v) (c.history w) := by
  obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le hvw
  induction d with
  | zero => exact Reach.refl _
  | succ d ih =>
    rw [← Nat.add_assoc]
    cases hj : c.log[v + d]? with
    | none => rw [history_succ_none hj]; exact ih (Nat.le_add_right _ _)
    | some u =>
      rw [history_succ hj]
      exact Reach.tail (ih (Nat.le_add_right _ _)) (step_of_enabled (hinv.enabled _ u hj))

theorem reach_le {σ τ : RegState} (h : Reach σ τ) : σ.Le τ := by
  induction h with
  | refl => exact le_refl _
  | tail _ hs ih =>
    obtain ⟨_, rfl⟩ := hs
    exact le_trans ih (apply_le _ _)

theorem history_ne {c : Vdr} (hinv : Inv c) {a b : Nat} (hab : a < b) (hb : b ≤ c.version) :
    c.history a ≠ c.history b := by
  intro heq
  have ha : a < c.log.length := Nat.lt_of_lt_of_le hab hb
  have hu : c.log[a]? = some c.log[a] := List.getElem?_eq_getElem ha
  have he : c.log[a].Enabled (c.history a) := hinv.enabled a _ hu
  have hle : (c.history (a + 1)).Le (c.history b) := reach_le (history_reach hinv hab)
  rw [history_succ hu, ← heq] at hle
  revert he hle
  cases c.log[a] with
  | issue y => exact fun he hle => he (hle.1 y (by simp [Update.apply, IdSet.insert]))
  | revoke y => exact fun he hle => he.2 (hle.2 y (by simp [Update.apply, IdSet.insert]))

theorem history_extend (i : Party) (pre post : List Tx) {v : Nat}
    (hv : v ≤ (Vdr.runWith Checks.all i pre).version) :
    (Vdr.runWith Checks.all i (pre ++ post)).history v =
      (Vdr.runWith Checks.all i pre).history v := by
  obtain ⟨l, hl⟩ := log_prefix Checks.all i pre post
  simp only [Vdr.history, hl]
  rw [List.take_append_of_le_length hv]

theorem version_mono (k : Checks) (i : Party) (pre post : List Tx) :
    (Vdr.runWith k i pre).version ≤ (Vdr.runWith k i (pre ++ post)).version := by
  obtain ⟨l, hl⟩ := log_prefix k i pre post
  simp [Vdr.version, hl]

end V

open V

theorem honest_update : HonestUpdateSpec := by
  intro i txs u
  dsimp only
  intro he
  have hinv := inv_run i txs
  rw [show Vdr.run i txs = Vdr.runWith Checks.all i txs from rfl] at he ⊢
  rw [reg_eq hinv] at he
  have hw : Accs.write u (Vdr.runWith Checks.all i txs).acc
      ((Vdr.runWith Checks.all i txs).acc.update u) =
      (Vdr.runWith Checks.all i txs).acc.update u := by
    cases u <;> rfl
  obtain ⟨h1, h2, h3, h4⟩ :=
    (checks_exact _ _ u _ hinv.valid hinv.rep).2 ⟨he, hw⟩
  exact ⟨fun _ => rfl, fun _ => h1, fun _ => h2, fun _ => h3, fun _ => h4,
    fun _ g hg => by cases hg⟩

theorem global_version : GlobalVersionSpec := by
  intro i txs v w
  dsimp only
  intro hv hw
  have hinv := inv_run i txs
  constructor
  · constructor
    · intro heq
      rcases Nat.lt_trichotomy v w with h | h | h
      · exact absurd heq (history_ne hinv h hw)
      · exact h
      · exact absurd heq.symm (history_ne hinv h hv)
    · rintro rfl; rfl
  · constructor
    · intro hr
      refine Nat.le_of_not_lt fun hlt => ?_
      have h1 := reach_le hr
      have h2 := reach_le (history_reach hinv (Nat.le_of_lt hlt))
      exact history_ne hinv hlt hv (le_antisymm h2 h1)
    · exact history_reach hinv

/-! ## Claims S1–S6, S10, S11 -/

theorem s1_single_writer : S1SingleWriterSpec := by
  intro i pre t ht
  rw [runWith_snoc]
  exact submit_neg fun h => ht (h.1 rfl)

theorem s2_lifecycle : S2LifecycleSpec := by
  intro i txs
  dsimp only
  have hinv := inv_run i txs
  have hRI : IdSet.Subset (Vdr.runWith Checks.all i txs).acc.R
      (Vdr.runWith Checks.all i txs).acc.I :=
    fun y h => (hinv.rep.1 y).2 (hinv.valid.2.2 y ((hinv.rep.2.2 y).1 h))
  refine ⟨fun y h => h.1, hRI, fun y => ⟨fun hI => ?_, fun h => ?_⟩, hinv.nodup, ?_, ?_, ?_⟩
  · by_cases hA : (Vdr.runWith Checks.all i txs).acc.Arev y
    · exact Or.inr ((hinv.rep.2.2 y).2 ((hinv.rep.2.1 y).1 hA))
    · exact Or.inl ⟨hI, hA⟩
  · rcases h with h | h
    · exact h.1
    · exact hRI y h
  · intro j y hj
    have he := (hinv.enabled j _ hj).1
    obtain ⟨m, hm⟩ := List.mem_iff_getElem?.mp (init_iss_iff.mp he)
    rw [List.getElem?_take] at hm
    by_cases hmj : m < j
    · rw [if_pos hmj] at hm
      exact ⟨m, hmj, hm⟩
    · rw [if_neg hmj] at hm
      cases hm
  · intro t y hu h
    have he := (accepted_honest hinv h).1
    rw [hu] at he
    exact ⟨(hinv.rep.1 y).2 he.1, fun hA => he.2 ((hinv.rep.2.1 y).1 hA)⟩
  · intro t y hu h
    have h1 := (checks_of_accepts h).2.1
    rw [hu] at h1
    exact h1.1

theorem s3_monotone : S3MonotoneSpec := by
  intro i pre post y
  dsimp only
  have hinv := inv_run i pre
  have hinv' := inv_run i (pre ++ post)
  obtain ⟨l, hl⟩ := log_prefix Checks.all i pre post
  have hle := replay_le_append RegState.init (Vdr.runWith Checks.all i pre).log l
  have rep' := hinv'.rep
  rw [hl] at rep'
  refine ⟨fun h => (rep'.1 y).2 (hle.1 y ((hinv.rep.1 y).1 h)),
    fun h => (rep'.2.2 y).2 (hle.2 y ((hinv.rep.2.2 y).1 h)), fun hA hA' => ?_, fun hR hA' => ?_⟩
  · have hI' := (rep'.1 y).2 (hle.1 y ((hinv.rep.1 y).1 hA.1))
    have hX : (Vdr.runWith Checks.all i (pre ++ post)).acc.Arev y :=
      Classical.byContradiction fun hX => hA' ⟨hI', hX⟩
    exact (rep'.2.2 y).2 ((rep'.2.1 y).1 hX)
  · exact hA'.2 ((rep'.2.1 y).2 (hle.2 y ((hinv.rep.2.2 y).1 hR)))

namespace V

theorem mem_revocationLog {l : List Update} {y : CredId} :
    y ∈ revocationLog l ↔ Update.revoke y ∈ l := by
  simp only [revocationLog, List.mem_filterMap]
  constructor
  · rintro ⟨u, hu, hy⟩
    cases u with
    | issue z => simp [Update.revokedCred] at hy
    | revoke z =>
      simp only [Update.revokedCred, Option.some.injEq] at hy
      subst hy
      exact hu
  · intro h
    exact ⟨_, h, rfl⟩

theorem revocationLog_nodup {l : List Update} (h : l.Nodup) : (revocationLog l).Nodup := by
  induction l with
  | nil => simp [revocationLog]
  | cons u l ih =>
    rw [List.nodup_cons] at h
    cases u with
    | issue z =>
      simpa [revocationLog, Update.revokedCred] using ih h.2
    | revoke z =>
      simp only [revocationLog, List.filterMap_cons, Update.revokedCred]
      rw [List.nodup_cons]
      exact ⟨fun hz => h.1 (mem_revocationLog.mp hz), ih h.2⟩

end V

theorem s4_revocation_log : S4RevocationLogSpec := by
  intro i pre post
  dsimp only
  unfold Vdr.run
  have hinv := inv_run i pre
  obtain ⟨l, hl⟩ := log_prefix Checks.all i pre post
  refine ⟨fun y => ?_, revocationLog_nodup hinv.nodup, ?_⟩
  · rw [hinv.rep.2.2 y, init_rev_iff, mem_revocationLog]
  · rw [hl]
    simp only [revocationLog, List.filterMap_append]
    exact List.prefix_append _ _

theorem s5_log_bound : S5LogBoundSpec := by
  refine ⟨fun i txs => ?_, fun i pre t h => ?_⟩
  · have hinv := inv_run i txs
    exact ⟨hinv.enabled, hinv.rep⟩
  · show Vdr.runWith Checks.all i (pre ++ [t]) = Vdr.runWith Checks.all i pre
    rw [runWith_snoc]
    exact submit_neg h

theorem s6_exclusive : S6ExclusiveSpec := by
  intro i pre post y ⟨hR, hA⟩
  have hinv := inv_run i pre
  have hinv' := inv_run i (pre ++ post)
  obtain ⟨l, hl⟩ := log_prefix Checks.all i pre post
  have hle := replay_le_append RegState.init (Vdr.runWith Checks.all i pre).log l
  have rep' := hinv'.rep
  rw [hl] at rep'
  exact hA.2 ((rep'.2.1 y).2 (hle.2 y ((hinv.rep.2.2 y).1 hR)))

theorem s10_partitions : S10PartitionsSpec := by
  intro issuers txs r
  suffices h : ∀ (sys : RegId → Vdr) (ts : List SysTx),
      (ts.foldl (fun sys t r =>
          if r = t.registry then Vdr.submit Checks.all (issuers r) (sys r) t.tx else sys r)
        sys) r =
      ((ts.filter (fun t => t.registry == r)).map SysTx.tx).foldl
        (Vdr.submit Checks.all (issuers r)) (sys r) from h (fun _ => Vdr.init) txs
  intro sys ts
  induction ts generalizing sys with
  | nil => rfl
  | cons t ts ih =>
    rw [List.foldl_cons, ih]
    by_cases hr : t.registry = r
    · subst hr
      simp
    · have hr' : ¬ r = t.registry := fun h => hr h.symm
      simp [hr, hr']

theorem s11_history : S11HistorySpec := by
  intro i pre post
  dsimp only
  refine ⟨version_mono Checks.all i pre post, fun v hv => history_extend i pre post hv, ?_⟩
  rw [history_version]
  exact (inv_run i pre).rep

end Lifecycle
