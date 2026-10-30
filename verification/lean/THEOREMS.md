# Theorems

Status of every target in `CONTRACT.md` at the commit that adds this file. All 33 are proved; none is false or open. `Audit.lean` checks each theorem against its spec and pins the axioms below with `#guard_msgs`, so `lake build` fails if they change. `Model.lean` and `CONTRACT.md` match `frozen/spec.sha256`.

## Lemmas

| Spec | Theorem | Status | Location | Axioms |
|---|---|---|---|---|
| `StateOrderSpec` | `state_order` | proved | `Lifecycle/Registry.lean:190` | propext, Classical.choice, Quot.sound |
| `AtomClassesSpec` | `atom_classes` | proved | `Lifecycle/Registry.lean:202` | propext |
| `ClosureSpec` | `closure` | proved | `Lifecycle/Formulas.lean:237` | propext, Classical.choice, Quot.sound |
| `NarrowingSpec` | `narrowing` | proved | `Lifecycle/Formulas.lean:247` | propext |
| `GlobalVersionSpec` | `global_version` | proved | `Lifecycle/Vdr.lean:431` | propext, Classical.choice, Quot.sound |
| `GroupVersionSpec` | `group_version` | proved | `Lifecycle/Claims.lean:165` | propext, Classical.choice, Quot.sound |
| `FreshGuardSpec` | `fresh_guard_sound` | proved | `Lifecycle/Claims.lean:172` | propext, Classical.choice, Quot.sound |
| `RepresentationSpec` | `representation` | proved | `Lifecycle/Vdr.lean:169` | propext |
| `ChecksExactSpec` | `checks_exact` | proved | `Lifecycle/Vdr.lean:181` | propext, Quot.sound |
| `HonestUpdateSpec` | `honest_update` | proved | `Lifecycle/Vdr.lean:415` | propext, Classical.choice, Quot.sound |

## Design-level claims

| Spec | Theorem | Status | Location | Axioms |
|---|---|---|---|---|
| `S1SingleWriterSpec` | `s1_single_writer` | proved | `Lifecycle/Vdr.lean:454` | propext, Classical.choice, Quot.sound |
| `S2LifecycleSpec` | `s2_lifecycle` | proved | `Lifecycle/Vdr.lean:459` | propext, Classical.choice, Quot.sound |
| `S3MonotoneSpec` | `s3_monotone` | proved | `Lifecycle/Vdr.lean:491` | propext, Classical.choice, Quot.sound |
| `S4RevocationLogSpec` | `s4_revocation_log` | proved | `Lifecycle/Vdr.lean:539` | propext, Classical.choice, Quot.sound |
| `S5LogBoundSpec` | `s5_log_bound` | proved | `Lifecycle/Vdr.lean:551` | propext, Classical.choice, Quot.sound |
| `S6ExclusiveSpec` | `s6_exclusive` | proved | `Lifecycle/Vdr.lean:559` | propext, Classical.choice, Quot.sound |
| `S7FreshnessSpec` | `s7_freshness` | proved | `Lifecycle/Claims.lean:178` | propext, Classical.choice, Quot.sound |
| `S8GuardedUpdateSpec` | `s8_guarded_update` | proved | `Lifecycle/Claims.lean:204` | propext, Classical.choice, Quot.sound |
| `S10PartitionsSpec` | `s10_partitions` | proved | `Lifecycle/Vdr.lean:569` | propext, Classical.choice, Quot.sound |
| `S11HistorySpec` | `s11_history` | proved | `Lifecycle/Vdr.lean:588` | propext, Classical.choice, Quot.sound |

## Necessity

| Spec | Theorem | Status | Location | Axioms |
|---|---|---|---|---|
| `SenderCheckNeededSpec` | `sender_check_needed` | proved | `Lifecycle/Necessity.lean:169` | propext, Classical.choice, Quot.sound |
| `IssueCheckNeededSpec` | `issue_check_needed` | proved | `Lifecycle/Necessity.lean:177` | propext, Classical.choice, Quot.sound |
| `StepCheckNeededSpec` | `step_check_needed` | proved | `Lifecycle/Necessity.lean:191` | propext, Classical.choice, Quot.sound |
| `ConsistencyCheckNeededSpec` | `consistency_check_needed` | proved | `Lifecycle/Necessity.lean:207` | propext, Classical.choice, Quot.sound |
| `SubsetCheckNeededSpec` | `subset_check_needed` | proved | `Lifecycle/Necessity.lean:224` | propext, Classical.choice, Quot.sound |
| `GuardCheckNeededSpec` | `guard_check_needed` | proved | `Lifecycle/Necessity.lean:238` | propext, Classical.choice, Quot.sound |

## Witnesses

| Spec | Theorem | Status | Location | Axioms |
|---|---|---|---|---|
| `StaleStableGuardWitness` | `stale_stable_guard` | proved | `Lifecycle/Witnesses.lean:320` | propext, Classical.choice, Quot.sound |
| `StaleVolatileGuardWitness` | `stale_volatile_guard` | proved | `Lifecycle/Witnesses.lean:326` | propext, Classical.choice, Quot.sound |
| `AliceBobWitness` | `alice_bob` | proved | `Lifecycle/Witnesses.lean:333` | propext, Classical.choice, Quot.sound |
| `UnguardedRaceWitness` | `unguarded_race` | proved | `Lifecycle/Witnesses.lean:344` | propext, Classical.choice, Quot.sound |
| `OneReservationWitness` | `one_reservation` | proved | `Lifecycle/Witnesses.lean:350` | propext, Classical.choice, Quot.sound |
| `BothRejectedWitness` | `both_rejected` | proved | `Lifecycle/Witnesses.lean:356` | propext, Classical.choice, Quot.sound |
| `StaleValuesWitness` | `stale_values` | proved | `Lifecycle/Witnesses.lean:371` | propext, Classical.choice, Quot.sound |

## Reproduce

```sh
bash scripts/setup-toolchain.sh
export PATH="$PWD/tools/lean-4.23.0/bin:$PATH"
bash scripts/check.sh   # prints check.sh: OK
```

From a clean `.lake`, the gate takes about 2 seconds of build time on a laptop once the toolchain is installed.
