import Lifecycle.Claims
import Lifecycle.Witnesses
import Lifecycle.Necessity

open Lifecycle

#check (state_order : StateOrderSpec)
/-- info: 'Lifecycle.state_order' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms state_order

#check (atom_classes : AtomClassesSpec)
/-- info: 'Lifecycle.atom_classes' depends on axioms: [propext] -/
#guard_msgs in #print axioms atom_classes

#check (closure : ClosureSpec)
/-- info: 'Lifecycle.closure' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms closure

#check (narrowing : NarrowingSpec)
/-- info: 'Lifecycle.narrowing' depends on axioms: [propext] -/
#guard_msgs in #print axioms narrowing

#check (global_version : GlobalVersionSpec)
/-- info: 'Lifecycle.global_version' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms global_version

#check (group_version : GroupVersionSpec)
/-- info: 'Lifecycle.group_version' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms group_version

#check (fresh_guard_sound : FreshGuardSpec)
/-- info: 'Lifecycle.fresh_guard_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms fresh_guard_sound

#check (representation : RepresentationSpec)
/-- info: 'Lifecycle.representation' depends on axioms: [propext] -/
#guard_msgs in #print axioms representation

#check (checks_exact : ChecksExactSpec)
/-- info: 'Lifecycle.checks_exact' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms checks_exact

#check (honest_update : HonestUpdateSpec)
/-- info: 'Lifecycle.honest_update' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms honest_update

#check (s1_single_writer : S1SingleWriterSpec)
/-- info: 'Lifecycle.s1_single_writer' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms s1_single_writer

#check (s2_lifecycle : S2LifecycleSpec)
/-- info: 'Lifecycle.s2_lifecycle' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms s2_lifecycle

#check (s3_monotone : S3MonotoneSpec)
/-- info: 'Lifecycle.s3_monotone' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms s3_monotone

#check (s4_revocation_log : S4RevocationLogSpec)
/-- info: 'Lifecycle.s4_revocation_log' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms s4_revocation_log

#check (s5_log_bound : S5LogBoundSpec)
/-- info: 'Lifecycle.s5_log_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms s5_log_bound

#check (s6_exclusive : S6ExclusiveSpec)
/-- info: 'Lifecycle.s6_exclusive' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms s6_exclusive

#check (s7_freshness : S7FreshnessSpec)
/-- info: 'Lifecycle.s7_freshness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms s7_freshness

#check (s8_guarded_update : S8GuardedUpdateSpec)
/-- info: 'Lifecycle.s8_guarded_update' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms s8_guarded_update

#check (s10_partitions : S10PartitionsSpec)
/-- info: 'Lifecycle.s10_partitions' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms s10_partitions

#check (s11_history : S11HistorySpec)
/-- info: 'Lifecycle.s11_history' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms s11_history

#check (sender_check_needed : SenderCheckNeededSpec)
/-- info: 'Lifecycle.sender_check_needed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms sender_check_needed

#check (issue_check_needed : IssueCheckNeededSpec)
/-- info: 'Lifecycle.issue_check_needed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms issue_check_needed

#check (step_check_needed : StepCheckNeededSpec)
/-- info: 'Lifecycle.step_check_needed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms step_check_needed

#check (consistency_check_needed : ConsistencyCheckNeededSpec)
/-- info: 'Lifecycle.consistency_check_needed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms consistency_check_needed

#check (subset_check_needed : SubsetCheckNeededSpec)
/-- info: 'Lifecycle.subset_check_needed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms subset_check_needed

#check (guard_check_needed : GuardCheckNeededSpec)
/-- info: 'Lifecycle.guard_check_needed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms guard_check_needed

#check (stale_stable_guard : StaleStableGuardWitness)
/-- info: 'Lifecycle.stale_stable_guard' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms stale_stable_guard

#check (stale_volatile_guard : StaleVolatileGuardWitness)
/-- info: 'Lifecycle.stale_volatile_guard' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms stale_volatile_guard

#check (alice_bob : AliceBobWitness)
/-- info: 'Lifecycle.alice_bob' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms alice_bob

#check (unguarded_race : UnguardedRaceWitness)
/-- info: 'Lifecycle.unguarded_race' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms unguarded_race

#check (one_reservation : OneReservationWitness)
/-- info: 'Lifecycle.one_reservation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms one_reservation

#check (both_rejected : BothRejectedWitness)
/-- info: 'Lifecycle.both_rejected' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms both_rejected

#check (stale_values : StaleValuesWitness)
/-- info: 'Lifecycle.stale_values' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms stale_values
