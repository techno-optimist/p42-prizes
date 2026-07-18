compile_error!("SP1 guest disabled pending an externally reviewed patched dependency pin; see BUILD_PENDING.md");

// Activation design: read a full bounded objective witness, call
// p42_erdos_min_overlap_objective_core::evaluate_and_journal, and commit the
// resulting 32-byte P42_OBJECTIVE_VERDICT_JOURNAL_V2 digest.
