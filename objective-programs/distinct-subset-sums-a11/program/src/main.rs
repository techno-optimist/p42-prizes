#![no_main]
sp1_zkvm::entrypoint!(main);

use p42_objective_core::{
    verify_distinct_subset_sums_a11_and_journal, A11ObjectiveWitness, ObjectiveWitness,
};

pub fn main() {
    let witness = ObjectiveWitness::from(sp1_zkvm::io::read::<A11ObjectiveWitness>());
    let journal =
        verify_distinct_subset_sums_a11_and_journal(&witness).expect("invalid objective witness");
    sp1_zkvm::io::commit_slice(&journal);
}
