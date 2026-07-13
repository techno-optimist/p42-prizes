#![no_main]
sp1_zkvm::entrypoint!(main);

use p42_objective_core::{verify_hadamard_668_and_journal, ObjectiveWitness};

pub fn main() {
    let witness = sp1_zkvm::io::read::<ObjectiveWitness>();
    let journal = verify_hadamard_668_and_journal(&witness).expect("invalid objective witness");
    sp1_zkvm::io::commit_slice(&journal);
}
