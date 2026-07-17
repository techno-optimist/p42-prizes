#![no_main]
sp1_zkvm::entrypoint!(main);

use p42_q6_objective_core::{verify_q6_intersecting_hypergraph_and_journal, ObjectiveWitness};

pub fn main() {
    let witness = sp1_zkvm::io::read::<ObjectiveWitness>();
    let journal = verify_q6_intersecting_hypergraph_and_journal(&witness)
        .expect("invalid q6 objective witness");
    sp1_zkvm::io::commit_slice(&journal);
}
