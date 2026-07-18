#![no_main]
sp1_zkvm::entrypoint!(main);

use p42_edges_objective_core::{verify_edges_vs_triangles_and_journal, ObjectiveWitness};

pub fn main() {
    let witness = sp1_zkvm::io::read::<ObjectiveWitness>();
    let journal =
        verify_edges_vs_triangles_and_journal(&witness).expect("invalid edges objective witness");
    sp1_zkvm::io::commit_slice(&journal);
}
