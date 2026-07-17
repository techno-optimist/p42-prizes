#![no_main]
sp1_zkvm::entrypoint!(main);

use p42_arithmetic_kakeya_objective_core::{
    verify_arithmetic_kakeya_and_journal, ObjectiveWitness,
};

pub fn main() {
    let witness = sp1_zkvm::io::read::<ObjectiveWitness>();
    let journal = verify_arithmetic_kakeya_and_journal(&witness)
        .expect("invalid arithmetic-kakeya objective witness");
    sp1_zkvm::io::commit_slice(&journal);
}
