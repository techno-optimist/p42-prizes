use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, CanSample, MultiField32Challenger};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_symmetric::{CryptographicPermutation, Permutation};

const WIDTH: usize = 8;
const RATE: usize = 4;

#[derive(Clone)]
struct MixingPermutation;

impl Permutation<[Goldilocks; WIDTH]> for MixingPermutation {
    fn permute_mut(&self, input: &mut [Goldilocks; WIDTH]) {
        let sum: Goldilocks = input.iter().copied().sum();
        for (index, value) in input.iter_mut().enumerate() {
            *value = sum + Goldilocks::from_canonical_u8((index + 1) as u8);
        }
    }
}

impl CryptographicPermutation<[Goldilocks; WIDTH]> for MixingPermutation {}

fn challenger() -> MultiField32Challenger<BabyBear, Goldilocks, MixingPermutation, WIDTH, RATE> {
    MultiField32Challenger::new(MixingPermutation).expect("valid field pair")
}

fn main() {
    let value = BabyBear::from_canonical_u8(7);

    let mut short = challenger();
    short.observe(value);
    let short_challenge: BabyBear = short.sample();

    let mut padded = challenger();
    padded.observe(value);
    padded.observe(BabyBear::zero());
    let padded_challenge: BabyBear = padded.sample();

    assert_eq!(
        short_challenge, padded_challenge,
        "candidate no longer reproduces the transcript-length collision"
    );
    assert_eq!(
        short.sponge_state, padded.sponge_state,
        "candidate no longer reproduces the sponge-state collision"
    );

    println!("COLLISION: [7] and [7, 0] produce the same sponge state and challenge");
}
