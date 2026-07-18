use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use p42_objective_core::{word_u128, Word};
use p42_three_objective_shared::{
    number_equals_python, parse_canonical_document, verdict_journal_v2, JournalError,
    ObjectiveContext,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const N: usize = 2_400;
pub const HALF_N: u32 = 1_200;
pub const MAX_DENOMINATOR_POWER: u32 = 128;
pub const MAX_SOLUTION_BYTES: usize = 256 * 1024;
pub const SCORE_ATOM_SCALE: u128 = 1_000_000_000_000_000_000;
const MIN_IMPROVEMENT_DENOMINATOR: u64 = 1_000_000_000_000;
const SEED_NUMERATOR: &str = "1424992289798782609633201801352767458976314440679252577";
const SEED_DENOMINATOR: &str = "3741444197802851304404516484910431627947663875649308401";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub n: usize,
    pub numerator: BigUint,
    pub denominator: BigUint,
    pub argmax_lag: i32,
    pub raw_sum: BigUint,
    pub chain_score_atoms: u128,
    pub qualifies: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Oversized,
    MalformedJson,
    NRange,
    DenominatorPowerRange,
    WrongShape,
    RawRange,
    ZeroMass,
    RescaleRange,
    ArithmeticBound,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectiveError {
    InvalidEnvelope(JournalError),
}

pub fn evaluate_and_journal(witness: &ObjectiveContext<'_>) -> Result<Word, ObjectiveError> {
    verdict_journal_v2(witness, expected_score_atoms(witness.solution))
        .map_err(ObjectiveError::InvalidEnvelope)
}

fn expected_score_atoms(raw: &[u8]) -> Option<Word> {
    evaluate(raw)
        .ok()
        .filter(|evaluation| evaluation.qualifies)
        .map(|evaluation| word_u128(evaluation.chain_score_atoms))
}

pub fn evaluate(raw: &[u8]) -> Result<Evaluation, VerifyError> {
    if raw.len() > MAX_SOLUTION_BYTES {
        return Err(VerifyError::Oversized);
    }
    let root = parse_canonical_document(raw).map_err(|_| VerifyError::MalformedJson)?;
    if !number_equals_python(root.n.as_ref(), N as u64) {
        return Err(VerifyError::NRange);
    }
    let power = parse_u32(root.denominator_power.as_ref())
        .filter(|power| *power <= MAX_DENOMINATOR_POWER)
        .ok_or(VerifyError::DenominatorPowerRange)?;
    let numbers = root
        .values
        .and_then(|value| value.as_array().cloned())
        .ok_or(VerifyError::WrongShape)?;
    if numbers.len() != N {
        return Err(VerifyError::WrongShape);
    }
    let limit = BigUint::one() << power;
    let mut values = Vec::with_capacity(N);
    let mut total = BigUint::zero();
    for number in numbers {
        let value = parse_biguint(&number).ok_or(VerifyError::RawRange)?;
        if value > limit {
            return Err(VerifyError::RawRange);
        }
        total += &value;
        values.push(value);
    }
    if total.is_zero() {
        return Err(VerifyError::ZeroMass);
    }

    let scaled: Vec<BigUint> = values.iter().map(|value| value * HALF_N).collect();
    if scaled.iter().any(|value| value > &total) {
        return Err(VerifyError::RescaleRange);
    }
    let complements: Vec<BigUint> = scaled.iter().map(|value| &total - value).collect();

    // The loop order intentionally matches Python range(-(N - 1), N), so a
    // tied maximum selects the same first (most negative) lag.
    let mut best_lag = -(N as i32 - 1);
    let mut best_total = BigUint::zero();
    let mut first = true;
    for lag in -(N as i32 - 1)..N as i32 {
        let start = 0.max(-lag) as usize;
        let stop = (N as i32).min(N as i32 - lag) as usize;
        let mut lag_total = BigUint::zero();
        for index in start..stop {
            lag_total += &scaled[index] * &complements[(index as i32 + lag) as usize];
        }
        if first || lag_total > best_total {
            first = false;
            best_total = lag_total;
            best_lag = lag;
        }
    }

    let mut numerator = BigUint::from(2u8) * best_total;
    let mut denominator = BigUint::from(N) * &total * &total;
    let gcd = numerator.gcd(&denominator);
    numerator /= &gcd;
    denominator /= gcd;
    let atoms_big = (&numerator * SCORE_ATOM_SCALE + &denominator - 1u8) / &denominator;
    let chain_score_atoms = atoms_big.to_u128().ok_or(VerifyError::ArithmeticBound)?;
    let qualifies = qualifies_minimize(&numerator, &denominator);
    Ok(Evaluation {
        n: N,
        numerator,
        denominator,
        argmax_lag: best_lag,
        raw_sum: total,
        chain_score_atoms,
        qualifies,
    })
}

/// Diagnostic digest only. The candidate journal path uses
/// `evaluate_and_journal` and the full `P42_OBJECTIVE_VERDICT_JOURNAL_V2` envelope.
pub fn evaluation_digest(raw: &[u8], evaluation: &Evaluation) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"P42_CANDIDATE_ERDOS_MIN_OVERLAP_EVALUATION_V1");
    hash.update(Sha256::digest(raw));
    hash.update((evaluation.n as u32).to_be_bytes());
    hash_biguint(&mut hash, &evaluation.numerator);
    hash_biguint(&mut hash, &evaluation.denominator);
    hash.update(evaluation.argmax_lag.to_be_bytes());
    hash.update([u8::from(evaluation.qualifies)]);
    hash.finalize().into()
}

fn qualifies_minimize(numerator: &BigUint, denominator: &BigUint) -> bool {
    let seed_numerator: BigUint = SEED_NUMERATOR.parse().expect("constant");
    let seed_denominator: BigUint = SEED_DENOMINATOR.parse().expect("constant");
    let seed_scaled = &seed_numerator * denominator;
    let score_scaled = numerator * &seed_denominator;
    seed_scaled > score_scaled
        && (seed_scaled - score_scaled) * MIN_IMPROVEMENT_DENOMINATOR
            >= seed_denominator * denominator
}

fn hash_biguint(hash: &mut Sha256, value: &BigUint) {
    let bytes = value.to_bytes_be();
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
}

fn parse_biguint(value: &serde_json::Value) -> Option<BigUint> {
    let text = value.as_number()?.to_string();
    if text.starts_with('-') || text.contains(['.', 'e', 'E', '+']) {
        return (text == "-0").then(BigUint::zero);
    }
    text.parse().ok()
}

fn parse_u32(value: Option<&serde_json::Value>) -> Option<u32> {
    parse_integer_text(value?).and_then(|text| text.parse().ok())
}

fn parse_integer_text(value: &serde_json::Value) -> Option<String> {
    let text = value.as_number()?.to_string();
    if text == "-0" {
        return Some("0".to_owned());
    }
    (!text.contains(['.', 'e', 'E', '+'])).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn challenger_context(solution: &[u8]) -> ObjectiveContext<'_> {
        ObjectiveContext {
            chain_id: [0; 32],
            quorum: [0; 20],
            manager: [0; 20],
            submission_manager: [0; 20],
            registry: [0; 20],
            problem_id: [0; 32],
            objective_package_hash: [0; 32],
            guest_elf_sha256: [0; 32],
            program_vkey: [0; 32],
            submission_id: [0; 32],
            solver: [0; 20],
            commitment: [0; 32],
            commit_da_hash: p42_objective_core::sha256(solution),
            solution_cid: b"cid",
            claimed_score_atoms: [0; 32],
            improvement_atoms: [0; 32],
            challenge_ends_at: [0; 32],
            challenger: [0; 20],
            reason_hash: [0; 32],
            challenged_at: [0; 32],
            dispute_ends_at: [0; 32],
            pending_challenger_wins: false,
            transcript_hash: [0; 32],
            transcript_uri: b"uri",
            verdict_hash: [0; 32],
            corrected_challenger_wins: true,
            proof_beneficiary: [0; 20],
            solution,
        }
    }

    #[test]
    fn small_oracle_matches_python_vector() {
        assert_eq!(
            score_small(&[1, 2, 1, 2]),
            (BigUint::from(1u8), BigUint::from(2u8), -1)
        );
    }

    #[test]
    fn duplicate_keys_are_malformed() {
        assert_eq!(
            evaluate(br#"{"n":2400,"n":2400,"denominator_power":0,"values":[]}"#),
            Err(VerifyError::MalformedJson)
        );
    }

    #[test]
    fn n_uses_python_numeric_equality() {
        let values = std::iter::repeat_n("1", N).collect::<Vec<_>>().join(",");
        for n in ["2400", "2400.0", "2.4e3"] {
            let raw = format!(r#"{{"n":{n},"denominator_power":0,"values":[{values}]}}"#);
            assert!(evaluate(raw.as_bytes()).is_ok(), "{n}");
        }
        assert_eq!(
            evaluate(br#"{"n":true,"denominator_power":0,"values":[]}"#),
            Err(VerifyError::NRange)
        );
    }

    #[test]
    fn exact_seed_is_not_an_improvement() {
        assert!(!qualifies_minimize(
            &SEED_NUMERATOR.parse().unwrap(),
            &SEED_DENOMINATOR.parse().unwrap()
        ));
        assert!(qualifies_minimize(&BigUint::zero(), &BigUint::one()));
    }

    #[test]
    fn malformed_solution_maps_to_no_expected_score() {
        for solution in [b"not json".as_slice(), b"{}".as_slice()] {
            assert_eq!(expected_score_atoms(solution), None);
            assert!(evaluate_and_journal(&challenger_context(solution)).is_ok());
        }
    }

    #[test]
    #[ignore = "bounded full Python/Rust differential vector"]
    fn bundled_frontier_matches_python_vector() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.join("../../..");
        let vectors: serde_json::Value = serde_json::from_slice(
            &fs::read(manifest.join("../fixtures/differential-vectors.json")).unwrap(),
        )
        .unwrap();
        for vector in vectors["vectors"].as_array().unwrap() {
            let path = root.join(vector["solution"].as_str().unwrap());
            let evaluation = evaluate(&fs::read(path).unwrap()).unwrap();
            assert_eq!(evaluation.n, vector["n"].as_u64().unwrap() as usize);
            assert_eq!(
                evaluation.argmax_lag,
                vector["argmax"].as_i64().unwrap() as i32
            );
            assert_eq!(
                evaluation.raw_sum.to_string(),
                vector["aux"].as_str().unwrap()
            );
            assert_eq!(
                format!("{}/{}", evaluation.numerator, evaluation.denominator),
                vector["score"].as_str().unwrap()
            );
            assert_eq!(
                evaluation.qualifies,
                vector["qualifies"].as_bool().unwrap_or(false)
            );
        }
    }

    fn score_small(values: &[u32]) -> (BigUint, BigUint, i32) {
        let n = values.len();
        let half = n as u32 / 2;
        let total: u32 = values.iter().sum();
        let scaled: Vec<u32> = values.iter().map(|value| value * half).collect();
        let complements: Vec<u32> = scaled.iter().map(|value| total - value).collect();
        let mut best = 0u32;
        let mut best_lag = 0;
        for lag in -(n as i32 - 1)..n as i32 {
            let start = 0.max(-lag) as usize;
            let stop = (n as i32).min(n as i32 - lag) as usize;
            let value = (start..stop)
                .map(|i| scaled[i] * complements[(i as i32 + lag) as usize])
                .sum();
            if value > best {
                best = value;
                best_lag = lag;
            }
        }
        let mut numerator = BigUint::from(2 * best);
        let mut denominator = BigUint::from(n as u32 * total * total);
        let gcd = numerator.gcd(&denominator);
        numerator /= &gcd;
        denominator /= gcd;
        (numerator, denominator, best_lag)
    }
}
