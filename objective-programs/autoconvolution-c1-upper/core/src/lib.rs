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

pub const N: usize = 90_000;
pub const MAX_VALUE_DECIMAL: &str = "1000000000000000000000000000000000000";
pub const MAX_SOLUTION_BYTES: usize = 5 * 1024 * 1024;
pub const SCORE_ATOM_SCALE: u128 = 1_000_000_000_000_000_000;
const MIN_IMPROVEMENT_DENOMINATOR: u64 = 1_000_000_000_000;
const SEED_NUMERATOR: &str =
    "15041971118343665197137380984232095998912388144895190342004000000000000";
const SEED_DENOMINATOR: &str =
    "10008961702715850455872036862958802052289156042841554837278437518918769";
const NTT_LEN: usize = 1 << 18;

// Each p = k*2^20+1 is prime; g is a primitive root. Their product has
// 278.66 bits, above N*(10^36)^2 (< 2^256), so CRT is unique on every
// verifier-admitted coefficient.
const MODULI: [(u32, u32); 9] = [
    (2_130_706_433, 3),
    (2_114_977_793, 3),
    (2_113_929_217, 5),
    (2_099_249_153, 3),
    (2_095_054_849, 11),
    (2_088_763_393, 5),
    (2_077_229_057, 3),
    (2_070_937_601, 6),
    (2_047_868_929, 13),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub numerator: BigUint,
    pub denominator: BigUint,
    pub argmax_index: usize,
    pub linf: BigUint,
    pub l1: BigUint,
    pub chain_score_atoms: u128,
    pub qualifies: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Oversized,
    MalformedJson,
    WrongN,
    WrongShape,
    RawRange,
    ZeroMass,
    PackingChecksum,
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
        return Err(VerifyError::WrongN);
    }
    let numbers = match root.values {
        Some(serde_json::Value::Array(values)) => values,
        _ => return Err(VerifyError::WrongShape),
    };
    if numbers.len() != N {
        return Err(VerifyError::WrongShape);
    }
    let max_value: BigUint = MAX_VALUE_DECIMAL.parse().expect("constant");
    let mut values = Vec::with_capacity(N);
    let mut total = BigUint::zero();
    for number in numbers {
        let value = parse_biguint(&number).ok_or(VerifyError::RawRange)?;
        if value > max_value {
            return Err(VerifyError::RawRange);
        }
        total += &value;
        values.push(value);
    }
    if total.is_zero() {
        return Err(VerifyError::ZeroMass);
    }

    let coefficients = convolve_exact(&values, NTT_LEN, &MODULI)?;
    if coefficients.iter().sum::<BigUint>() != &total * &total {
        return Err(VerifyError::PackingChecksum);
    }
    let (argmax_index, linf) = coefficients
        .iter()
        .enumerate()
        .max_by(|(left_index, left), (right_index, right)| {
            left.cmp(right).then_with(|| right_index.cmp(left_index))
        })
        .map(|(index, value)| (index, value.clone()))
        .ok_or(VerifyError::ZeroMass)?;
    let mut numerator = BigUint::from(2 * N) * &linf;
    let mut denominator = &total * &total;
    let gcd = numerator.gcd(&denominator);
    numerator /= &gcd;
    denominator /= gcd;
    let atoms = (&numerator * SCORE_ATOM_SCALE + &denominator - 1u8) / &denominator;
    let qualifies = qualifies_minimize(&numerator, &denominator);
    Ok(Evaluation {
        numerator,
        denominator,
        argmax_index,
        linf,
        l1: total,
        chain_score_atoms: atoms.to_u128().ok_or(VerifyError::ArithmeticBound)?,
        qualifies,
    })
}

/// Diagnostic digest only. The candidate journal path uses
/// `evaluate_and_journal` and the full `P42_OBJECTIVE_VERDICT_JOURNAL_V2` envelope.
pub fn evaluation_digest(raw: &[u8], evaluation: &Evaluation) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"P42_CANDIDATE_AUTOCONVOLUTION_C1_UPPER_EVALUATION_V1");
    hash.update(Sha256::digest(raw));
    hash_biguint(&mut hash, &evaluation.numerator);
    hash_biguint(&mut hash, &evaluation.denominator);
    hash.update((evaluation.argmax_index as u32).to_be_bytes());
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

fn convolve_exact(
    values: &[BigUint],
    ntt_len: usize,
    moduli: &[(u32, u32)],
) -> Result<Vec<BigUint>, VerifyError> {
    if ntt_len < 2 * values.len() - 1 || !ntt_len.is_power_of_two() {
        return Err(VerifyError::ArithmeticBound);
    }
    let output_len = 2 * values.len() - 1;
    let mut coefficients = vec![BigUint::zero(); output_len];
    let mut product = BigUint::one();
    for &(modulus, primitive_root) in moduli {
        let mut transformed = vec![0u32; ntt_len];
        for (slot, value) in transformed.iter_mut().zip(values) {
            *slot = (value % modulus)
                .to_u32()
                .ok_or(VerifyError::ArithmeticBound)?;
        }
        ntt(&mut transformed, false, modulus, primitive_root);
        for value in &mut transformed {
            *value = mul_mod(*value, *value, modulus);
        }
        ntt(&mut transformed, true, modulus, primitive_root);

        let product_mod = (&product % modulus)
            .to_u32()
            .ok_or(VerifyError::ArithmeticBound)?;
        let inverse = mod_pow(product_mod, u64::from(modulus - 2), modulus);
        for (coefficient, residue) in coefficients.iter_mut().zip(transformed) {
            let current = (&*coefficient % modulus)
                .to_u32()
                .ok_or(VerifyError::ArithmeticBound)?;
            let delta = ((u64::from(residue) + u64::from(modulus) - u64::from(current))
                % u64::from(modulus)) as u32;
            let digit = mul_mod(delta, inverse, modulus);
            *coefficient += &product * digit;
        }
        product *= modulus;
    }
    Ok(coefficients)
}

fn ntt(values: &mut [u32], inverse: bool, modulus: u32, primitive_root: u32) {
    let n = values.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            values.swap(i, j);
        }
    }
    let mut len = 2usize;
    while len <= n {
        let mut root = mod_pow(primitive_root, u64::from(modulus - 1) / len as u64, modulus);
        if inverse {
            root = mod_pow(root, u64::from(modulus - 2), modulus);
        }
        for chunk in values.chunks_exact_mut(len) {
            let mut omega = 1u32;
            for i in 0..len / 2 {
                let even = chunk[i];
                let odd = mul_mod(chunk[i + len / 2], omega, modulus);
                chunk[i] = ((u64::from(even) + u64::from(odd)) % u64::from(modulus)) as u32;
                chunk[i + len / 2] = ((u64::from(even) + u64::from(modulus) - u64::from(odd))
                    % u64::from(modulus)) as u32;
                omega = mul_mod(omega, root, modulus);
            }
        }
        len <<= 1;
    }
    if inverse {
        let inverse_n = mod_pow(n as u32, u64::from(modulus - 2), modulus);
        for value in values {
            *value = mul_mod(*value, inverse_n, modulus);
        }
    }
}

fn mul_mod(left: u32, right: u32, modulus: u32) -> u32 {
    (u64::from(left) * u64::from(right) % u64::from(modulus)) as u32
}

fn mod_pow(mut base: u32, mut exponent: u64, modulus: u32) -> u32 {
    let mut result = 1u32;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exponent >>= 1;
    }
    result
}

fn parse_biguint(value: &serde_json::Value) -> Option<BigUint> {
    let text = value.as_number()?.to_string();
    if text.starts_with('-') || text.contains(['.', 'e', 'E', '+']) {
        return (text == "-0").then(BigUint::zero);
    }
    text.parse().ok()
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
    fn ntt_crt_matches_naive_convolution() {
        let values: Vec<BigUint> = [2u32, 0, 5, 1].into_iter().map(BigUint::from).collect();
        let got = convolve_exact(&values, 8, &MODULI).unwrap();
        let expected: Vec<BigUint> = [4u32, 0, 20, 4, 25, 10, 1]
            .into_iter()
            .map(BigUint::from)
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn crt_product_exceeds_declared_coefficient_bound() {
        let product: BigUint = MODULI.iter().map(|(p, _)| BigUint::from(*p)).product();
        let max: BigUint = MAX_VALUE_DECIMAL.parse().unwrap();
        assert!(product > BigUint::from(N) * &max * &max);
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
    fn parser_rejects_duplicates_and_uses_python_n_equality() {
        let duplicate = format!(r#"{{"n":false,"n":{N},"values":[]}}"#);
        assert_eq!(
            evaluate(duplicate.as_bytes()),
            Err(VerifyError::MalformedJson)
        );
        let exponent = format!(r#"{{"n":{N}e0,"values":[]}}"#);
        assert_eq!(evaluate(exponent.as_bytes()), Err(VerifyError::WrongShape));
        let decimal = format!(r#"{{"n":{N}.0,"values":[]}}"#);
        assert_eq!(evaluate(decimal.as_bytes()), Err(VerifyError::WrongShape));
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
        let vector = &vectors["vectors"][0];
        let raw = fs::read(root.join(vector["solution"].as_str().unwrap())).unwrap();
        let evaluation = evaluate(&raw).unwrap();
        assert!(!evaluation.qualifies);
        assert_eq!(
            evaluation.argmax_index,
            vector["argmax"].as_u64().unwrap() as usize
        );
        assert_eq!(evaluation.linf.to_string(), vector["aux"].as_str().unwrap());
        assert_eq!(
            format!("{}/{}", evaluation.numerator, evaluation.denominator),
            vector["score"].as_str().unwrap()
        );
    }
}
