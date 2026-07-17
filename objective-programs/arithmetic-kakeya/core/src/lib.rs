use num_bigint::{BigInt, Sign};
use num_rational::BigRational;
use num_traits::{Signed, ToPrimitive, Zero};
use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::{collections::HashSet, fmt, str::FromStr};
use tiny_keccak::{Hasher, Keccak};

pub type Word = [u8; 32];
pub type Address = [u8; 20];

pub const MAX_SOLUTION_CID_BYTES: usize = 512;
pub const MAX_TRANSCRIPT_URI_BYTES: usize = 512;
pub const MAX_SOLUTION_BYTES: usize = 32_768;
pub const MAX_SLOPES: usize = 128;
pub const MAX_EDGE_LABELS_PER_AXIS: usize = 32;
pub const MAX_FREE_VERTICES: usize = 4;
pub const MAX_RELATIONS: usize = 128;
pub const SCORE_ATOM_SCALE: u128 = 1_000_000_000_000_000_000;
const MIN_IMPROVEMENT_DENOMINATOR: u128 = 1_000_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveWitness {
    pub chain_id: Word,
    pub quorum: Address,
    pub manager: Address,
    pub submission_manager: Address,
    pub registry: Address,
    pub problem_id: Word,
    pub objective_package_hash: Word,
    pub guest_elf_sha256: Word,
    pub program_vkey: Word,
    pub submission_id: Word,
    pub solver: Address,
    pub commitment: Word,
    pub commit_da_hash: Word,
    #[serde(deserialize_with = "deserialize_solution_cid")]
    pub solution_cid: Vec<u8>,
    pub claimed_score_atoms: Word,
    pub improvement_atoms: Word,
    pub challenge_ends_at: Word,
    pub challenger: Address,
    pub reason_hash: Word,
    pub challenged_at: Word,
    pub dispute_ends_at: Word,
    pub pending_challenger_wins: bool,
    pub transcript_hash: Word,
    #[serde(deserialize_with = "deserialize_transcript_uri")]
    pub transcript_uri: Vec<u8>,
    pub verdict_hash: Word,
    pub corrected_challenger_wins: bool,
    pub proof_beneficiary: Address,
    #[serde(deserialize_with = "deserialize_solution")]
    pub solution: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectiveError {
    SolutionAnchorMismatch,
    SolutionCidOutOfBounds { got: usize },
    TranscriptUriOutOfBounds { got: usize },
    ImprovementAtomsMismatch { expected: Word, supplied: Word },
    ImprovementComputationOutOfRange,
    CorrectedOutcomeMismatch { expected: bool, supplied: bool },
    NonContradictoryOutcome,
}

impl fmt::Display for ObjectiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SolutionAnchorMismatch => {
                write!(formatter, "solution bytes do not match commitDaHash")
            }
            Self::SolutionCidOutOfBounds { got } => {
                write!(formatter, "solution CID length out of bounds: {got}")
            }
            Self::TranscriptUriOutOfBounds { got } => {
                write!(formatter, "transcript URI length out of bounds: {got}")
            }
            Self::ImprovementAtomsMismatch { .. } => {
                write!(
                    formatter,
                    "improvement atoms do not match seed score atoms minus claimed score atoms"
                )
            }
            Self::ImprovementComputationOutOfRange => {
                write!(
                    formatter,
                    "seed-minus-claimed improvement does not fit a canonical uint256 word"
                )
            }
            Self::CorrectedOutcomeMismatch { expected, supplied } => write!(
                formatter,
                "corrected outcome mismatch: expected {expected}, supplied {supplied}"
            ),
            Self::NonContradictoryOutcome => write!(
                formatter,
                "corrected outcome does not contradict pending outcome"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KakeyaScore {
    pub numerator: u64,
    pub denominator: u64,
    pub chain_atoms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KakeyaEvaluation {
    pub score: KakeyaScore,
    pub rounds: Vec<Vec<[u8; 2]>>,
}

pub fn verify_arithmetic_kakeya_and_journal(
    witness: &ObjectiveWitness,
) -> Result<Word, ObjectiveError> {
    verify_arithmetic_kakeya_and_journal_against_seed(witness, 7, 4)
}

fn verify_arithmetic_kakeya_and_journal_against_seed(
    witness: &ObjectiveWitness,
    seed_numerator: u128,
    seed_denominator: u128,
) -> Result<Word, ObjectiveError> {
    if witness.solution_cid.is_empty() || witness.solution_cid.len() > MAX_SOLUTION_CID_BYTES {
        return Err(ObjectiveError::SolutionCidOutOfBounds {
            got: witness.solution_cid.len(),
        });
    }
    if witness.transcript_uri.is_empty() || witness.transcript_uri.len() > MAX_TRANSCRIPT_URI_BYTES
    {
        return Err(ObjectiveError::TranscriptUriOutOfBounds {
            got: witness.transcript_uri.len(),
        });
    }
    if sha256(&witness.solution) != witness.commit_da_hash {
        return Err(ObjectiveError::SolutionAnchorMismatch);
    }

    let expected_improvement_atoms = canonical_claimed_improvement_atoms(
        witness.claimed_score_atoms,
        seed_numerator,
        seed_denominator,
    )
    .ok_or(ObjectiveError::ImprovementComputationOutOfRange)?;
    if witness.improvement_atoms != expected_improvement_atoms {
        return Err(ObjectiveError::ImprovementAtomsMismatch {
            expected: expected_improvement_atoms,
            supplied: witness.improvement_atoms,
        });
    }

    let expected_score = verify_arithmetic_kakeya(&witness.solution)
        .filter(|score| is_minimum_improvement(*score, seed_numerator, seed_denominator))
        .map(|score| word_u128(score.chain_atoms));
    let expected_challenger_wins =
        expected_score.is_none_or(|score| score != witness.claimed_score_atoms);
    if witness.corrected_challenger_wins != expected_challenger_wins {
        return Err(ObjectiveError::CorrectedOutcomeMismatch {
            expected: expected_challenger_wins,
            supplied: witness.corrected_challenger_wins,
        });
    }
    if witness.corrected_challenger_wins == witness.pending_challenger_wins {
        return Err(ObjectiveError::NonContradictoryOutcome);
    }

    let reveal_instance_hash = keccak_words(&[
        word_address(witness.submission_manager),
        witness.chain_id,
        witness.submission_id,
        word_address(witness.solver),
        witness.commitment,
        witness.commit_da_hash,
        keccak256(&witness.solution_cid),
        witness.claimed_score_atoms,
        witness.improvement_atoms,
        witness.challenge_ends_at,
    ]);
    let challenge_instance_hash = keccak_words(&[
        word_address(witness.manager),
        witness.chain_id,
        witness.submission_id,
        reveal_instance_hash,
        word_address(witness.challenger),
        witness.reason_hash,
        witness.challenged_at,
        witness.dispute_ends_at,
    ]);
    let pending_decision_context = keccak_words(&[
        challenge_instance_hash,
        reveal_instance_hash,
        word_address(witness.challenger),
        witness.reason_hash,
        word_bool(witness.pending_challenger_wins),
        witness.transcript_hash,
        keccak256(&witness.transcript_uri),
        witness.verdict_hash,
    ]);
    let objective_binding_context = keccak_words(&[
        word_address(witness.registry),
        witness.problem_id,
        witness.objective_package_hash,
        witness.guest_elf_sha256,
        witness.program_vkey,
    ]);
    let context_hash = keccak_tagged(
        b"P42_OBJECTIVE_CHALLENGE_CONTEXT_V2",
        &[
            witness.chain_id,
            word_address(witness.manager),
            word_address(witness.submission_manager),
            objective_binding_context,
            witness.submission_id,
            pending_decision_context,
        ],
    );
    Ok(keccak_tagged(
        b"P42_OBJECTIVE_VERDICT_JOURNAL_V2",
        &[
            witness.chain_id,
            word_address(witness.quorum),
            word_address(witness.manager),
            witness.guest_elf_sha256,
            witness.program_vkey,
            context_hash,
            word_bool(witness.corrected_challenger_wins),
            word_address(witness.proof_beneficiary),
        ],
    ))
}

pub fn verify_arithmetic_kakeya(raw: &[u8]) -> Option<KakeyaScore> {
    verify_arithmetic_kakeya_detailed(raw).map(|evaluation| evaluation.score)
}

pub fn verify_arithmetic_kakeya_detailed(raw: &[u8]) -> Option<KakeyaEvaluation> {
    if raw.len() > MAX_SOLUTION_BYTES || raw.starts_with(&[0xef, 0xbb, 0xbf]) {
        return None;
    }
    std::str::from_utf8(raw).ok()?;
    let solution: Solution = serde_json::from_slice(raw).ok()?;
    let parsed = ParsedSolution::try_from(solution)?;
    evaluate(&parsed)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BoundedInt(BigInt);

impl<'de> Deserialize<'de> for BoundedInt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let number = serde_json::Number::deserialize(deserializer)?;
        let text = number.to_string();
        if text.contains(['.', 'e', 'E', '+']) {
            return Err(de::Error::custom("expected a canonical JSON integer"));
        }
        let value = BigInt::from_str(&text).map_err(de::Error::custom)?;
        let limit = (BigInt::from(1u8) << 255usize) - 1u8;
        if value.abs() > limit {
            return Err(de::Error::custom(
                "integer exceeds signed 255-bit magnitude bound",
            ));
        }
        Ok(Self(value))
    }
}

type Pair = [BoundedInt; 2];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EdgeLabel {
    key: Vec<BoundedInt>,
    slope: Pair,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Relation {
    vertex: Pair,
    slope: Pair,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Solution {
    grid: Pair,
    slopes: Vec<Pair>,
    edge_labels: [Vec<EdgeLabel>; 2],
    free: Vec<Pair>,
    relations: Vec<Relation>,
    #[allow(dead_code)]
    source: Option<String>,
    #[allow(dead_code)]
    claimed_score: Option<String>,
}

type IntPair = (BigInt, BigInt);

struct ParsedSolution {
    edge_labels: [Vec<(Vec<BigInt>, IntPair)>; 2],
    free: Vec<IntPair>,
    relations: Vec<(IntPair, IntPair)>,
}

impl ParsedSolution {
    fn try_from(solution: Solution) -> Option<Self> {
        if pair_value(&solution.grid) != (BigInt::from(2), BigInt::from(2))
            || solution.slopes.len() > MAX_SLOPES
            || solution.free.len() > MAX_FREE_VERTICES
            || solution.relations.len() > MAX_RELATIONS
            || solution
                .edge_labels
                .iter()
                .any(|axis| axis.len() > MAX_EDGE_LABELS_PER_AXIS)
        {
            return None;
        }
        let slope_list: Vec<_> = solution.slopes.iter().map(pair_value).collect();
        let slopes: HashSet<_> = slope_list.iter().cloned().collect();
        if slopes.len() != slope_list.len() || !slopes.contains(&(BigInt::zero(), BigInt::zero())) {
            return None;
        }
        if slopes
            .iter()
            .any(|(a, b)| (!a.is_zero() || !b.is_zero()) && (a + b).is_zero())
        {
            return None;
        }

        let vertices = vertex_set();
        let free: Vec<_> = solution.free.iter().map(pair_value).collect();
        let free_set: HashSet<_> = free.iter().cloned().collect();
        if free_set.len() != free.len() || free.iter().any(|vertex| !vertices.contains(vertex)) {
            return None;
        }

        let mut edge_labels: [Vec<(Vec<BigInt>, IntPair)>; 2] = [Vec::new(), Vec::new()];
        for (axis_index, entries) in solution.edge_labels.into_iter().enumerate() {
            let expected_key_len = axis_index + 1;
            let mut seen = HashSet::new();
            for entry in entries {
                if entry.key.len() != expected_key_len {
                    return None;
                }
                let key: Vec<_> = entry.key.into_iter().map(|value| value.0).collect();
                let slope = pair_value(&entry.slope);
                if !slopes.contains(&slope) || !seen.insert((key.clone(), slope.clone())) {
                    return None;
                }
                edge_labels[axis_index].push((key, slope));
            }
        }

        let mut relations = Vec::with_capacity(solution.relations.len());
        let mut seen_relations = HashSet::new();
        for relation in solution.relations {
            let vertex = pair_value(&relation.vertex);
            let slope = pair_value(&relation.slope);
            if !vertices.contains(&vertex)
                || !slopes.contains(&slope)
                || !seen_relations.insert((vertex.clone(), slope.clone()))
            {
                return None;
            }
            relations.push((vertex, slope));
        }
        Some(Self {
            edge_labels,
            free,
            relations,
        })
    }
}

fn pair_value(pair: &Pair) -> IntPair {
    (pair[0].0.clone(), pair[1].0.clone())
}

fn vertex_set() -> HashSet<IntPair> {
    [(1, 1), (1, 2), (2, 1), (2, 2)]
        .into_iter()
        .map(|(a, b)| (BigInt::from(a), BigInt::from(b)))
        .collect()
}

type Generator = [BigInt; 8];

fn zero_generator() -> Generator {
    std::array::from_fn(|_| BigInt::zero())
}

fn coordinate_index(vertex: &IntPair, component: usize) -> Option<usize> {
    let one = BigInt::from(1);
    let two = BigInt::from(2);
    let order = match vertex {
        value if value == &(one.clone(), one.clone()) => 0,
        value if value == &(one.clone(), two.clone()) => 1,
        value if value == &(two.clone(), one) => 2,
        value if value == &(two.clone(), two) => 3,
        _ => return None,
    };
    Some(2 * order + component)
}

fn add_slope(vector: &mut Generator, vertex: &IntPair, slope: &IntPair, sign: i8) -> Option<()> {
    let factor = BigInt::from(sign);
    vector[coordinate_index(vertex, 0)?] += &slope.0 * &factor;
    vector[coordinate_index(vertex, 1)?] += &slope.1 * factor;
    Some(())
}

fn build_generators(parsed: &ParsedSolution) -> Option<Vec<Generator>> {
    let mut generators = Vec::new();
    for (vertex, slope) in &parsed.relations {
        let mut vector = zero_generator();
        add_slope(&mut vector, vertex, slope, 1)?;
        generators.push(vector);
    }
    for (key, slope) in &parsed.edge_labels[0] {
        if key != &[BigInt::from(1)] {
            return None;
        }
        for second in [1, 2] {
            let mut vector = zero_generator();
            add_slope(
                &mut vector,
                &(BigInt::from(1), BigInt::from(second)),
                slope,
                1,
            )?;
            add_slope(
                &mut vector,
                &(BigInt::from(2), BigInt::from(second)),
                slope,
                -1,
            )?;
            generators.push(vector);
        }
    }
    for (key, slope) in &parsed.edge_labels[1] {
        if key != &[BigInt::from(1), BigInt::from(1)] && key != &[BigInt::from(2), BigInt::from(1)]
        {
            return None;
        }
        let first = key[0].clone();
        let mut vector = zero_generator();
        add_slope(&mut vector, &(first.clone(), BigInt::from(1)), slope, 1)?;
        add_slope(&mut vector, &(first, BigInt::from(2)), slope, -1)?;
        generators.push(vector);
    }
    Some(generators)
}

fn is_consistent(mut rows: Vec<Vec<BigRational>>) -> bool {
    if rows.is_empty() {
        return true;
    }
    let columns = rows[0].len() - 1;
    let mut pivot_row = 0;
    for column in 0..columns {
        let Some(pivot) = (pivot_row..rows.len()).find(|row| !rows[*row][column].is_zero()) else {
            continue;
        };
        rows.swap(pivot_row, pivot);
        let pivot_value = rows[pivot_row][column].clone();
        for row in (pivot_row + 1)..rows.len() {
            if rows[row][column].is_zero() {
                continue;
            }
            let factor = &rows[row][column] / &pivot_value;
            for update_column in column..=columns {
                let delta = &factor * &rows[pivot_row][update_column];
                rows[row][update_column] -= delta;
            }
        }
        pivot_row += 1;
    }
    rows.iter()
        .all(|row| !row[..columns].iter().all(Zero::is_zero) || row[columns].is_zero())
}

fn can_force(target: &IntPair, free: &HashSet<IntPair>, generators: &[Generator]) -> bool {
    let vertices: Vec<_> = [(1, 1), (1, 2), (2, 1), (2, 2)]
        .into_iter()
        .map(|(a, b)| (BigInt::from(a), BigInt::from(b)))
        .collect();
    let mut equations = Vec::new();
    for vertex in &vertices {
        if vertex == target || !free.contains(vertex) {
            for component in 0..2 {
                let coordinate = coordinate_index(vertex, component).unwrap();
                let mut row: Vec<_> = generators
                    .iter()
                    .map(|generator| BigRational::from_integer(generator[coordinate].clone()))
                    .collect();
                let rhs = if vertex == target {
                    BigInt::from([1, -1][component])
                } else {
                    BigInt::zero()
                };
                row.push(BigRational::from_integer(rhs));
                equations.push(row);
            }
        }
    }
    is_consistent(equations)
}

fn evaluate(parsed: &ParsedSolution) -> Option<KakeyaEvaluation> {
    let generators = build_generators(parsed)?;
    let vertices: Vec<_> = [(1, 1), (1, 2), (2, 1), (2, 2)]
        .into_iter()
        .map(|(a, b)| (BigInt::from(a), BigInt::from(b)))
        .collect();
    let mut free: HashSet<_> = parsed.free.iter().cloned().collect();
    let mut rounds = Vec::new();
    while free.len() < vertices.len() {
        let newly_forced: Vec<_> = vertices
            .iter()
            .filter(|vertex| !free.contains(*vertex) && can_force(vertex, &free, &generators))
            .cloned()
            .collect();
        if newly_forced.is_empty() {
            break;
        }
        rounds.push(
            newly_forced
                .iter()
                .map(|(first, second)| Some([first.to_u8()?, second.to_u8()?]))
                .collect::<Option<Vec<_>>>()?,
        );
        free.extend(newly_forced);
    }
    if free.len() != vertices.len() {
        return None;
    }
    let denominator = 4usize.checked_sub(parsed.free.len())?;
    if denominator == 0 {
        return None;
    }
    let edge_cost = parsed.edge_labels[0]
        .iter()
        .filter(|(_, slope)| !slope.0.is_zero() || !slope.1.is_zero())
        .count()
        * 2
        + parsed.edge_labels[1]
            .iter()
            .filter(|(_, slope)| !slope.0.is_zero() || !slope.1.is_zero())
            .count();
    let numerator = edge_cost + parsed.relations.len();
    let divisor = gcd(numerator, denominator);
    let numerator = (numerator / divisor) as u64;
    let denominator = (denominator / divisor) as u64;
    let chain_atoms = (u128::from(numerator) * SCORE_ATOM_SCALE).div_ceil(u128::from(denominator));
    Some(KakeyaEvaluation {
        score: KakeyaScore {
            numerator,
            denominator,
            chain_atoms,
        },
        rounds,
    })
}

fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let next = left % right;
        left = right;
        right = next;
    }
    left
}

fn is_minimum_improvement(
    score: KakeyaScore,
    seed_numerator: u128,
    seed_denominator: u128,
) -> bool {
    let score_numerator = u128::from(score.numerator);
    let score_denominator = u128::from(score.denominator);
    let Some(seed_scaled) = seed_numerator.checked_mul(score_denominator) else {
        return false;
    };
    let Some(score_scaled) = score_numerator.checked_mul(seed_denominator) else {
        return false;
    };
    let Some(delta) = seed_scaled.checked_sub(score_scaled) else {
        return false;
    };
    delta
        .checked_mul(MIN_IMPROVEMENT_DENOMINATOR)
        .is_some_and(|scaled| scaled >= seed_denominator * score_denominator)
}

fn canonical_claimed_improvement_atoms(
    claimed_score_atoms: Word,
    seed_numerator: u128,
    seed_denominator: u128,
) -> Option<Word> {
    if seed_denominator == 0 {
        return None;
    }
    let denominator = BigInt::from(seed_denominator);
    let scaled_seed = BigInt::from(seed_numerator) * SCORE_ATOM_SCALE;
    let seed_score_atoms = (&scaled_seed + &denominator - 1u8) / denominator;
    let max_int256 = (BigInt::from(1u8) << 255usize) - 1u8;
    if seed_score_atoms > max_int256 {
        return None;
    }

    let unsigned_claim = BigInt::from_bytes_be(Sign::Plus, &claimed_score_atoms);
    let claimed_score_atoms = if claimed_score_atoms[0] & 0x80 == 0 {
        unsigned_claim
    } else {
        unsigned_claim - (BigInt::from(1u8) << 256usize)
    };
    let improvement_atoms = seed_score_atoms - claimed_score_atoms;
    if improvement_atoms.is_negative() {
        return None;
    }
    let (_, bytes) = improvement_atoms.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Some(word)
}

fn deserialize_solution_cid<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes::<D, MAX_SOLUTION_CID_BYTES>(deserializer)
}
fn deserialize_transcript_uri<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes::<D, MAX_TRANSCRIPT_URI_BYTES>(deserializer)
}
fn deserialize_solution<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes::<D, MAX_SOLUTION_BYTES>(deserializer)
}
fn deserialize_bounded_bytes<'de, D: Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct BoundedBytes<const MAX: usize>;
    impl<'de, const MAX: usize> de::Visitor<'de> for BoundedBytes<MAX> {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX} bytes")
        }
        fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
            if value.len() > MAX {
                return Err(E::custom(format!("byte length exceeds {MAX}")));
            }
            Ok(value.to_vec())
        }
        fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            if value.len() > MAX {
                return Err(E::custom(format!("byte length exceeds {MAX}")));
            }
            Ok(value)
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let hint = seq.size_hint().unwrap_or(0);
            if hint > MAX {
                return Err(de::Error::custom(format!("byte length exceeds {MAX}")));
            }
            let mut value = Vec::with_capacity(hint.min(MAX));
            while let Some(byte) = seq.next_element::<u8>()? {
                if value.len() == MAX {
                    return Err(de::Error::custom(format!("byte length exceeds {MAX}")));
                }
                value.push(byte);
            }
            Ok(value)
        }
    }
    deserializer.deserialize_seq(BoundedBytes::<MAX>)
}

pub fn sha256(bytes: &[u8]) -> Word {
    Sha256::digest(bytes).into()
}
pub fn keccak256(bytes: &[u8]) -> Word {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}
fn keccak_words(words: &[Word]) -> Word {
    let mut bytes = Vec::with_capacity(words.len() * 32);
    for word in words {
        bytes.extend_from_slice(word);
    }
    keccak256(&bytes)
}
fn keccak_tagged(tag: &[u8], words: &[Word]) -> Word {
    let head_words = 1 + words.len();
    let padded_tag_len = tag.len().div_ceil(32) * 32;
    let mut bytes = Vec::with_capacity(head_words * 32 + 32 + padded_tag_len);
    bytes.extend_from_slice(&word_u128((head_words * 32) as u128));
    for word in words {
        bytes.extend_from_slice(word);
    }
    bytes.extend_from_slice(&word_u128(tag.len() as u128));
    bytes.extend_from_slice(tag);
    bytes.resize(bytes.len() + padded_tag_len - tag.len(), 0);
    keccak256(&bytes)
}
pub fn word_address(address: Address) -> Word {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&address);
    word
}
pub fn word_bool(value: bool) -> Word {
    let mut word = [0u8; 32];
    word[31] = u8::from(value);
    word
}
pub fn word_u128(value: u128) -> Word {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::path::PathBuf;

    trait ReadBytes {
        fn read_bytes(&self) -> Vec<u8>;
    }
    impl ReadBytes for PathBuf {
        fn read_bytes(&self) -> Vec<u8> {
            std::fs::read(self).unwrap()
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DifferentialDocument {
        schema: String,
        base_fixture: String,
        minimum_improvement: String,
        improvement_scale: String,
        atom_scale: String,
        solution_vectors: Vec<SolutionVector>,
        threshold_vectors: Vec<ThresholdVector>,
        outcome_vectors: Vec<OutcomeVector>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SolutionVector {
        name: String,
        mutation: String,
        expected: SolutionExpected,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SolutionExpected {
        result: String,
        score: Option<String>,
        chain_atoms: Option<String>,
        rounds: Option<Vec<Vec<[u8; 2]>>>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ThresholdVector {
        name: String,
        seed: String,
        score: String,
        accepted: bool,
        chain_atoms: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OutcomeVector {
        name: String,
        seed: String,
        claimed_atoms: String,
        improvement_atoms: String,
        challenger_wins: bool,
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
    }

    fn mutate(base: &[u8], mutation: &str) -> Vec<u8> {
        if mutation == "none" {
            return base.to_vec();
        }
        if mutation == "duplicate-relation-slope-key" {
            let text = std::str::from_utf8(base).unwrap();
            return text
                .replacen(
                    r#"{"slope":[1,2],"vertex":[1,1]}"#,
                    r#"{"slope":[1,2],"slope":[1,2],"vertex":[1,1]}"#,
                    1,
                )
                .into_bytes();
        }
        if mutation == "duplicate-grid-key" {
            return std::str::from_utf8(base)
                .unwrap()
                .replacen(r#""grid":[2,2]"#, r#""grid":[2,2],"grid":[2,2]"#, 1)
                .into_bytes();
        }
        if mutation == "utf8-bom" {
            return [b"\xef\xbb\xbf".as_slice(), base].concat();
        }
        if mutation == "utf16-le" {
            return std::str::from_utf8(base)
                .unwrap()
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
        }
        if mutation == "utf32-be" {
            return std::str::from_utf8(base)
                .unwrap()
                .chars()
                .flat_map(|character| u32::from(character).to_be_bytes())
                .collect();
        }
        let raw_mutation = match mutation {
            "json-plus-sign" => Some((r#""grid":[2,2]"#, r#""grid":[+2,2]"#)),
            "json-leading-zero" => Some((r#""grid":[2,2]"#, r#""grid":[02,2]"#)),
            "json-decimal-integer" => Some((r#""grid":[2,2]"#, r#""grid":[2.0,2]"#)),
            "json-exponent-integer" => Some((r#""grid":[2,2]"#, r#""grid":[2e0,2]"#)),
            "json-negative-zero" => Some((r#""slopes":[[0,0]"#, r#""slopes":[[-0,0]"#)),
            _ => None,
        };
        if let Some((before, after)) = raw_mutation {
            return std::str::from_utf8(base)
                .unwrap()
                .replacen(before, after, 1)
                .into_bytes();
        }
        if mutation.starts_with("escaped-") {
            let text = std::str::from_utf8(base).unwrap();
            let source = text.find(r#""source":"#).unwrap();
            let replacement = match mutation {
                "escaped-valid-surrogate-pair" => r#""source":"\ud83d\ude00"}"#,
                "escaped-lone-high-surrogate" => r#""source":"\ud800"}"#,
                "escaped-lone-low-surrogate" => r#""source":"\udfff"}"#,
                _ => unreachable!(),
            };
            return format!("{}{}", &text[..source], replacement).into_bytes();
        }
        let mut value: serde_json::Value = serde_json::from_slice(base).unwrap();
        let root = value.as_object_mut().unwrap();
        match mutation {
            "remove-last-relation" => {
                root["relations"].as_array_mut().unwrap().pop();
            }
            "duplicate-first-slope" => duplicate_first(root, "slopes"),
            "duplicate-first-relation" => duplicate_first(root, "relations"),
            "duplicate-first-edge-label" => {
                let axes = root["edge_labels"].as_array_mut().unwrap();
                let entries = axes[0].as_array_mut().unwrap();
                entries.push(entries[0].clone());
            }
            "boolean-grid-coordinate" => {
                root.get_mut("grid").unwrap().as_array_mut().unwrap()[0] = true.into()
            }
            "unknown-root-field" => {
                root.insert("unknown".into(), 1.into());
            }
            "unknown-relation-field" => {
                root["relations"].as_array_mut().unwrap()[0]
                    .as_object_mut()
                    .unwrap()
                    .insert("unknown".into(), 1.into());
            }
            "integer-at-bound" => push_slope(
                root,
                "57896044618658097711785492504343953926634992332820282019728792003956564819967",
            ),
            "integer-over-bound" => push_slope(
                root,
                "57896044618658097711785492504343953926634992332820282019728792003956564819968",
            ),
            "reflect-grid-certificate" => {
                for relation in root["relations"].as_array_mut().unwrap() {
                    let vertex = relation["vertex"].as_array_mut().unwrap();
                    for coordinate in vertex {
                        *coordinate = (3 - coordinate.as_i64().unwrap()).into();
                    }
                }
                root["edge_labels"].as_array_mut().unwrap()[1]
                    .as_array_mut()
                    .unwrap()
                    .reverse();
            }
            "active-worst-case-rational-integers" => {
                let maximum = BigInt::from(1u8) << 255usize;
                let maximum = maximum - 1u8;
                let almost = &maximum - 1u8;
                let first: serde_json::Value =
                    serde_json::from_str(&format!("[{maximum},{almost}]")).unwrap();
                let second: serde_json::Value =
                    serde_json::from_str(&format!("[{almost},{maximum}]")).unwrap();
                root["slopes"]
                    .as_array_mut()
                    .unwrap()
                    .extend([first.clone(), second.clone()]);
                let relations = root["relations"].as_array_mut().unwrap();
                relations.insert(0, serde_json::json!({"slope": second, "vertex": [2, 2]}));
                relations.insert(0, serde_json::json!({"slope": first, "vertex": [1, 1]}));
            }
            "slopes-at-bound" | "slopes-over-bound" => {
                let slopes = root.get_mut("slopes").unwrap().as_array_mut().unwrap();
                for index in 2..125 {
                    slopes.push(serde_json::json!([index, 1]));
                }
                if mutation == "slopes-over-bound" {
                    slopes.push(serde_json::json!([125, 1]));
                }
            }
            _ => panic!("unknown mutation: {mutation}"),
        }
        serde_json::to_vec(&value).unwrap()
    }

    fn duplicate_first(root: &mut serde_json::Map<String, serde_json::Value>, field: &str) {
        let entries = root.get_mut(field).unwrap().as_array_mut().unwrap();
        entries.push(entries[0].clone());
    }

    fn push_slope(root: &mut serde_json::Map<String, serde_json::Value>, integer: &str) {
        let pair: serde_json::Value = serde_json::from_str(&format!("[{integer},0]")).unwrap();
        root.get_mut("slopes")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(pair);
    }

    #[test]
    fn shared_v02_differential_vectors_match() {
        let document: DifferentialDocument = serde_json::from_slice(
            &repo_root()
                .join("objective-programs/arithmetic-kakeya/fixtures/differential-vectors.json")
                .read_bytes(),
        )
        .unwrap();
        assert_eq!(
            document.schema,
            "p42-arithmetic-kakeya-v0.2-differential/v2"
        );
        assert_eq!(document.minimum_improvement, "1/1000000000000");
        assert_eq!(
            document.improvement_scale.parse::<u128>().unwrap(),
            SCORE_ATOM_SCALE
        );
        assert_eq!(
            document.atom_scale.parse::<u128>().unwrap(),
            SCORE_ATOM_SCALE
        );
        let base = repo_root().join(document.base_fixture).read_bytes();
        for vector in document.solution_vectors {
            let observed = verify_arithmetic_kakeya_detailed(&mutate(&base, &vector.mutation));
            assert_eq!(
                observed.is_some(),
                vector.expected.result == "accept",
                "{}",
                vector.name
            );
            if let Some(evaluation) = observed {
                assert_eq!(
                    format!(
                        "{}/{}",
                        evaluation.score.numerator, evaluation.score.denominator
                    ),
                    vector.expected.score.unwrap(),
                    "{}",
                    vector.name,
                );
                assert_eq!(
                    evaluation.score.chain_atoms.to_string(),
                    vector.expected.chain_atoms.unwrap(),
                    "{}",
                    vector.name,
                );
                assert_eq!(
                    evaluation.rounds,
                    vector.expected.rounds.unwrap(),
                    "{}",
                    vector.name
                );
            } else {
                assert_eq!(vector.expected.result, "reject", "{}", vector.name);
                assert!(vector.expected.score.is_none(), "{}", vector.name);
                assert!(vector.expected.chain_atoms.is_none(), "{}", vector.name);
                assert!(vector.expected.rounds.is_none(), "{}", vector.name);
            }
        }
        for vector in document.threshold_vectors {
            let (seed_numerator, seed_denominator) = parse_fraction(&vector.seed);
            let (numerator, denominator) = parse_fraction(&vector.score);
            let score = KakeyaScore {
                numerator: numerator.try_into().unwrap(),
                denominator: denominator.try_into().unwrap(),
                chain_atoms: (numerator * SCORE_ATOM_SCALE).div_ceil(denominator),
            };
            assert_eq!(
                score.chain_atoms.to_string(),
                vector.chain_atoms,
                "{}",
                vector.name
            );
            assert_eq!(
                is_minimum_improvement(score, seed_numerator, seed_denominator),
                vector.accepted,
                "{}",
                vector.name,
            );
        }
        for vector in document.outcome_vectors {
            let (seed_numerator, seed_denominator) = parse_fraction(&vector.seed);
            let mut witness = witness(base.clone());
            witness.claimed_score_atoms = word_u128(vector.claimed_atoms.parse().unwrap());
            let expected_improvement_atoms = canonical_claimed_improvement_atoms(
                witness.claimed_score_atoms,
                seed_numerator,
                seed_denominator,
            )
            .unwrap();
            assert_eq!(
                expected_improvement_atoms,
                word_u128(vector.improvement_atoms.parse().unwrap()),
                "{}",
                vector.name,
            );
            witness.improvement_atoms = word_u128(vector.improvement_atoms.parse().unwrap());
            witness.pending_challenger_wins = !vector.challenger_wins;
            witness.corrected_challenger_wins = vector.challenger_wins;
            assert!(
                verify_arithmetic_kakeya_and_journal_against_seed(
                    &witness,
                    seed_numerator,
                    seed_denominator,
                )
                .is_ok(),
                "{}",
                vector.name,
            );
            witness.corrected_challenger_wins = !vector.challenger_wins;
            assert!(
                matches!(
                    verify_arithmetic_kakeya_and_journal_against_seed(
                        &witness,
                        seed_numerator,
                        seed_denominator,
                    ),
                    Err(ObjectiveError::CorrectedOutcomeMismatch { .. })
                ),
                "{}",
                vector.name,
            );
        }
    }

    fn parse_fraction(value: &str) -> (u128, u128) {
        let (numerator, denominator) = value.split_once('/').unwrap();
        (numerator.parse().unwrap(), denominator.parse().unwrap())
    }

    fn word_from_hex(value: &str) -> Word {
        let bytes = value.as_bytes();
        assert_eq!(bytes.len(), 64);
        std::array::from_fn(|index| {
            u8::from_str_radix(
                std::str::from_utf8(&bytes[2 * index..2 * index + 2]).unwrap(),
                16,
            )
            .unwrap()
        })
    }

    fn witness(solution: Vec<u8>) -> ObjectiveWitness {
        ObjectiveWitness {
            chain_id: word_u128(84_532),
            quorum: [0x11; 20],
            manager: [0x22; 20],
            submission_manager: [0x33; 20],
            registry: [0x44; 20],
            problem_id: word_u128(4),
            objective_package_hash: [0x55; 32],
            guest_elf_sha256: [0xdd; 32],
            program_vkey: [0xee; 32],
            submission_id: word_u128(7),
            solver: [0x66; 20],
            commitment: [0x77; 32],
            commit_da_hash: sha256(&solution),
            solution_cid: b"ipfs://p42-kakeya-fixture".to_vec(),
            claimed_score_atoms: word_u128(1_750_000_000_000_000_000),
            improvement_atoms: word_u128(0),
            challenge_ends_at: word_u128(2_000_000_300),
            challenger: [0x88; 20],
            reason_hash: [0x99; 32],
            challenged_at: word_u128(2_000_000_100),
            dispute_ends_at: word_u128(2_000_000_200),
            pending_challenger_wins: false,
            transcript_hash: [0xaa; 32],
            transcript_uri: b"ipfs://p42-kakeya-transcript".to_vec(),
            verdict_hash: [0xbb; 32],
            corrected_challenger_wins: true,
            proof_beneficiary: [0xcc; 20],
            solution,
        }
    }

    #[test]
    fn production_seed_requires_zero_claim_relative_improvement_atoms() {
        let honest = witness(
            repo_root()
                .join("problems/arithmetic-kakeya/examples/kt-2x2-forcing.json")
                .read_bytes(),
        );
        assert_eq!(
            verify_arithmetic_kakeya_and_journal(&honest),
            Ok(word_from_hex(
                "c35c5ff9ccf4047ef46dee665e7e679ee988c97315ea28cf25ce02f1fb15836f",
            )),
        );

        let mut inflated = honest;
        inflated.improvement_atoms = word_u128(1);
        assert_eq!(
            verify_arithmetic_kakeya_and_journal(&inflated),
            Err(ObjectiveError::ImprovementAtomsMismatch {
                expected: word_u128(0),
                supplied: word_u128(1),
            })
        );
    }

    #[test]
    fn relaxed_seed_rejects_inflated_and_deflated_improvement_atoms() {
        let solution = repo_root()
            .join("problems/arithmetic-kakeya/examples/kt-2x2-forcing.json")
            .read_bytes();
        let mut honest = witness(solution);
        honest.improvement_atoms = word_u128(250_000_000_000_000_000);
        honest.pending_challenger_wins = true;
        honest.corrected_challenger_wins = false;
        assert!(verify_arithmetic_kakeya_and_journal_against_seed(&honest, 2, 1).is_ok());

        for supplied in [249_999_999_999_999_999, 250_000_000_000_000_001] {
            let mut dishonest = honest.clone();
            dishonest.improvement_atoms = word_u128(supplied);
            assert_eq!(
                verify_arithmetic_kakeya_and_journal_against_seed(&dishonest, 2, 1),
                Err(ObjectiveError::ImprovementAtomsMismatch {
                    expected: word_u128(250_000_000_000_000_000),
                    supplied: word_u128(supplied),
                })
            );
        }
    }

    #[test]
    fn dishonest_claim_with_matching_improvement_still_produces_correction() {
        let solution = repo_root()
            .join("problems/arithmetic-kakeya/examples/kt-2x2-forcing.json")
            .read_bytes();
        let mut dishonest = witness(solution);
        dishonest.claimed_score_atoms = word_u128(1_700_000_000_000_000_000);
        dishonest.improvement_atoms = word_u128(50_000_000_000_000_000);
        assert!(verify_arithmetic_kakeya_and_journal(&dishonest).is_ok());
    }

    #[test]
    fn claimed_score_word_uses_signed_int256_semantics() {
        let solution = repo_root()
            .join("problems/arithmetic-kakeya/examples/kt-2x2-forcing.json")
            .read_bytes();
        let mut negative_claim = witness(solution);
        negative_claim.claimed_score_atoms = [0xff; 32];
        negative_claim.improvement_atoms = word_u128(1_750_000_000_000_000_001);
        assert!(verify_arithmetic_kakeya_and_journal(&negative_claim).is_ok());
    }

    #[test]
    fn claimed_score_above_seed_fails_closed_before_journaling() {
        let solution = repo_root()
            .join("problems/arithmetic-kakeya/examples/kt-2x2-forcing.json")
            .read_bytes();
        let mut invalid_direction = witness(solution);
        invalid_direction.claimed_score_atoms = word_u128(1_750_000_000_000_000_001);
        assert_eq!(
            verify_arithmetic_kakeya_and_journal(&invalid_direction),
            Err(ObjectiveError::ImprovementComputationOutOfRange),
        );
    }
}
