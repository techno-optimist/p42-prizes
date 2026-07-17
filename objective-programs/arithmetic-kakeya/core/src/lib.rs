use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::{Signed, Zero};
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

fn evaluate(parsed: &ParsedSolution) -> Option<KakeyaScore> {
    let generators = build_generators(parsed)?;
    let vertices: Vec<_> = [(1, 1), (1, 2), (2, 1), (2, 2)]
        .into_iter()
        .map(|(a, b)| (BigInt::from(a), BigInt::from(b)))
        .collect();
    let mut free: HashSet<_> = parsed.free.iter().cloned().collect();
    while free.len() < vertices.len() {
        let newly_forced: Vec<_> = vertices
            .iter()
            .filter(|vertex| !free.contains(*vertex) && can_force(vertex, &free, &generators))
            .cloned()
            .collect();
        if newly_forced.is_empty() {
            break;
        }
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
    Some(KakeyaScore {
        numerator,
        denominator,
        chain_atoms,
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

    fn fixture() -> Vec<u8> {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../problems/arithmetic-kakeya/examples/kt-2x2-forcing.json")
            .read_bytes()
    }

    trait ReadBytes {
        fn read_bytes(&self) -> Vec<u8>;
    }
    impl ReadBytes for PathBuf {
        fn read_bytes(&self) -> Vec<u8> {
            std::fs::read(self).unwrap()
        }
    }

    #[derive(Deserialize)]
    struct DifferentialDocument {
        schema: String,
        base_fixture: String,
        vectors: Vec<DifferentialVector>,
    }

    #[derive(Deserialize)]
    struct DifferentialVector {
        name: String,
        mutation: String,
        accepted: bool,
        score: Option<String>,
        chain_atoms: Option<String>,
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
            "p42-arithmetic-kakeya-v0.2-differential/v1"
        );
        let base = repo_root().join(document.base_fixture).read_bytes();
        for vector in document.vectors {
            let observed = verify_arithmetic_kakeya(&mutate(&base, &vector.mutation));
            assert_eq!(observed.is_some(), vector.accepted, "{}", vector.name);
            if let Some(score) = observed {
                assert_eq!(
                    format!("{}/{}", score.numerator, score.denominator),
                    vector.score.unwrap()
                );
                assert_eq!(score.chain_atoms.to_string(), vector.chain_atoms.unwrap());
            }
        }
    }

    #[test]
    fn seed_score_and_atoms_are_exact() {
        assert_eq!(
            verify_arithmetic_kakeya(&fixture()),
            Some(KakeyaScore {
                numerator: 7,
                denominator: 4,
                chain_atoms: 1_750_000_000_000_000_000,
            })
        );
    }

    #[test]
    fn exact_threshold_has_no_atom_rounding_shortcut() {
        let exact = KakeyaScore {
            numerator: 1_749_999_999_999,
            denominator: 1_000_000_000_000,
            chain_atoms: 1_749_999_999_999_000_000,
        };
        let below = KakeyaScore {
            numerator: 1_749_999_999_999_000_001,
            denominator: 1_000_000_000_000_000_000,
            chain_atoms: 1_749_999_999_999_000_001,
        };
        assert!(is_minimum_improvement(exact, 7, 4));
        assert!(!is_minimum_improvement(below, 7, 4));
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
            improvement_atoms: word_u128(1),
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
    fn seed_is_not_a_strict_improvement_and_false_outcome_fails_closed() {
        let witness = witness(fixture());
        assert!(verify_arithmetic_kakeya_and_journal(&witness).is_ok());
        let mut false_outcome = witness.clone();
        false_outcome.corrected_challenger_wins = false;
        assert_eq!(
            verify_arithmetic_kakeya_and_journal(&false_outcome),
            Err(ObjectiveError::CorrectedOutcomeMismatch {
                expected: true,
                supplied: false
            })
        );
    }

    #[test]
    fn honest_relaxed_seed_outcome_is_supported_without_changing_production_seed() {
        let mut witness = witness(fixture());
        witness.pending_challenger_wins = true;
        witness.corrected_challenger_wins = false;
        assert!(verify_arithmetic_kakeya_and_journal_against_seed(&witness, 2, 1).is_ok());
    }
}
