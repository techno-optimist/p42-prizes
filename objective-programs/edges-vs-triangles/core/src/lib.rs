use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::{collections::HashSet, fmt};
use tiny_keccak::{Hasher, Keccak};

pub type Word = [u8; 32];
pub type Address = [u8; 20];

pub const MAX_SOLUTION_CID_BYTES: usize = 512;
pub const MAX_TRANSCRIPT_URI_BYTES: usize = 512;
pub const EDGES_MAX_SOLUTION_BYTES: usize = 512 * 1024;
pub const SCORE_ATOM_SCALE: u128 = 1_000_000_000_000_000_000;

pub const EDGES_ATOMS: usize = 20;
pub const EDGES_ROW_SUM: u128 = 1_000;
pub const EDGES_MAX_ROWS: usize = 500;
pub const X_SCALE: u128 = 1_000_000;
pub const Y_SCALE: u128 = 1_000_000_000;
pub const AREA_SCALE: u128 = 6_000_000_000_000_000_000;
pub const SEED_ABS_NUMERATOR: u128 = 16_684_282_317_138_839;
pub const SEED_DENOMINATOR: u128 = 23_437_500_000_000_000;
pub const MIN_IMPROVEMENT_DENOMINATOR: u128 = 1_000_000_000_000;

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
pub enum EdgesObjectiveError {
    SolutionAnchorMismatch,
    SolutionCidOutOfBounds { got: usize },
    TranscriptUriOutOfBounds { got: usize },
    CorrectedOutcomeMismatch { expected: bool, supplied: bool },
    NonContradictoryOutcome,
}

impl fmt::Display for EdgesObjectiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SolutionAnchorMismatch => {
                write!(formatter, "solution bytes do not match commitDaHash")
            }
            Self::SolutionCidOutOfBounds { got } => write!(
                formatter,
                "solution CID length must be in 1..={MAX_SOLUTION_CID_BYTES} bytes, got {got}"
            ),
            Self::TranscriptUriOutOfBounds { got } => write!(
                formatter,
                "transcript URI length must be in 1..={MAX_TRANSCRIPT_URI_BYTES} bytes, got {got}"
            ),
            Self::CorrectedOutcomeMismatch { expected, supplied } => write!(
                formatter,
                "corrected outcome mismatch: expected {expected}, supplied {supplied}"
            ),
            Self::NonContradictoryOutcome => {
                write!(
                    formatter,
                    "corrected outcome does not contradict pending outcome"
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgesScore {
    pub area_scaled: u128,
    pub max_gap_numerator: u128,
    pub total_scaled: u128,
    pub chain_atoms: i128,
}

pub fn verify_edges_vs_triangles_and_journal(
    witness: &ObjectiveWitness,
) -> Result<Word, EdgesObjectiveError> {
    verify_edges_vs_triangles_and_journal_against_seed(
        witness,
        SEED_ABS_NUMERATOR,
        SEED_DENOMINATOR,
        MIN_IMPROVEMENT_DENOMINATOR,
    )
}

fn verify_edges_vs_triangles_and_journal_against_seed(
    witness: &ObjectiveWitness,
    seed_abs_numerator: u128,
    seed_denominator: u128,
    min_improvement_denominator: u128,
) -> Result<Word, EdgesObjectiveError> {
    if witness.solution_cid.is_empty() || witness.solution_cid.len() > MAX_SOLUTION_CID_BYTES {
        return Err(EdgesObjectiveError::SolutionCidOutOfBounds {
            got: witness.solution_cid.len(),
        });
    }
    if witness.transcript_uri.is_empty() || witness.transcript_uri.len() > MAX_TRANSCRIPT_URI_BYTES
    {
        return Err(EdgesObjectiveError::TranscriptUriOutOfBounds {
            got: witness.transcript_uri.len(),
        });
    }
    if sha256(&witness.solution) != witness.commit_da_hash {
        return Err(EdgesObjectiveError::SolutionAnchorMismatch);
    }

    let expected_score_atoms = verify_edges_vs_triangles(&witness.solution)
        .filter(|score| {
            is_minimum_improvement(
                score.total_scaled,
                seed_abs_numerator,
                seed_denominator,
                min_improvement_denominator,
            )
        })
        .map(|score| word_i128(score.chain_atoms));
    let expected_challenger_wins =
        expected_score_atoms.is_none_or(|score| score != witness.claimed_score_atoms);
    if witness.corrected_challenger_wins != expected_challenger_wins {
        return Err(EdgesObjectiveError::CorrectedOutcomeMismatch {
            expected: expected_challenger_wins,
            supplied: witness.corrected_challenger_wins,
        });
    }
    if witness.corrected_challenger_wins == witness.pending_challenger_wins {
        return Err(EdgesObjectiveError::NonContradictoryOutcome);
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

pub fn verify_edges_vs_triangles(raw: &[u8]) -> Option<EdgesScore> {
    if raw.len() > EDGES_MAX_SOLUTION_BYTES {
        return None;
    }
    let solution: EdgesSolution = serde_json::from_slice(raw).ok()?;
    if !json_number_equals(&solution.atoms, EDGES_ATOMS as u64)
        || !json_number_equals(&solution.row_sum, EDGES_ROW_SUM as u64)
    {
        return None;
    }
    if solution.rows.0.is_empty() {
        return None;
    }

    let mut points = Vec::with_capacity(solution.rows.0.len());
    for row in &solution.rows.0 {
        let mut total = 0u128;
        let mut sum2 = 0u128;
        let mut sum3 = 0u128;
        for raw_value in row {
            let value = u128::from(*raw_value);
            if value > EDGES_ROW_SUM {
                return None;
            }
            total = total.checked_add(value)?;
            let square = value.checked_mul(value)?;
            sum2 = sum2.checked_add(square)?;
            sum3 = sum3.checked_add(square.checked_mul(value)?)?;
        }
        if total != EDGES_ROW_SUM || sum2 > X_SCALE || sum3 > Y_SCALE {
            return None;
        }
        let x_numerator = X_SCALE.checked_sub(sum2)?;
        let y_numerator = Y_SCALE
            .checked_add(sum3.checked_mul(2)?)?
            .checked_sub(sum2.checked_mul(3_000)?)?;
        if y_numerator > Y_SCALE {
            return None;
        }
        points.push((x_numerator, y_numerator));
    }

    points.sort_unstable();
    let mut unique_points: Vec<(u128, u128)> = Vec::with_capacity(points.len());
    for point in points {
        // Tuple sorting puts the minimum y first for each x, matching Python's
        // by_x[x] = min(y) reduction.
        if unique_points
            .last()
            .is_some_and(|previous| previous.0 == point.0)
        {
            continue;
        }
        unique_points.push(point);
    }
    let mut canonical = Vec::with_capacity(unique_points.len() + 2);
    canonical.push((0, 0));
    canonical.extend(unique_points);
    canonical.push((X_SCALE, Y_SCALE));

    let mut area_scaled = 0u128;
    let mut max_gap_numerator = 0u128;
    for pair in canonical.windows(2) {
        let left = pair[0];
        let right = pair[1];
        let width = right.0.checked_sub(left.0)?;
        max_gap_numerator = max_gap_numerator.max(width);
        let segment = segment_area_scaled(left, right)?;
        let segment_bound = width.checked_mul(AREA_SCALE / X_SCALE)?;
        if segment > segment_bound {
            return None;
        }
        area_scaled = area_scaled.checked_add(segment)?;
    }
    if area_scaled > AREA_SCALE || max_gap_numerator > X_SCALE {
        return None;
    }

    let gap_penalty_scaled = max_gap_numerator
        .checked_mul(10)?
        .checked_mul(AREA_SCALE / X_SCALE)?;
    let total_scaled = area_scaled.checked_add(gap_penalty_scaled)?;
    let chain_atoms_u128 = total_scaled.checked_add(5)?.checked_div(6)?;
    let chain_atoms = i128::try_from(chain_atoms_u128).ok()?;
    Some(EdgesScore {
        area_scaled,
        max_gap_numerator,
        total_scaled,
        chain_atoms,
    })
}

// All point coordinates are in [0,1]. AREA_SCALE is lcm(2*X_SCALE*Y_SCALE,
// 6*Y_SCALE^2), so every branch is integral at this scale. A segment is at
// most its width, all widths sum to one, and the gap penalty is at most ten.
// Thus area_scaled <= 6e18 and total_scaled <= 66e18. The largest seed or
// improvement cross-product below is <= 1.546875e36, about 220 times below
// u128::MAX.
fn segment_area_scaled(left: (u128, u128), right: (u128, u128)) -> Option<u128> {
    let width = right.0.checked_sub(left.0)?;
    if width == 0 {
        return Some(0);
    }
    if left.1 > right.1 {
        return left.1.checked_mul(width)?.checked_mul(6_000);
    }
    let slope_span = width.checked_mul(3_000)?;
    let slope_tip = left.1.checked_add(slope_span)?;
    if slope_tip <= right.1 {
        return left
            .1
            .checked_add(slope_tip)?
            .checked_mul(width)?
            .checked_mul(3_000);
    }
    let rise = right.1.checked_sub(left.1)?;
    let flat = slope_span.checked_sub(rise)?;
    left.1
        .checked_add(right.1)?
        .checked_mul(rise)?
        .checked_add(right.1.checked_mul(flat)?.checked_mul(2)?)
}

fn is_minimum_improvement(
    total_scaled: u128,
    seed_abs_numerator: u128,
    seed_denominator: u128,
    min_improvement_denominator: u128,
) -> bool {
    if seed_denominator == 0 || min_improvement_denominator == 0 {
        return false;
    }
    let Some(seed_scaled) = seed_abs_numerator.checked_mul(AREA_SCALE) else {
        return false;
    };
    let Some(score_scaled) = total_scaled.checked_mul(seed_denominator) else {
        return false;
    };
    let Some(delta) = seed_scaled.checked_sub(score_scaled) else {
        return false;
    };
    if !AREA_SCALE.is_multiple_of(min_improvement_denominator) {
        return false;
    }
    seed_denominator
        .checked_mul(AREA_SCALE / min_improvement_denominator)
        .is_some_and(|minimum_delta| delta >= minimum_delta)
}

fn deserialize_solution_cid<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_SOLUTION_CID_BYTES>(deserializer)
}

fn deserialize_transcript_uri<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_TRANSCRIPT_URI_BYTES>(deserializer)
}

fn deserialize_solution<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, EDGES_MAX_SOLUTION_BYTES>(deserializer)
}

fn deserialize_bounded_bytes<'de, D, const MAX: usize>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedBytes<const MAX: usize>;

    impl<'de, const MAX: usize> de::Visitor<'de> for BoundedBytes<MAX> {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX} bytes")
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.len() > MAX {
                return Err(E::custom(format!("byte length exceeds {MAX}")));
            }
            Ok(value.to_vec())
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.len() > MAX {
                return Err(E::custom(format!("byte length exceeds {MAX}")));
            }
            Ok(value)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let size_hint = seq.size_hint().unwrap_or(0);
            if size_hint > MAX {
                return Err(de::Error::custom(format!("byte length exceeds {MAX}")));
            }
            let mut value = Vec::with_capacity(size_hint.min(MAX));
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
    bytes.resize(bytes.len() + (padded_tag_len - tag.len()), 0);
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

pub fn word_i128(value: i128) -> Word {
    let mut word = if value < 0 { [0xff; 32] } else { [0u8; 32] };
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

#[derive(Debug)]
struct EdgesSolution {
    atoms: serde_json::Number,
    row_sum: serde_json::Number,
    rows: BoundedRows,
}

fn json_number_equals(value: &serde_json::Number, expected: u64) -> bool {
    if let Some(value) = value.as_u64() {
        return value == expected;
    }
    value
        .as_f64()
        .is_some_and(|value| value.is_finite() && value == expected as f64)
}

#[derive(Debug)]
struct BoundedRows(Vec<[u16; EDGES_ATOMS]>);

impl<'de> Deserialize<'de> for BoundedRows {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RowsVisitor;
        impl<'de> de::Visitor<'de> for RowsVisitor {
            type Value = BoundedRows;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "1..={EDGES_MAX_ROWS} rows of {EDGES_ATOMS} integers"
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut rows = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(EDGES_MAX_ROWS));
                while let Some(row) = seq.next_element::<[u16; EDGES_ATOMS]>()? {
                    if rows.len() == EDGES_MAX_ROWS {
                        return Err(de::Error::custom(format!(
                            "row count exceeds {EDGES_MAX_ROWS}"
                        )));
                    }
                    rows.push(row);
                }
                Ok(BoundedRows(rows))
            }
        }
        deserializer.deserialize_seq(RowsVisitor)
    }
}

impl<'de> Deserialize<'de> for EdgesSolution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SolutionVisitor;
        impl<'de> de::Visitor<'de> for SolutionVisitor {
            type Value = EdgesSolution;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an edges-vs-triangles solution object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut atoms = None;
                let mut row_sum = None;
                let mut rows = None;
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate key: {key}")));
                    }
                    match key.as_str() {
                        "atoms" => atoms = Some(map.next_value()?),
                        "row_sum" => row_sum = Some(map.next_value()?),
                        "rows" => rows = Some(map.next_value()?),
                        "source" | "claimed_score" => {
                            map.next_value::<String>()?;
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &key,
                                &["atoms", "row_sum", "rows", "source", "claimed_score"],
                            ))
                        }
                    }
                }
                Ok(EdgesSolution {
                    atoms: atoms.ok_or_else(|| de::Error::missing_field("atoms"))?,
                    row_sum: row_sum.ok_or_else(|| de::Error::missing_field("row_sum"))?,
                    rows: rows.ok_or_else(|| de::Error::missing_field("rows"))?,
                })
            }
        }
        deserializer.deserialize_map(SolutionVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::path::Path;

    #[derive(Deserialize)]
    struct DifferentialDocument {
        schema: String,
        vectors: Vec<DifferentialVector>,
        acceptance_vectors: Vec<AcceptanceVector>,
    }

    #[derive(Deserialize)]
    struct DifferentialVector {
        name: String,
        fixture: Option<String>,
        rows: Option<Vec<[u16; EDGES_ATOMS]>>,
        area_scaled: String,
        max_gap_numerator: String,
        chain_atoms: String,
    }

    #[derive(Deserialize)]
    struct AcceptanceVector {
        name: String,
        raw: String,
        accepted: bool,
    }

    #[test]
    fn seed_matches_exact_python_score_and_maximize_atoms() {
        let score = verify_edges_vs_triangles(&fixture("rational-curve-sample.json")).unwrap();
        assert_eq!(score.area_scaled, 1_271_176_273_187_542_784);
        assert_eq!(score.max_gap_numerator, 50_000);
        assert_eq!(score.total_scaled, 4_271_176_273_187_542_784);
        assert_eq!(score.chain_atoms, 711_862_712_197_923_798);
        assert!(!is_minimum_improvement(
            score.total_scaled,
            SEED_ABS_NUMERATOR,
            SEED_DENOMINATOR,
            MIN_IMPROVEMENT_DENOMINATOR,
        ));
    }

    #[test]
    fn worst_case_resource_fixture_preserves_seed_score() {
        let seed = verify_edges_vs_triangles(&fixture("rational-curve-sample.json")).unwrap();
        let worst =
            verify_edges_vs_triangles(&fixture_local("fixtures/worst-case-500-rows.json")).unwrap();
        assert_eq!(worst, seed);
    }

    #[test]
    fn shared_python_fraction_vectors_match_rust() {
        let document: DifferentialDocument =
            serde_json::from_slice(&fixture_local("fixtures/differential-vectors.json")).unwrap();
        assert_eq!(document.schema, "p42-edges-objective-differential/v1");
        assert_eq!(document.vectors.len(), 5);
        for vector in document.vectors {
            let raw = if let Some(path) = vector.fixture {
                std::fs::read(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../../..")
                        .join(path),
                )
                .unwrap()
            } else {
                serde_json::to_vec(&serde_json::json!({
                    "atoms": EDGES_ATOMS,
                    "row_sum": EDGES_ROW_SUM,
                    "rows": vector.rows.unwrap(),
                }))
                .unwrap()
            };
            let score = verify_edges_vs_triangles(&raw)
                .unwrap_or_else(|| panic!("Rust rejected differential vector {}", vector.name));
            assert_eq!(
                score.area_scaled,
                vector.area_scaled.parse::<u128>().unwrap()
            );
            assert_eq!(
                score.chain_atoms,
                vector.chain_atoms.parse::<i128>().unwrap()
            );
            assert_eq!(
                score.max_gap_numerator,
                vector.max_gap_numerator.parse::<u128>().unwrap()
            );
        }
        for vector in document.acceptance_vectors {
            assert_eq!(
                verify_edges_vs_triangles(vector.raw.as_bytes()).is_some(),
                vector.accepted,
                "acceptance mismatch for {}",
                vector.name,
            );
        }
    }

    #[test]
    fn segment_formula_covers_every_python_branch() {
        assert_eq!(segment_area_scaled((0, 800), (10, 700)), Some(48_000_000));
        assert_eq!(
            segment_area_scaled((0, 100), (10, 40_000)),
            Some(906_000_000)
        );
        assert_eq!(
            segment_area_scaled((0, 100), (10, 10_000)),
            Some(501_990_000)
        );
        assert_eq!(segment_area_scaled((10, 100), (10, 200)), Some(0));
    }

    #[test]
    fn strict_json_and_shape_boundaries_fail_closed() {
        for raw in [
            br#"{"atoms":20,"atoms":20,"row_sum":1000,"rows":[[1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}"#.as_slice(),
            br#"{"atoms":true,"row_sum":1000,"rows":[[1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}"#.as_slice(),
            br#"{"atoms":20,"row_sum":1000,"rows":[]}"#.as_slice(),
            br#"{"atoms":20,"row_sum":1000,"rows":[[1001,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}"#.as_slice(),
            br#"{"atoms":20,"row_sum":1000,"rows":[[999,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}"#.as_slice(),
        ] {
            assert!(verify_edges_vs_triangles(raw).is_none());
        }
        assert!(verify_edges_vs_triangles(&vec![b' '; EDGES_MAX_SOLUTION_BYTES + 1]).is_none());
    }

    #[test]
    fn exact_minimum_improvement_uses_scaled_delta_before_atom_rounding() {
        const THRESHOLD: u128 = AREA_SCALE / MIN_IMPROVEMENT_DENOMINATOR;
        assert_eq!(THRESHOLD, 6_000_000);
        let below = AREA_SCALE - (THRESHOLD - 1);
        let at = AREA_SCALE - THRESHOLD;
        let above = AREA_SCALE - (THRESHOLD + 1);

        assert!(!is_minimum_improvement(
            below,
            1,
            1,
            MIN_IMPROVEMENT_DENOMINATOR,
        ));
        assert!(is_minimum_improvement(
            at,
            1,
            1,
            MIN_IMPROVEMENT_DENOMINATOR,
        ));
        assert!(is_minimum_improvement(
            above,
            1,
            1,
            MIN_IMPROVEMENT_DENOMINATOR,
        ));

        let atoms = |total: u128| total.checked_add(5).unwrap() / 6;
        assert_eq!(atoms(at), atoms(above));
        assert_eq!(atoms(below), atoms(at) + 1);
        assert_ne!(AREA_SCALE - at, AREA_SCALE - above);

        let max_product = AREA_SCALE
            .checked_mul(11)
            .unwrap()
            .checked_mul(SEED_DENOMINATOR)
            .unwrap();
        assert_eq!(
            max_product,
            1_546_875_000_000_000_000_000_000_000_000_000_000
        );
        assert!(u128::MAX / max_product >= 219);
    }

    #[test]
    fn row_count_and_duplicate_x_boundaries_match_python() {
        let row = "[1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        let exactly_500 = format!(
            "{{\"atoms\":20,\"row_sum\":1000,\"rows\":[{}]}}",
            std::iter::repeat(row)
                .take(500)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(verify_edges_vs_triangles(exactly_500.as_bytes()).is_some());
        let too_many = format!(
            "{{\"atoms\":20,\"row_sum\":1000,\"rows\":[{}]}}",
            std::iter::repeat(row)
                .take(501)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(verify_edges_vs_triangles(too_many.as_bytes()).is_none());

        let same_x_different_y = verify_edges_vs_triangles(
            br#"{"atoms":20,"row_sum":1000,"rows":[[430,168,76,326,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[196,418,330,56,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}"#,
        )
        .unwrap();
        let lower_y_only = verify_edges_vs_triangles(
            br#"{"atoms":20,"row_sum":1000,"rows":[[196,418,330,56,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}"#,
        )
        .unwrap();
        assert_eq!(same_x_different_y, lower_y_only);
    }

    #[test]
    fn objective_outcome_and_full_journal_are_fail_closed() {
        let solution = fixture("rational-curve-sample.json");
        let score = verify_edges_vs_triangles(&solution).unwrap();
        let witness = ObjectiveWitness {
            chain_id: word_u128(84_532),
            quorum: [0x11; 20],
            manager: [0x22; 20],
            submission_manager: [0x33; 20],
            registry: [0x44; 20],
            problem_id: word_u128(3),
            objective_package_hash: [0x55; 32],
            guest_elf_sha256: [0xdd; 32],
            program_vkey: [0xee; 32],
            submission_id: word_u128(7),
            solver: [0x66; 20],
            commitment: [0x77; 32],
            commit_da_hash: sha256(&solution),
            solution_cid: b"ipfs://p42-edges-objective-fixture".to_vec(),
            claimed_score_atoms: word_i128(score.chain_atoms),
            improvement_atoms: word_u128(1_000_000),
            challenge_ends_at: word_u128(2_000_000_300),
            challenger: [0x88; 20],
            reason_hash: [0x99; 32],
            challenged_at: word_u128(2_000_000_100),
            dispute_ends_at: word_u128(2_000_000_200),
            pending_challenger_wins: false,
            transcript_hash: [0xaa; 32],
            transcript_uri: b"ipfs://p42-edges-transcript".to_vec(),
            verdict_hash: [0xbb; 32],
            corrected_challenger_wins: true,
            proof_beneficiary: [0xcc; 20],
            solution,
        };
        assert_eq!(
            verify_edges_vs_triangles_and_journal(&witness).unwrap(),
            hex_word("7da3db058aa4c42dd54e590ce850e884c3504680dd29b25034046961f423033d")
        );

        let mut honest = witness.clone();
        honest.pending_challenger_wins = true;
        honest.corrected_challenger_wins = false;
        assert!(verify_edges_vs_triangles_and_journal_against_seed(
            &honest,
            SEED_ABS_NUMERATOR + SEED_DENOMINATOR,
            SEED_DENOMINATOR,
            MIN_IMPROVEMENT_DENOMINATOR,
        )
        .is_ok());

        let mut mismatched = witness.clone();
        mismatched.corrected_challenger_wins = false;
        assert!(matches!(
            verify_edges_vs_triangles_and_journal(&mismatched),
            Err(EdgesObjectiveError::CorrectedOutcomeMismatch { .. })
        ));

        let mut non_contradictory = witness.clone();
        non_contradictory.pending_challenger_wins = true;
        assert!(matches!(
            verify_edges_vs_triangles_and_journal(&non_contradictory),
            Err(EdgesObjectiveError::NonContradictoryOutcome)
        ));
    }

    #[test]
    fn signed_int256_words_sign_extend() {
        assert_eq!(word_i128(7), word_u128(7));
        assert_eq!(word_i128(-1), [0xff; 32]);
        assert_eq!(&word_i128(-2)[..16], &[0xff; 16]);
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../problems/edges-vs-triangles/examples")
                .join(name),
        )
        .unwrap()
    }

    fn fixture_local(path: &str) -> Vec<u8> {
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path)).unwrap()
    }

    fn hex_word(value: &str) -> Word {
        assert_eq!(value.len(), 64);
        let mut word = [0u8; 32];
        for (index, byte) in word.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        word
    }
}
