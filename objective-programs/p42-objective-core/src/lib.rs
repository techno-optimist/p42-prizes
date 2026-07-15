use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::{collections::HashSet, fmt};
use tiny_keccak::{Hasher, Keccak};

pub type Word = [u8; 32];
pub type Address = [u8; 20];

pub const HADAMARD_N: usize = 668;
pub const HADAMARD_ROW_HEX_DIGITS: usize = 167;
pub const HADAMARD_SEED_DEFECT: u64 = 55_444;
pub const A11_N: usize = 11;
pub const A11_SUBSET_COUNT: usize = 1 << A11_N;
pub const A11_MAX_ELEMENT: u64 = 1_000_000_000_000_000;
pub const A11_SEED_BEST: u64 = 594;
pub const A11_MAX_SOLUTION_BYTES: usize = 4 * 1024;
pub const MAX_SOLUTION_BYTES: usize = 256 * 1024;
pub const MAX_WITNESS_SOLUTION_BYTES: usize = 1024 * 1024;
pub const MAX_SOLUTION_CID_BYTES: usize = 512;
pub const MAX_TRANSCRIPT_URI_BYTES: usize = 512;
pub const SCORE_ATOM_SCALE: u128 = 1_000_000_000_000_000_000;

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

// The A11 guest uses a distinct wire-compatible witness type so its 4 KiB
// solution bound is enforced during deserialization, before allocation and
// hashing. Keep the field order and types synchronized with ObjectiveWitness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A11ObjectiveWitness {
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
    #[serde(deserialize_with = "deserialize_a11_solution")]
    pub solution: Vec<u8>,
}

impl From<A11ObjectiveWitness> for ObjectiveWitness {
    fn from(value: A11ObjectiveWitness) -> Self {
        Self {
            chain_id: value.chain_id,
            quorum: value.quorum,
            manager: value.manager,
            submission_manager: value.submission_manager,
            registry: value.registry,
            problem_id: value.problem_id,
            objective_package_hash: value.objective_package_hash,
            guest_elf_sha256: value.guest_elf_sha256,
            program_vkey: value.program_vkey,
            submission_id: value.submission_id,
            solver: value.solver,
            commitment: value.commitment,
            commit_da_hash: value.commit_da_hash,
            solution_cid: value.solution_cid,
            claimed_score_atoms: value.claimed_score_atoms,
            improvement_atoms: value.improvement_atoms,
            challenge_ends_at: value.challenge_ends_at,
            challenger: value.challenger,
            reason_hash: value.reason_hash,
            challenged_at: value.challenged_at,
            dispute_ends_at: value.dispute_ends_at,
            pending_challenger_wins: value.pending_challenger_wins,
            transcript_hash: value.transcript_hash,
            transcript_uri: value.transcript_uri,
            verdict_hash: value.verdict_hash,
            corrected_challenger_wins: value.corrected_challenger_wins,
            proof_beneficiary: value.proof_beneficiary,
            solution: value.solution,
        }
    }
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SolutionAnchorMismatch => write!(f, "solution bytes do not match commitDaHash"),
            Self::SolutionCidOutOfBounds { got } => write!(
                f,
                "solution CID length must be in 1..={MAX_SOLUTION_CID_BYTES} bytes, got {got}"
            ),
            Self::TranscriptUriOutOfBounds { got } => write!(
                f,
                "transcript URI length must be in 1..={MAX_TRANSCRIPT_URI_BYTES} bytes, got {got}"
            ),
            Self::CorrectedOutcomeMismatch { expected, supplied } => {
                write!(
                    f,
                    "corrected outcome mismatch: expected {expected}, supplied {supplied}"
                )
            }
            Self::NonContradictoryOutcome => {
                write!(f, "corrected outcome does not contradict pending outcome")
            }
        }
    }
}

pub fn verify_hadamard_668_and_journal(witness: &ObjectiveWitness) -> Result<Word, ObjectiveError> {
    verify_objective_and_journal(witness, |solution| {
        verify_hadamard_668(solution)
            .filter(|defect| *defect < HADAMARD_SEED_DEFECT)
            .and_then(score_atoms)
    })
}

pub fn verify_distinct_subset_sums_a11_and_journal(
    witness: &ObjectiveWitness,
) -> Result<Word, ObjectiveError> {
    verify_objective_and_journal(witness, |solution| {
        verify_distinct_subset_sums_a11_against_seed(solution, A11_SEED_BEST).and_then(score_atoms)
    })
}

fn verify_objective_and_journal<F>(
    witness: &ObjectiveWitness,
    expected_score_atoms: F,
) -> Result<Word, ObjectiveError>
where
    F: FnOnce(&[u8]) -> Option<Word>,
{
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

    let expected_score_atoms = expected_score_atoms(&witness.solution);
    let expected_challenger_wins =
        expected_score_atoms.is_none_or(|score| score != witness.claimed_score_atoms);

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

fn score_atoms(score: u64) -> Option<Word> {
    u128::from(score)
        .checked_mul(SCORE_ATOM_SCALE)
        .map(word_u128)
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
    deserialize_bounded_bytes::<D, MAX_WITNESS_SOLUTION_BYTES>(deserializer)
}

fn deserialize_a11_solution<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, A11_MAX_SOLUTION_BYTES>(deserializer)
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

pub fn verify_hadamard_668(raw: &[u8]) -> Option<u64> {
    if raw.len() > MAX_SOLUTION_BYTES {
        return None;
    }
    let solution: HadamardSolution = serde_json::from_slice(raw).ok()?;
    if solution.n != HADAMARD_N as u64 || solution.encoding != "hex-row-bits-v1" {
        return None;
    }
    if solution.rows.len() != HADAMARD_N {
        return None;
    }
    let rows: Option<Vec<[u64; 11]>> = solution
        .rows
        .iter()
        .map(|row| decode_hex_words(row))
        .collect();
    let rows = rows?;
    let mut defect = 0u64;
    for left in 0..HADAMARD_N {
        for right in (left + 1)..HADAMARD_N {
            let hamming: u32 = rows[left]
                .iter()
                .zip(&rows[right])
                .map(|(a, b)| (a ^ b).count_ones())
                .sum();
            if hamming != 334 {
                defect += 1;
            }
        }
    }
    Some(defect)
}

pub fn verify_distinct_subset_sums_a11(raw: &[u8]) -> Option<u64> {
    if raw.len() > A11_MAX_SOLUTION_BYTES {
        return None;
    }
    let solution: A11Solution = serde_json::from_slice(raw).ok()?;
    if solution.elements.len() != A11_N {
        return None;
    }
    if solution
        .elements
        .iter()
        .any(|value| *value == 0 || *value > A11_MAX_ELEMENT)
    {
        return None;
    }
    if solution.elements.windows(2).any(|pair| pair[1] <= pair[0]) {
        return None;
    }

    let mut sums = Vec::with_capacity(A11_SUBSET_COUNT);
    sums.push(0u64);
    for element in &solution.elements {
        let previous_len = sums.len();
        for index in 0..previous_len {
            sums.push(sums[index].checked_add(*element)?);
        }
    }
    if sums.len() != A11_SUBSET_COUNT {
        return None;
    }
    sums.sort_unstable();
    if sums.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }
    solution.elements.last().copied()
}

pub fn verify_distinct_subset_sums_a11_against_seed(raw: &[u8], seed: u64) -> Option<u64> {
    verify_distinct_subset_sums_a11(raw).filter(|score| *score < seed)
}

#[derive(Debug)]
struct A11Solution {
    elements: Vec<u64>,
}

impl<'de> Deserialize<'de> for A11Solution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SolutionVisitor;
        impl<'de> de::Visitor<'de> for SolutionVisitor {
            type Value = A11Solution;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a distinct-subset-sums A11 solution object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut elements = None;
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate key: {key}")));
                    }
                    match key.as_str() {
                        "set" => elements = Some(map.next_value()?),
                        "source" | "claimed_score" | "claimed_improvement" => {
                            map.next_value::<String>()?;
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &key,
                                &["set", "source", "claimed_score", "claimed_improvement"],
                            ))
                        }
                    }
                }
                Ok(A11Solution {
                    elements: elements.ok_or_else(|| de::Error::missing_field("set"))?,
                })
            }
        }
        deserializer.deserialize_map(SolutionVisitor)
    }
}

#[derive(Debug)]
struct HadamardSolution {
    n: u64,
    encoding: String,
    rows: Vec<String>,
}

impl<'de> Deserialize<'de> for HadamardSolution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SolutionVisitor;
        impl<'de> de::Visitor<'de> for SolutionVisitor {
            type Value = HadamardSolution;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Hadamard solution object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut n = None;
                let mut encoding = None;
                let mut rows = None;
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate key: {key}")));
                    }
                    match key.as_str() {
                        "n" => n = Some(map.next_value()?),
                        "encoding" => encoding = Some(map.next_value()?),
                        "rows" => rows = Some(map.next_value()?),
                        _ => {
                            map.next_value::<StrictIgnored>()?;
                        }
                    }
                }
                Ok(HadamardSolution {
                    n: n.ok_or_else(|| de::Error::missing_field("n"))?,
                    encoding: encoding.ok_or_else(|| de::Error::missing_field("encoding"))?,
                    rows: rows.ok_or_else(|| de::Error::missing_field("rows"))?,
                })
            }
        }
        deserializer.deserialize_map(SolutionVisitor)
    }
}

struct StrictIgnored;

impl<'de> Deserialize<'de> for StrictIgnored {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;
        impl<'de> de::Visitor<'de> for StrictVisitor {
            type Value = StrictIgnored;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(StrictIgnored)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(StrictIgnored)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(StrictIgnored)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(StrictIgnored)
            }
            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
                Ok(StrictIgnored)
            }
            fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
                Ok(StrictIgnored)
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictIgnored)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictIgnored)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                while seq.next_element::<StrictIgnored>()?.is_some() {}
                Ok(StrictIgnored)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate key: {key}")));
                    }
                    map.next_value::<StrictIgnored>()?;
                }
                Ok(StrictIgnored)
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn decode_hex_words(row: &str) -> Option<[u64; 11]> {
    if row.len() != HADAMARD_ROW_HEX_DIGITS || !row.is_ascii() {
        return None;
    }
    let mut words = [0u64; 11];
    for (index, byte) in row.bytes().enumerate() {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        let word_index = index / 16;
        words[word_index] = (words[word_index] << 4) | u64::from(nibble);
    }
    Some(words)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn rejects_duplicate_root_and_nested_unknown_keys() {
        let row = "0".repeat(HADAMARD_ROW_HEX_DIGITS);
        let duplicate =
            format!(r#"{{"n":668,"n":668,"encoding":"hex-row-bits-v1","rows":["{row}"]}}"#);
        assert!(verify_hadamard_668(duplicate.as_bytes()).is_none());
        let nested = format!(
            r#"{{"n":668,"encoding":"hex-row-bits-v1","rows":["{row}"],"ignored":{{"x":1,"x":2}}}}"#
        );
        assert!(verify_hadamard_668(nested.as_bytes()).is_none());
        assert!(
            verify_hadamard_668(br#"{"n":668.0,"encoding":"hex-row-bits-v1","rows":[]}"#).is_none()
        );
        assert!(verify_hadamard_668(&vec![b' '; MAX_SOLUTION_BYTES + 1]).is_none());
    }

    #[test]
    fn tagged_abi_encoding_matches_solidity_vector() {
        let got = keccak_tagged(
            b"P42_OBJECTIVE_VERDICT_JOURNAL_V2",
            &[[0x11; 32], [0x22; 32]],
        );
        assert_eq!(
            hex_word(got),
            "11270120a447dbe7f890b4f9e6c201c1fcadc2107f17e716a2b2a594e08f104e"
        );
    }

    #[test]
    fn full_hadamard_journal_matches_independent_ethers_vector() {
        let witness = fixture_witness();
        assert_eq!(verify_hadamard_668(&witness.solution), Some(55_444));
        let journal = verify_hadamard_668_and_journal(&witness).unwrap();
        let execution = artifact_json("execution.json");
        assert_eq!(
            hex_word(journal),
            execution["journalDigest"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x")
        );
    }

    #[test]
    fn distinct_subset_sums_matches_packaged_fixtures_and_frontier() {
        let seed = a11_fixture("conway-guy-594.json");
        assert_eq!(verify_distinct_subset_sums_a11(&seed), Some(594));
        assert_eq!(
            verify_distinct_subset_sums_a11_against_seed(&seed, A11_SEED_BEST),
            None
        );

        let powers = a11_fixture("lying-claim.json");
        assert_eq!(verify_distinct_subset_sums_a11(&powers), Some(1024));
        assert_eq!(
            verify_distinct_subset_sums_a11_against_seed(&powers, 1025),
            Some(1024)
        );
        assert_eq!(
            verify_distinct_subset_sums_a11(&a11_fixture("duplicate-sum.json")),
            None
        );
        assert_eq!(
            verify_distinct_subset_sums_a11(&a11_fixture("not-increasing.json")),
            None
        );
        assert_eq!(
            verify_distinct_subset_sums_a11(&a11_fixture("negative-element.json")),
            None
        );
    }

    #[test]
    fn distinct_subset_sums_matches_strict_finite_json_semantics() {
        let accepted_metadata = br#"{"set":[1,2,4,8,16,32,64,128,256,512,1024],"source":"fixture","claimed_score":"1/1"}"#;
        assert_eq!(
            verify_distinct_subset_sums_a11(accepted_metadata),
            Some(1024)
        );
        assert!(verify_distinct_subset_sums_a11(
            br#"{"set":[1,2,4,8,16,32,64,128,256,512,1024],"unknown":1}"#
        )
        .is_none());
        assert!(verify_distinct_subset_sums_a11(
            br#"{"set":[1,2,4,8,16,32,64,128,256,512,1024],"source":{"nested":[]}}"#
        )
        .is_none());
        assert!(verify_distinct_subset_sums_a11(
            br#"{"set":[1,2,4,8,16,32,64,128,256,512,1024],"source":"\ud800"}"#
        )
        .is_none());
        assert!(verify_distinct_subset_sums_a11(
            br#"{"set":[1,2,4,8,16,32,64,128,256,512,1024],"set":[1,2,4,8,16,32,64,128,256,512,1024]}"#
        )
        .is_none());
        assert!(verify_distinct_subset_sums_a11(
            br#"{"set":[1,2,4,8,16,32,64,128,256,512,1024],"ignored":{"x":1,"x":2}}"#
        )
        .is_none());
        assert!(verify_distinct_subset_sums_a11(
            br#"{"set":[true,2,4,8,16,32,64,128,256,512,1024]}"#
        )
        .is_none());
        assert!(verify_distinct_subset_sums_a11(
            br#"{"set":[1.0,2,4,8,16,32,64,128,256,512,1024]}"#
        )
        .is_none());
        assert!(verify_distinct_subset_sums_a11(&vec![b' '; A11_MAX_SOLUTION_BYTES + 1]).is_none());
    }

    #[test]
    fn distinct_subset_sums_objective_handles_challenger_and_honest_paths() {
        let seed = a11_fixture("conway-guy-594.json");
        let seed_witness = a11_witness(seed, A11_SEED_BEST, false, true);
        assert_eq!(
            hex_word(verify_distinct_subset_sums_a11_and_journal(&seed_witness).unwrap()),
            "561a4ba62b404deda35acc407e9e646cd5a2266dad80a550a626c417405be177"
        );

        let powers = a11_fixture("lying-claim.json");
        let honest = a11_witness(powers.clone(), 1024, true, false);
        let honest_score =
            verify_distinct_subset_sums_a11_against_seed(&powers, 1025).and_then(score_atoms);
        assert!(verify_objective_and_journal(&honest, |_| honest_score).is_ok());

        let wrong_claim = a11_witness(powers, 1023, true, false);
        assert!(matches!(
            verify_objective_and_journal(&wrong_claim, |_| honest_score),
            Err(ObjectiveError::CorrectedOutcomeMismatch {
                expected: true,
                supplied: false
            })
        ));
    }

    #[test]
    fn distinct_subset_sums_score_atom_conversion_is_checked() {
        assert_eq!(
            score_atoms(A11_MAX_ELEMENT),
            Some(word_u128(
                u128::from(A11_MAX_ELEMENT)
                    .checked_mul(SCORE_ATOM_SCALE)
                    .unwrap()
            ))
        );
        assert!(u128::from(A11_MAX_ELEMENT)
            .checked_mul(SCORE_ATOM_SCALE)
            .is_some());
    }

    #[test]
    fn bounds_variable_witness_fields_before_guest_execution() {
        let witness = fixture_witness();
        let encoded = bincode::serialize(&witness).unwrap();
        assert_eq!(
            bincode::deserialize::<ObjectiveWitness>(&encoded).unwrap(),
            witness
        );

        let mut oversized_cid = witness.clone();
        oversized_cid.solution_cid = vec![b'c'; MAX_SOLUTION_CID_BYTES + 1];
        assert!(matches!(
            verify_hadamard_668_and_journal(&oversized_cid),
            Err(ObjectiveError::SolutionCidOutOfBounds { got }) if got == MAX_SOLUTION_CID_BYTES + 1
        ));
        assert!(bincode::deserialize::<ObjectiveWitness>(
            &bincode::serialize(&oversized_cid).unwrap()
        )
        .is_err());

        let mut oversized_uri = witness.clone();
        oversized_uri.transcript_uri = vec![b'u'; MAX_TRANSCRIPT_URI_BYTES + 1];
        assert!(matches!(
            verify_hadamard_668_and_journal(&oversized_uri),
            Err(ObjectiveError::TranscriptUriOutOfBounds { got }) if got == MAX_TRANSCRIPT_URI_BYTES + 1
        ));
        assert!(bincode::deserialize::<ObjectiveWitness>(
            &bincode::serialize(&oversized_uri).unwrap()
        )
        .is_err());

        let mut oversized_solution = witness;
        oversized_solution.solution = vec![0; MAX_WITNESS_SOLUTION_BYTES + 1];
        assert!(bincode::deserialize::<ObjectiveWitness>(
            &bincode::serialize(&oversized_solution).unwrap()
        )
        .is_err());

        let a11 = a11_witness(
            a11_fixture("conway-guy-594.json"),
            A11_SEED_BEST,
            false,
            true,
        );
        let encoded = bincode::serialize(&a11).unwrap();
        let bounded = bincode::deserialize::<A11ObjectiveWitness>(&encoded).unwrap();
        assert_eq!(ObjectiveWitness::from(bounded), a11);

        let mut oversized_a11 = a11;
        oversized_a11.solution = vec![0; A11_MAX_SOLUTION_BYTES + 1];
        assert!(bincode::deserialize::<A11ObjectiveWitness>(
            &bincode::serialize(&oversized_a11).unwrap()
        )
        .is_err());
    }

    fn fixture_witness() -> ObjectiveWitness {
        let identity = artifact_json("identity.json");
        let solution = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../problems/hadamard-668-defect/examples/sylvester-prefix.json"),
        )
        .unwrap();
        ObjectiveWitness {
            chain_id: word_u128(84_532),
            quorum: [0x11; 20],
            manager: [0x22; 20],
            submission_manager: [0x33; 20],
            registry: [0x44; 20],
            problem_id: word_u128(10),
            objective_package_hash: [0x55; 32],
            guest_elf_sha256: hex_word_array(
                identity["guestElfSha256"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("sha256:"),
            ),
            program_vkey: hex_word_array(
                identity["programVKey"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            ),
            submission_id: word_u128(7),
            solver: [0x66; 20],
            commitment: [0x77; 32],
            commit_da_hash: sha256(&solution),
            solution_cid: b"ipfs://p42-objective-fixture".to_vec(),
            claimed_score_atoms: word_u128(55_444 * SCORE_ATOM_SCALE),
            improvement_atoms: word_u128(0),
            challenge_ends_at: word_u128(2_000_000_300),
            challenger: [0x88; 20],
            reason_hash: [0x99; 32],
            challenged_at: word_u128(2_000_000_100),
            dispute_ends_at: word_u128(2_000_000_200),
            pending_challenger_wins: false,
            transcript_hash: [0xaa; 32],
            transcript_uri: b"ipfs://p42-transcript-fixture".to_vec(),
            verdict_hash: [0xbb; 32],
            corrected_challenger_wins: true,
            proof_beneficiary: [0xcc; 20],
            solution,
        }
    }

    fn a11_witness(
        solution: Vec<u8>,
        claimed_score: u64,
        pending_challenger_wins: bool,
        corrected_challenger_wins: bool,
    ) -> ObjectiveWitness {
        ObjectiveWitness {
            chain_id: word_u128(84_532),
            quorum: [0x11; 20],
            manager: [0x22; 20],
            submission_manager: [0x33; 20],
            registry: [0x44; 20],
            problem_id: word_u128(7),
            objective_package_hash: [0x55; 32],
            guest_elf_sha256: [0xdd; 32],
            program_vkey: [0xee; 32],
            submission_id: word_u128(7),
            solver: [0x66; 20],
            commitment: [0x77; 32],
            commit_da_hash: sha256(&solution),
            solution_cid: b"ipfs://p42-a11-objective-fixture".to_vec(),
            claimed_score_atoms: score_atoms(claimed_score).unwrap(),
            improvement_atoms: word_u128(0),
            challenge_ends_at: word_u128(2_000_000_300),
            challenger: [0x88; 20],
            reason_hash: [0x99; 32],
            challenged_at: word_u128(2_000_000_100),
            dispute_ends_at: word_u128(2_000_000_200),
            pending_challenger_wins,
            transcript_hash: [0xaa; 32],
            transcript_uri: b"ipfs://p42-a11-transcript-fixture".to_vec(),
            verdict_hash: [0xbb; 32],
            corrected_challenger_wins,
            proof_beneficiary: [0xcc; 20],
            solution,
        }
    }

    fn a11_fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../problems/distinct-subset-sums-a11/tests")
                .join(name),
        )
        .unwrap()
    }

    fn artifact_json(name: &str) -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../artifacts/hadamard-668-defect/v0.1.0")
            .join(name);
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn hex_word(word: Word) -> String {
        word.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hex_word_array(value: &str) -> Word {
        assert_eq!(value.len(), 64);
        let mut word = [0u8; 32];
        for (index, byte) in word.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        word
    }
}
