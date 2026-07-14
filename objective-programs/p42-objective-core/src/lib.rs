use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::{collections::HashSet, fmt};
use tiny_keccak::{Hasher, Keccak};

pub type Word = [u8; 32];
pub type Address = [u8; 20];

pub const HADAMARD_N: usize = 668;
pub const HADAMARD_ROW_HEX_DIGITS: usize = 167;
pub const HADAMARD_SEED_DEFECT: u64 = 55_444;
pub const MAX_SOLUTION_BYTES: usize = 256 * 1024;
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
    pub transcript_uri: Vec<u8>,
    pub verdict_hash: Word,
    pub corrected_challenger_wins: bool,
    pub proof_beneficiary: Address,
    pub solution: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectiveError {
    SolutionAnchorMismatch,
    CorrectedOutcomeMismatch { expected: bool, supplied: bool },
    NonContradictoryOutcome,
}

impl fmt::Display for ObjectiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SolutionAnchorMismatch => write!(f, "solution bytes do not match commitDaHash"),
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
    if sha256(&witness.solution) != witness.commit_da_hash {
        return Err(ObjectiveError::SolutionAnchorMismatch);
    }

    let expected_score_atoms = verify_hadamard_668(&witness.solution)
        .filter(|defect| *defect < HADAMARD_SEED_DEFECT)
        .map(|defect| word_u128(u128::from(defect) * SCORE_ATOM_SCALE));
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
        let solution = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../problems/hadamard-668-defect/examples/sylvester-prefix.json"),
        )
        .unwrap();
        assert_eq!(verify_hadamard_668(&solution), Some(55_444));
        let witness = ObjectiveWitness {
            chain_id: word_u128(84_532),
            quorum: [0x11; 20],
            manager: [0x22; 20],
            submission_manager: [0x33; 20],
            registry: [0x44; 20],
            problem_id: word_u128(10),
            objective_package_hash: [0x55; 32],
            guest_elf_sha256: hex_word_array(
                "2cda9c4c278b5c5b72b56417d6c0d2c7a15f045898e69ead9b75a61026ca13a6",
            ),
            program_vkey: hex_word_array(
                "0016d27da623507d3e323cc70a9da608e55879c4d74481566040fc38bf7f9799",
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
        };
        let journal = verify_hadamard_668_and_journal(&witness).unwrap();
        assert_eq!(
            hex_word(journal),
            "b7fc3d85ad6a8606edb944c1883fd8feed8363a74b84697d81439f3a69c664fc"
        );
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
