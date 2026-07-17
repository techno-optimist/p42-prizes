use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::{collections::HashSet, fmt};
use tiny_keccak::{Hasher, Keccak};

pub type Word = [u8; 32];
pub type Address = [u8; 20];

pub const MAX_SOLUTION_CID_BYTES: usize = 512;
pub const MAX_TRANSCRIPT_URI_BYTES: usize = 512;
pub const MAX_WITNESS_SOLUTION_BYTES: usize = 1024 * 1024;
pub const SCORE_ATOM_SCALE: u128 = 1_000_000_000_000_000_000;

pub const Q6_EDGE_SIZE: usize = 6;
pub const Q6_MAX_EDGES: usize = 64;
pub const Q6_MAX_VERTICES: u64 = 321;
pub const Q6_MAX_HITTING_SET: usize = 5;
pub const Q6_SEED_BEST: u64 = 18;
pub const Q6_MAX_SOLUTION_BYTES: usize = 64 * 1024;

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
pub enum Q6ObjectiveError {
    SolutionAnchorMismatch,
    SolutionCidOutOfBounds { got: usize },
    TranscriptUriOutOfBounds { got: usize },
    CorrectedOutcomeMismatch { expected: bool, supplied: bool },
    NonContradictoryOutcome,
}

impl fmt::Display for Q6ObjectiveError {
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

pub fn verify_q6_intersecting_hypergraph_and_journal(
    witness: &ObjectiveWitness,
) -> Result<Word, Q6ObjectiveError> {
    verify_q6_intersecting_hypergraph_and_journal_against_seed(witness, Q6_SEED_BEST)
}

fn verify_q6_intersecting_hypergraph_and_journal_against_seed(
    witness: &ObjectiveWitness,
    seed_best: u64,
) -> Result<Word, Q6ObjectiveError> {
    if witness.solution_cid.is_empty() || witness.solution_cid.len() > MAX_SOLUTION_CID_BYTES {
        return Err(Q6ObjectiveError::SolutionCidOutOfBounds {
            got: witness.solution_cid.len(),
        });
    }
    if witness.transcript_uri.is_empty() || witness.transcript_uri.len() > MAX_TRANSCRIPT_URI_BYTES
    {
        return Err(Q6ObjectiveError::TranscriptUriOutOfBounds {
            got: witness.transcript_uri.len(),
        });
    }
    if sha256(&witness.solution) != witness.commit_da_hash {
        return Err(Q6ObjectiveError::SolutionAnchorMismatch);
    }

    let expected_score_atoms = verify_q6_intersecting_hypergraph(&witness.solution)
        .filter(|edges| *edges < seed_best)
        .and_then(score_atoms);
    let expected_challenger_wins =
        expected_score_atoms.is_none_or(|score| score != witness.claimed_score_atoms);
    if witness.corrected_challenger_wins != expected_challenger_wins {
        return Err(Q6ObjectiveError::CorrectedOutcomeMismatch {
            expected: expected_challenger_wins,
            supplied: witness.corrected_challenger_wins,
        });
    }
    if witness.corrected_challenger_wins == witness.pending_challenger_wins {
        return Err(Q6ObjectiveError::NonContradictoryOutcome);
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

pub fn verify_q6_intersecting_hypergraph(raw: &[u8]) -> Option<u64> {
    if raw.len() > Q6_MAX_SOLUTION_BYTES {
        return None;
    }
    let solution: Q6Solution = serde_json::from_slice(raw).ok()?;
    if solution.vertices < Q6_EDGE_SIZE as u64 || solution.vertices > Q6_MAX_VERTICES {
        return None;
    }
    if solution.edges.is_empty() || solution.edges.len() > Q6_MAX_EDGES {
        return None;
    }

    let mut edges = Vec::with_capacity(solution.edges.len());
    for mut edge in solution.edges {
        if edge.len() != Q6_EDGE_SIZE || edge.iter().any(|vertex| *vertex >= solution.vertices) {
            return None;
        }
        edge.sort_unstable();
        if edge.windows(2).any(|pair| pair[0] == pair[1]) || edges.contains(&edge) {
            return None;
        }
        edges.push(edge);
    }
    for left in 0..edges.len() {
        for right in (left + 1)..edges.len() {
            if !edges[left]
                .iter()
                .any(|vertex| edges[right].binary_search(vertex).is_ok())
            {
                return None;
            }
        }
    }
    if q6_has_hitting_set(&edges, &mut Vec::new(), Q6_MAX_HITTING_SET) {
        return None;
    }
    Some(edges.len() as u64)
}

fn q6_has_hitting_set(edges: &[Vec<u64>], chosen: &mut Vec<u64>, budget: usize) -> bool {
    let target = edges
        .iter()
        .find(|edge| !edge.iter().any(|vertex| chosen.contains(vertex)));
    let Some(target) = target else { return true };
    if budget == 0 {
        return false;
    }
    for vertex in target {
        chosen.push(*vertex);
        if q6_has_hitting_set(edges, chosen, budget - 1) {
            return true;
        }
        chosen.pop();
    }
    false
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

#[derive(Debug)]
struct Q6Solution {
    vertices: u64,
    edges: Vec<Vec<u64>>,
}

impl<'de> Deserialize<'de> for Q6Solution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SolutionVisitor;
        impl<'de> de::Visitor<'de> for SolutionVisitor {
            type Value = Q6Solution;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a q6 intersecting-hypergraph solution object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut vertices = None;
                let mut edges = None;
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate key: {key}")));
                    }
                    match key.as_str() {
                        "vertices" => vertices = Some(map.next_value()?),
                        "edges" => edges = Some(map.next_value()?),
                        "source" | "claimed_score" | "claimed_improvement" => {
                            map.next_value::<String>()?;
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &key,
                                &[
                                    "vertices",
                                    "edges",
                                    "source",
                                    "claimed_score",
                                    "claimed_improvement",
                                ],
                            ))
                        }
                    }
                }
                Ok(Q6Solution {
                    vertices: vertices.ok_or_else(|| de::Error::missing_field("vertices"))?,
                    edges: edges.ok_or_else(|| de::Error::missing_field("edges"))?,
                })
            }
        }
        deserializer.deserialize_map(SolutionVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn matches_packaged_exact_verifier_fixtures() {
        assert_eq!(
            verify_q6_intersecting_hypergraph(&fixture("seed-pg25.json")),
            Some(18)
        );
        assert_eq!(
            verify_q6_intersecting_hypergraph(&fixture("lying-claim.json")),
            Some(19)
        );
        for name in [
            "boundary-tau5.json",
            "coverable-sunflower.json",
            "duplicate-edge.json",
            "edge-size.json",
            "malformed.json",
            "not-intersecting.json",
            "vertex-range.json",
        ] {
            assert!(
                verify_q6_intersecting_hypergraph(&fixture(name)).is_none(),
                "fixture {name}"
            );
        }
        assert!(verify_q6_intersecting_hypergraph(
            br#"{"vertices":6,"vertices":6,"edges":[[0,1,2,3,4,5]]}"#
        )
        .is_none());
        assert!(verify_q6_intersecting_hypergraph(
            br#"{"vertices":6,"edges":[[0,1,2,3,4,5]],"unknown":1}"#
        )
        .is_none());
        assert!(verify_q6_intersecting_hypergraph(
            br#"{"vertices":6,"edges":[[0,1,2,3,4,5]],"source":"\ud800"}"#
        )
        .is_none());
        assert!(
            verify_q6_intersecting_hypergraph(&vec![b' '; Q6_MAX_SOLUTION_BYTES + 1]).is_none()
        );
    }

    #[test]
    fn objective_journal_rejects_a_false_improvement_claim() {
        let solution = fixture("seed-pg25.json");
        let witness = ObjectiveWitness {
            chain_id: word_u128(84_532),
            quorum: [0x11; 20],
            manager: [0x22; 20],
            submission_manager: [0x33; 20],
            registry: [0x44; 20],
            problem_id: word_u128(1),
            objective_package_hash: [0x55; 32],
            guest_elf_sha256: [0xdd; 32],
            program_vkey: [0xee; 32],
            submission_id: word_u128(7),
            solver: [0x66; 20],
            commitment: [0x77; 32],
            commit_da_hash: sha256(&solution),
            solution_cid: b"ipfs://p42-q6-objective-fixture".to_vec(),
            claimed_score_atoms: score_atoms(17).unwrap(),
            improvement_atoms: score_atoms(1).unwrap(),
            challenge_ends_at: word_u128(2_000_000_300),
            challenger: [0x88; 20],
            reason_hash: [0x99; 32],
            challenged_at: word_u128(2_000_000_100),
            dispute_ends_at: word_u128(2_000_000_200),
            pending_challenger_wins: false,
            transcript_hash: [0xaa; 32],
            transcript_uri: b"ipfs://p42-q6-transcript".to_vec(),
            verdict_hash: [0xbb; 32],
            corrected_challenger_wins: true,
            proof_beneficiary: [0xcc; 20],
            solution,
        };
        let journal = verify_q6_intersecting_hypergraph_and_journal(&witness).unwrap();
        assert_eq!(
            journal,
            [
                0xfa, 0x23, 0x3a, 0x06, 0xc0, 0xc8, 0x86, 0xe0, 0x04, 0x20, 0x0d, 0xbd, 0xd5, 0x24,
                0xaa, 0x97, 0x06, 0x05, 0xfc, 0xe4, 0xca, 0xfe, 0x77, 0xe2, 0x17, 0x2c, 0x61, 0x51,
                0x2b, 0x85, 0x86, 0xc4,
            ]
        );

        let mut mismatched = witness.clone();
        mismatched.corrected_challenger_wins = false;
        assert!(matches!(
            verify_q6_intersecting_hypergraph_and_journal(&mismatched),
            Err(Q6ObjectiveError::CorrectedOutcomeMismatch {
                expected: true,
                supplied: false
            })
        ));

        let mut non_contradictory = witness.clone();
        non_contradictory.pending_challenger_wins = true;
        assert!(matches!(
            verify_q6_intersecting_hypergraph_and_journal(&non_contradictory),
            Err(Q6ObjectiveError::NonContradictoryOutcome)
        ));

        let mut honest = witness.clone();
        honest.claimed_score_atoms = score_atoms(18).unwrap();
        honest.pending_challenger_wins = true;
        honest.corrected_challenger_wins = false;
        assert!(verify_q6_intersecting_hypergraph_and_journal_against_seed(&honest, 19).is_ok());

        let mut oversized = witness.clone();
        oversized.solution = vec![b' '; Q6_MAX_SOLUTION_BYTES + 1];
        oversized.commit_da_hash = sha256(&oversized.solution);
        assert!(verify_q6_intersecting_hypergraph_and_journal(&oversized).is_ok());
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../problems/q6-intersecting-hypergraph/tests")
                .join(name),
        )
        .unwrap()
    }
}
