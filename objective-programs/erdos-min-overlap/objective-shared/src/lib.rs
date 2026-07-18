use p42_objective_core::{keccak256, sha256, word_address, word_bool, Address, Word};
use serde::{
    de::{IgnoredAny, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;
use std::{
    collections::HashSet,
    fmt::{self, Write},
};

const PYTHON_INT_MAX_STR_DIGITS: usize = 4_300;
pub const MAX_JSON_CONTAINER_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalDocument {
    pub n: Option<Value>,
    pub denominator_power: Option<Value>,
    pub values: Option<Value>,
}

impl<'de> Deserialize<'de> for CanonicalDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DocumentVisitor;

        impl<'de> Visitor<'de> for DocumentVisitor {
            type Value = CanonicalDocument;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut n = None;
                let mut denominator_power = None;
                let mut values = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "n" => n = Some(map.next_value()?),
                        "denominator_power" => denominator_power = Some(map.next_value()?),
                        "values" => values = Some(map.next_value()?),
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(CanonicalDocument {
                    n,
                    denominator_power,
                    values,
                })
            }
        }

        deserializer.deserialize_map(DocumentVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    Encoding,
    Syntax,
    RootNotObject,
}

/// Parse the candidate production domain derived from exact-main at 1b65b84.
/// CPython byte encoding detection is reproduced before duplicate-key,
/// integer-token, and explicit container-depth checks. Only authority-bearing
/// fields are retained.
pub fn parse_canonical_document(raw: &[u8]) -> Result<CanonicalDocument, JsonError> {
    let decoded = decode_python_json_bytes(raw)?;
    DuplicateScanner::new(&decoded.text, &decoded.raw_surrogate_escapes).parse_document()?;
    if decoded
        .text
        .bytes()
        .find(|byte| !matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        != Some(b'{')
    {
        return Err(JsonError::RootNotObject);
    }
    let sanitized = sanitize_surrogate_escapes(decoded.text);
    let mut deserializer = serde_json::Deserializer::from_str(&sanitized);
    deserializer.disable_recursion_limit();
    let document =
        CanonicalDocument::deserialize(serde_stacker::Deserializer::new(&mut deserializer))
            .map_err(|_| JsonError::Syntax)?;
    deserializer.end().map_err(|_| JsonError::Syntax)?;
    Ok(document)
}

pub fn number_equals_python(value: Option<&Value>, expected: u64) -> bool {
    let Some(number) = value.and_then(Value::as_number) else {
        return false;
    };
    let text = number.to_string();
    if text.contains(['.', 'e', 'E']) {
        return text
            .parse::<f64>()
            .is_ok_and(|value| value == expected as f64);
    }
    text.parse::<u64>().is_ok_and(|value| value == expected)
}

struct DecodedJson {
    text: String,
    raw_surrogate_escapes: HashSet<usize>,
}

fn decode_python_json_bytes(raw: &[u8]) -> Result<DecodedJson, JsonError> {
    if let Some(bytes) = raw.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return decode_utf8_surrogatepass(bytes);
    }
    if let Some(bytes) = raw.strip_prefix(&[0xff, 0xfe, 0x00, 0x00]) {
        return decode_utf32(bytes, true);
    }
    if let Some(bytes) = raw.strip_prefix(&[0x00, 0x00, 0xfe, 0xff]) {
        return decode_utf32(bytes, false);
    }
    if let Some(bytes) = raw.strip_prefix(&[0xff, 0xfe]) {
        return decode_utf16(bytes, true);
    }
    if let Some(bytes) = raw.strip_prefix(&[0xfe, 0xff]) {
        return decode_utf16(bytes, false);
    }

    let encoding = match raw.get(..4) {
        Some(prefix) if prefix[0] == 0 && prefix[1] == 0 => 4,
        Some(prefix) if prefix[0] == 0 && prefix[2] == 0 => 2,
        Some(prefix) if prefix[1] == 0 && prefix[2] == 0 => 5,
        Some(prefix) if prefix[1] == 0 => 3,
        _ => 0,
    };
    match encoding {
        2 => decode_utf16(raw, false),
        3 => decode_utf16(raw, true),
        4 => decode_utf32(raw, false),
        5 => decode_utf32(raw, true),
        _ => decode_utf8_surrogatepass(raw),
    }
}

fn decode_utf8_surrogatepass(raw: &[u8]) -> Result<DecodedJson, JsonError> {
    let mut decoded = DecodedJson {
        text: String::with_capacity(raw.len()),
        raw_surrogate_escapes: HashSet::new(),
    };
    let mut index = 0;
    while index < raw.len() {
        let first = raw[index];
        if first.is_ascii() {
            decoded.text.push(char::from(first));
            index += 1;
            continue;
        }
        let (length, minimum, mut codepoint) = match first {
            0xc2..=0xdf => (2, 0x80, u32::from(first & 0x1f)),
            0xe0..=0xef => (3, 0x800, u32::from(first & 0x0f)),
            0xf0..=0xf4 => (4, 0x10000, u32::from(first & 0x07)),
            _ => return Err(JsonError::Encoding),
        };
        let sequence = raw.get(index..index + length).ok_or(JsonError::Encoding)?;
        for byte in &sequence[1..] {
            if byte & 0xc0 != 0x80 {
                return Err(JsonError::Encoding);
            }
            codepoint = (codepoint << 6) | u32::from(byte & 0x3f);
        }
        if codepoint < minimum || codepoint > 0x10ffff {
            return Err(JsonError::Encoding);
        }
        push_codepoint(&mut decoded, codepoint)?;
        index += length;
    }
    Ok(decoded)
}

fn decode_utf16(raw: &[u8], little_endian: bool) -> Result<DecodedJson, JsonError> {
    if !raw.len().is_multiple_of(2) {
        return Err(JsonError::Encoding);
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    let mut decoded = DecodedJson {
        text: String::with_capacity(raw.len() / 2),
        raw_surrogate_escapes: HashSet::new(),
    };
    let mut index = 0;
    while index < units.len() {
        let first = units[index];
        if (0xd800..=0xdbff).contains(&first)
            && units
                .get(index + 1)
                .is_some_and(|second| (0xdc00..=0xdfff).contains(second))
        {
            let second = units[index + 1];
            let codepoint =
                0x10000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00);
            decoded
                .text
                .push(char::from_u32(codepoint).ok_or(JsonError::Encoding)?);
            index += 2;
        } else {
            push_codepoint(&mut decoded, u32::from(first))?;
            index += 1;
        }
    }
    Ok(decoded)
}

fn decode_utf32(raw: &[u8], little_endian: bool) -> Result<DecodedJson, JsonError> {
    if !raw.len().is_multiple_of(4) {
        return Err(JsonError::Encoding);
    }
    let mut decoded = DecodedJson {
        text: String::with_capacity(raw.len() / 4),
        raw_surrogate_escapes: HashSet::new(),
    };
    for quad in raw.chunks_exact(4) {
        let value = if little_endian {
            u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]])
        } else {
            u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]])
        };
        if value > 0x10ffff {
            return Err(JsonError::Encoding);
        }
        push_codepoint(&mut decoded, value)?;
    }
    Ok(decoded)
}

fn push_codepoint(decoded: &mut DecodedJson, codepoint: u32) -> Result<(), JsonError> {
    if (0xd800..=0xdfff).contains(&codepoint) {
        decoded.raw_surrogate_escapes.insert(decoded.text.len());
        write!(decoded.text, "\\u{codepoint:04x}").map_err(|_| JsonError::Encoding)
    } else {
        decoded
            .text
            .push(char::from_u32(codepoint).ok_or(JsonError::Encoding)?);
        Ok(())
    }
}

// CPython accepts raw and escaped lone surrogates in JSON strings, while Rust
// strings cannot represent them. Raw code points carry provenance through the
// duplicate scan; replacing active surrogate escapes afterward leaves all
// retained authority-bearing numeric fields unchanged.
fn sanitize_surrogate_escapes(mut text: String) -> String {
    let bytes = unsafe { text.as_bytes_mut() };
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                in_string = !in_string;
                index += 1;
            }
            b'\\' if in_string => {
                if index + 5 < bytes.len() && bytes[index + 1] == b'u' {
                    let hex = &bytes[index + 2..index + 6];
                    if let Ok(value) =
                        u16::from_str_radix(std::str::from_utf8(hex).unwrap_or(""), 16)
                    {
                        if (0xd800..=0xdfff).contains(&value) {
                            bytes[index + 2..index + 6].copy_from_slice(b"0000");
                        }
                    }
                    index += 6;
                } else {
                    index += 2;
                }
            }
            _ => index += 1,
        }
    }
    text
}

struct DuplicateScanner<'a> {
    bytes: &'a [u8],
    raw_surrogate_escapes: &'a HashSet<usize>,
    index: usize,
    depth: usize,
}

impl<'a> DuplicateScanner<'a> {
    fn new(text: &'a str, raw_surrogate_escapes: &'a HashSet<usize>) -> Self {
        Self {
            bytes: text.as_bytes(),
            raw_surrogate_escapes,
            index: 0,
            depth: 0,
        }
    }

    fn parse_document(mut self) -> Result<(), JsonError> {
        self.skip_whitespace();
        self.parse_value()?;
        self.skip_whitespace();
        (self.index == self.bytes.len())
            .then_some(())
            .ok_or(JsonError::Syntax)
    }

    fn parse_value(&mut self) -> Result<(), JsonError> {
        stacker::maybe_grow(32 * 1024, 1024 * 1024, || self.parse_value_inner())
    }

    fn parse_value_inner(&mut self) -> Result<(), JsonError> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string().map(|_| ()),
            Some(b't') => self.parse_literal(b"true"),
            Some(b'f') => self.parse_literal(b"false"),
            Some(b'n') => self.parse_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(JsonError::Syntax),
        }
    }

    fn parse_object(&mut self) -> Result<(), JsonError> {
        self.enter_container()?;
        self.expect(b'{')?;
        self.skip_whitespace();
        let mut keys = HashSet::new();
        if self.consume(b'}') {
            self.depth -= 1;
            return Ok(());
        }
        loop {
            let key = self.parse_string()?;
            if !keys.insert(key) {
                return Err(JsonError::Syntax);
            }
            self.skip_whitespace();
            self.expect(b':')?;
            self.parse_value()?;
            self.skip_whitespace();
            if self.consume(b'}') {
                self.depth -= 1;
                return Ok(());
            }
            self.expect(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_array(&mut self) -> Result<(), JsonError> {
        self.enter_container()?;
        self.expect(b'[')?;
        self.skip_whitespace();
        if self.consume(b']') {
            self.depth -= 1;
            return Ok(());
        }
        loop {
            self.parse_value()?;
            self.skip_whitespace();
            if self.consume(b']') {
                self.depth -= 1;
                return Ok(());
            }
            self.expect(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_string(&mut self) -> Result<Vec<u32>, JsonError> {
        self.expect(b'"')?;
        let mut decoded = Vec::new();
        loop {
            let byte = *self.bytes.get(self.index).ok_or(JsonError::Syntax)?;
            match byte {
                b'"' => {
                    self.index += 1;
                    return Ok(decoded);
                }
                b'\\' => {
                    let escape_start = self.index;
                    self.index += 1;
                    if self.raw_surrogate_escapes.contains(&self.index) {
                        return Err(JsonError::Syntax);
                    }
                    let escape = *self.bytes.get(self.index).ok_or(JsonError::Syntax)?;
                    self.index += 1;
                    match escape {
                        b'"' | b'\\' | b'/' => decoded.push(u32::from(escape)),
                        b'b' => decoded.push(0x08),
                        b'f' => decoded.push(0x0c),
                        b'n' => decoded.push(0x0a),
                        b'r' => decoded.push(0x0d),
                        b't' => decoded.push(0x09),
                        b'u' => {
                            let first = self.parse_hex_quad()?;
                            if (0xd800..=0xdbff).contains(&first)
                                && !self.raw_surrogate_escapes.contains(&escape_start)
                                && self.bytes.get(self.index..self.index + 2) == Some(b"\\u")
                                && !self.raw_surrogate_escapes.contains(&self.index)
                            {
                                let saved = self.index;
                                self.index += 2;
                                let second = self.parse_hex_quad()?;
                                if (0xdc00..=0xdfff).contains(&second) {
                                    decoded.push(
                                        0x10000
                                            + ((u32::from(first) - 0xd800) << 10)
                                            + (u32::from(second) - 0xdc00),
                                    );
                                } else {
                                    decoded.push(u32::from(first));
                                    self.index = saved;
                                }
                            } else {
                                decoded.push(u32::from(first));
                            }
                        }
                        _ => return Err(JsonError::Syntax),
                    }
                }
                0x00..=0x1f => return Err(JsonError::Syntax),
                _ if byte.is_ascii() => {
                    decoded.push(u32::from(byte));
                    self.index += 1;
                }
                _ => {
                    let text = std::str::from_utf8(&self.bytes[self.index..])
                        .map_err(|_| JsonError::Encoding)?;
                    let character = text.chars().next().ok_or(JsonError::Syntax)?;
                    decoded.push(character as u32);
                    self.index += character.len_utf8();
                }
            }
        }
    }

    fn parse_hex_quad(&mut self) -> Result<u16, JsonError> {
        let end = self.index.checked_add(4).ok_or(JsonError::Syntax)?;
        let bytes = self.bytes.get(self.index..end).ok_or(JsonError::Syntax)?;
        let text = std::str::from_utf8(bytes).map_err(|_| JsonError::Syntax)?;
        let value = u16::from_str_radix(text, 16).map_err(|_| JsonError::Syntax)?;
        self.index = end;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<(), JsonError> {
        let start = self.index;
        if self.consume(b'-') && self.peek().is_none() {
            return Err(JsonError::Syntax);
        }
        if self.consume(b'0') {
            if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(JsonError::Syntax);
            }
        } else {
            self.consume_digits(true)?;
        }
        let mut integer = true;
        if self.consume(b'.') {
            integer = false;
            self.consume_digits(true)?;
        }
        if self.peek().is_some_and(|byte| matches!(byte, b'e' | b'E')) {
            integer = false;
            self.index += 1;
            if self.peek().is_some_and(|byte| matches!(byte, b'+' | b'-')) {
                self.index += 1;
            }
            self.consume_digits(true)?;
        }
        if integer {
            let digits = &self.bytes[start..self.index];
            let count = digits.iter().filter(|byte| byte.is_ascii_digit()).count();
            if count > PYTHON_INT_MAX_STR_DIGITS {
                return Err(JsonError::Syntax);
            }
        }
        Ok(())
    }

    fn consume_digits(&mut self, require_one: bool) -> Result<(), JsonError> {
        let start = self.index;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.index += 1;
        }
        if require_one && self.index == start {
            return Err(JsonError::Syntax);
        }
        Ok(())
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), JsonError> {
        if self.bytes.get(self.index..self.index + literal.len()) != Some(literal) {
            return Err(JsonError::Syntax);
        }
        self.index += literal.len();
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.index += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), JsonError> {
        self.consume(expected)
            .then_some(())
            .ok_or(JsonError::Syntax)
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn enter_container(&mut self) -> Result<(), JsonError> {
        self.depth += 1;
        if self.depth > MAX_JSON_CONTAINER_DEPTH {
            return Err(JsonError::Syntax);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ObjectiveContext<'a> {
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
    pub solution_cid: &'a [u8],
    pub claimed_score_atoms: Word,
    pub improvement_atoms: Word,
    pub challenge_ends_at: Word,
    pub challenger: Address,
    pub reason_hash: Word,
    pub challenged_at: Word,
    pub dispute_ends_at: Word,
    pub pending_challenger_wins: bool,
    pub transcript_hash: Word,
    pub transcript_uri: &'a [u8],
    pub verdict_hash: Word,
    pub corrected_challenger_wins: bool,
    pub proof_beneficiary: Address,
    pub solution: &'a [u8],
}

pub fn word_i128(value: i128) -> Word {
    let mut word = [if value < 0 { 0xff } else { 0x00 }; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    SolutionAnchorMismatch,
    SolutionCidOutOfBounds,
    TranscriptUriOutOfBounds,
    CorrectedOutcomeMismatch,
    NonContradictoryOutcome,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

pub fn verdict_journal_v2(
    witness: &ObjectiveContext<'_>,
    expected_score_atoms: Option<Word>,
) -> Result<Word, JournalError> {
    if witness.solution_cid.is_empty() || witness.solution_cid.len() > 512 {
        return Err(JournalError::SolutionCidOutOfBounds);
    }
    if witness.transcript_uri.is_empty() || witness.transcript_uri.len() > 512 {
        return Err(JournalError::TranscriptUriOutOfBounds);
    }
    if sha256(witness.solution) != witness.commit_da_hash {
        return Err(JournalError::SolutionAnchorMismatch);
    }
    let expected_challenger_wins =
        expected_score_atoms.is_none_or(|score| score != witness.claimed_score_atoms);
    if witness.corrected_challenger_wins != expected_challenger_wins {
        return Err(JournalError::CorrectedOutcomeMismatch);
    }
    if witness.corrected_challenger_wins == witness.pending_challenger_wins {
        return Err(JournalError::NonContradictoryOutcome);
    }

    let reveal_instance_hash = keccak_words(&[
        word_address(witness.submission_manager),
        witness.chain_id,
        witness.submission_id,
        word_address(witness.solver),
        witness.commitment,
        witness.commit_da_hash,
        keccak256(witness.solution_cid),
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
        keccak256(witness.transcript_uri),
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
    bytes.extend_from_slice(&word_usize(head_words * 32));
    for word in words {
        bytes.extend_from_slice(word);
    }
    bytes.extend_from_slice(&word_usize(tag.len()));
    bytes.extend_from_slice(tag);
    bytes.resize(bytes.len() + padded_tag_len - tag.len(), 0);
    keccak256(&bytes)
}

fn word_usize(value: usize) -> Word {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&(value as u64).to_be_bytes());
    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use p42_objective_core::word_u128;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        vectors: Vec<Vector>,
    }
    #[derive(Deserialize)]
    struct Vector {
        name: String,
        encoding: String,
        payload: String,
        accepted: bool,
        integer_n: Option<u64>,
    }

    #[derive(Deserialize)]
    struct RawSurrogateFixture {
        encodings: Vec<String>,
        unit_vectors: Vec<RawSurrogateVector>,
    }

    #[derive(Deserialize)]
    struct RawSurrogateVector {
        name: String,
        units: Vec<u32>,
        accepted: bool,
    }

    fn encode(vector: &Vector) -> Vec<u8> {
        match vector.encoding.as_str() {
            "utf-8" => vector.payload.as_bytes().to_vec(),
            "utf-8-sig" => [&[0xef, 0xbb, 0xbf], vector.payload.as_bytes()].concat(),
            "utf-16-le-bom" => {
                let mut raw = vec![0xff, 0xfe];
                for unit in vector.payload.encode_utf16() {
                    raw.extend_from_slice(&unit.to_le_bytes());
                }
                raw
            }
            "utf-16-be" => vector
                .payload
                .encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect(),
            "utf-32-le" => vector
                .payload
                .chars()
                .flat_map(|c| (c as u32).to_le_bytes())
                .collect(),
            "utf-32-be" => vector
                .payload
                .chars()
                .flat_map(|c| (c as u32).to_be_bytes())
                .collect(),
            other => panic!("unsupported fixture encoding {other}"),
        }
    }

    fn encode_raw_json(encoding: &str, before: &str, units: &[u32], after: &str) -> Vec<u8> {
        match encoding {
            "utf-8" | "utf-8-sig" => {
                let mut raw = if encoding == "utf-8-sig" {
                    vec![0xef, 0xbb, 0xbf]
                } else {
                    Vec::new()
                };
                let codepoints = before
                    .chars()
                    .map(|character| character as u32)
                    .chain(units.iter().copied())
                    .chain(after.chars().map(|character| character as u32));
                for codepoint in codepoints {
                    if let Some(character) = char::from_u32(codepoint) {
                        let mut bytes = [0; 4];
                        raw.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
                    } else {
                        raw.extend_from_slice(&[
                            0xe0 | ((codepoint >> 12) as u8),
                            0x80 | (((codepoint >> 6) & 0x3f) as u8),
                            0x80 | ((codepoint & 0x3f) as u8),
                        ]);
                    }
                }
                raw
            }
            "utf-16-le" | "utf-16-le-bom" | "utf-16-be" | "utf-16-be-bom" => {
                let little_endian = encoding.contains("-le");
                let mut raw = match encoding {
                    "utf-16-le-bom" => vec![0xff, 0xfe],
                    "utf-16-be-bom" => vec![0xfe, 0xff],
                    _ => Vec::new(),
                };
                let units = before
                    .encode_utf16()
                    .map(u32::from)
                    .chain(units.iter().copied())
                    .chain(after.encode_utf16().map(u32::from));
                for unit in units.map(|unit| unit as u16) {
                    let bytes = if little_endian {
                        unit.to_le_bytes()
                    } else {
                        unit.to_be_bytes()
                    };
                    raw.extend_from_slice(&bytes);
                }
                raw
            }
            "utf-32-le" | "utf-32-le-bom" | "utf-32-be" | "utf-32-be-bom" => {
                let little_endian = encoding.contains("-le");
                let mut raw = match encoding {
                    "utf-32-le-bom" => vec![0xff, 0xfe, 0x00, 0x00],
                    "utf-32-be-bom" => vec![0x00, 0x00, 0xfe, 0xff],
                    _ => Vec::new(),
                };
                let codepoints = before
                    .chars()
                    .map(|character| character as u32)
                    .chain(units.iter().copied())
                    .chain(after.chars().map(|character| character as u32));
                for codepoint in codepoints {
                    let bytes = if little_endian {
                        codepoint.to_le_bytes()
                    } else {
                        codepoint.to_be_bytes()
                    };
                    raw.extend_from_slice(&bytes);
                }
                raw
            }
            other => panic!("unsupported raw-surrogate encoding {other}"),
        }
    }

    #[test]
    fn hostile_vectors_match_declared_byte_domain() {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../fixtures/parser-hostile-vectors.json")).unwrap();
        for vector in fixture.vectors {
            let parsed = parse_canonical_document(&encode(&vector));
            assert_eq!(parsed.is_ok(), vector.accepted, "{}", vector.name);
            if let Ok(document) = parsed {
                let integer_n = document.n.as_ref().and_then(Value::as_u64);
                assert_eq!(integer_n, vector.integer_n, "{}", vector.name);
            }
        }
    }

    #[test]
    fn raw_surrogate_matrix_matches_declared_byte_domain() {
        let fixture: RawSurrogateFixture =
            serde_json::from_str(include_str!("../fixtures/raw-surrogate-vectors.json")).unwrap();
        for encoding in fixture.encodings {
            for vector in &fixture.unit_vectors {
                let raw = encode_raw_json(&encoding, r#"{"n":2,"meta":""#, &vector.units, r#""}"#);
                assert_eq!(
                    parse_canonical_document(&raw).is_ok(),
                    vector.accepted,
                    "{}:{}",
                    encoding,
                    vector.name
                );
            }
        }
    }

    #[test]
    fn raw_surrogate_duplicate_equivalence_preserves_decoder_semantics() {
        let encodings = ["utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"];
        for encoding in encodings {
            let lone_duplicate = encode_raw_json(
                encoding,
                r#"{"n":2,"meta":{""#,
                &[0xd800],
                r#"":1,"\ud800":2}}"#,
            );
            assert_eq!(
                parse_canonical_document(&lone_duplicate),
                Err(JsonError::Syntax),
                "{encoding}: raw lone surrogate must equal its JSON escape"
            );

            let pair_vs_scalar = encode_raw_json(
                encoding,
                r#"{"n":2,"meta":{""#,
                &[0xd83d, 0xde00],
                r#"":1,"😀":2}}"#,
            );
            assert_eq!(
                parse_canonical_document(&pair_vs_scalar).is_err(),
                encoding.starts_with("utf-16"),
                "{encoding}: only UTF-16 decoding combines a raw surrogate pair"
            );
        }

        for (before, units, after) in [
            (
                r#"{"n":2,"meta":{""#,
                &[0xd83d][..],
                r#"\ude00":1,"😀":2}}"#,
            ),
            (
                r#"{"n":2,"meta":{"\ud83d"#,
                &[0xde00][..],
                r#"":1,"😀":2}}"#,
            ),
        ] {
            let mixed = encode_raw_json("utf-8", before, units, after);
            assert!(parse_canonical_document(&mixed).is_ok());
        }

        for encoding in encodings {
            let odd_backslash =
                encode_raw_json(encoding, "{\"n\":2,\"meta\":\"\\", &[0xd800], "\"}");
            assert_eq!(
                parse_canonical_document(&odd_backslash),
                Err(JsonError::Syntax),
                "{encoding}: an active backslash before a raw surrogate is invalid"
            );

            let even_backslashes =
                encode_raw_json(encoding, "{\"n\":2,\"meta\":\"\\\\", &[0xd800], "\"}");
            assert!(
                parse_canonical_document(&even_backslashes).is_ok(),
                "{encoding}: an escaped backslash before a raw surrogate is valid"
            );
        }
    }

    #[test]
    fn surrogatepass_does_not_accept_other_invalid_encodings() {
        let prefix = br#"{"n":2,"meta":""#;
        let suffix = br#""}"#;
        for insertion in [
            &[0x80][..],
            &[0xc0, 0xaf][..],
            &[0xe2, 0x82][..],
            &[0xf4, 0x90, 0x80, 0x80][..],
        ] {
            let raw = [prefix.as_slice(), insertion, suffix.as_slice()].concat();
            assert_eq!(parse_canonical_document(&raw), Err(JsonError::Encoding));
        }

        let odd_utf16 = [
            r#"{"n":2,"meta":""#.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>(),
            vec![0x00],
        ]
        .concat();
        assert_eq!(
            parse_canonical_document(&odd_utf16),
            Err(JsonError::Encoding)
        );

        let utf32_above_unicode =
            encode_raw_json("utf-32-le", r#"{"n":2,"meta":""#, &[0x110000], r#""}"#);
        assert_eq!(
            parse_canonical_document(&utf32_above_unicode),
            Err(JsonError::Encoding)
        );
    }

    #[test]
    fn journal_matches_existing_core_and_solidity_vector() {
        let solution = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../problems/distinct-subset-sums-a11/tests/conway-guy-594.json"),
        )
        .unwrap();
        let context = ObjectiveContext {
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
            solution_cid: b"ipfs://p42-a11-objective-fixture",
            claimed_score_atoms: word_u128(594_000_000_000_000_000_000),
            improvement_atoms: word_u128(0),
            challenge_ends_at: word_u128(2_000_000_300),
            challenger: [0x88; 20],
            reason_hash: [0x99; 32],
            challenged_at: word_u128(2_000_000_100),
            dispute_ends_at: word_u128(2_000_000_200),
            pending_challenger_wins: false,
            transcript_hash: [0xaa; 32],
            transcript_uri: b"ipfs://p42-a11-transcript-fixture",
            verdict_hash: [0xbb; 32],
            corrected_challenger_wins: true,
            proof_beneficiary: [0xcc; 20],
            solution: &solution,
        };
        assert_eq!(
            hex::encode(verdict_journal_v2(&context, None).unwrap()),
            "561a4ba62b404deda35acc407e9e646cd5a2266dad80a550a626c417405be177"
        );
    }

    #[test]
    fn python_byte_encodings_and_surrogate_metadata() {
        let text = r#"{"n":2,"denominator_power":0,"values":[1,1],"meta":"\ud800"}"#;
        let mut utf16 = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        for raw in [
            text.as_bytes().to_vec(),
            [&[0xef, 0xbb, 0xbf], text.as_bytes()].concat(),
            utf16,
        ] {
            let document = parse_canonical_document(&raw).unwrap();
            assert_eq!(document.n, Some(Value::from(2)));
        }
    }

    #[test]
    fn duplicate_keys_are_rejected_after_escape_decoding() {
        for raw in [
            br#"{"n":1,"n":2}"#.as_slice(),
            br#"{"n":1,"\u006e":2}"#.as_slice(),
            br#"{"n":2,"meta":{"x":1,"x":2}}"#.as_slice(),
            r#"{"n":2,"meta":{"\ud83d\ude00":1,"😀":2}}"#.as_bytes(),
        ] {
            assert_eq!(parse_canonical_document(raw), Err(JsonError::Syntax));
        }
    }

    #[test]
    fn n_uses_python_numeric_equality() {
        for raw in [
            br#"{"n":2400}"#.as_slice(),
            br#"{"n":2400.0}"#.as_slice(),
            br#"{"n":2.4e3}"#.as_slice(),
        ] {
            let document = parse_canonical_document(raw).unwrap();
            assert!(number_equals_python(document.n.as_ref(), 2_400));
        }
        let boolean = parse_canonical_document(br#"{"n":true,"values":[]}"#).unwrap();
        assert!(!number_equals_python(boolean.n.as_ref(), 2_400));
        let nonintegral = parse_canonical_document(br#"{"n":2400.5}"#).unwrap();
        assert!(!number_equals_python(nonintegral.n.as_ref(), 2_400));
        let nonfinite = parse_canonical_document(br#"{"n":1e9999}"#).unwrap();
        assert!(!number_equals_python(nonfinite.n.as_ref(), 2_400));
    }

    #[test]
    fn python_integer_limit_and_consensus_depth_are_explicit() {
        let accepted = format!(r#"{{"n":2,"meta":{}}}"#, "9".repeat(4_300));
        assert!(parse_canonical_document(accepted.as_bytes()).is_ok());
        let rejected = format!(r#"{{"n":2,"meta":{}}}"#, "9".repeat(4_301));
        assert_eq!(
            parse_canonical_document(rejected.as_bytes()),
            Err(JsonError::Syntax)
        );

        let accepted = format!(
            r#"{{"n":2,"meta":{}0{}}}"#,
            "[".repeat(MAX_JSON_CONTAINER_DEPTH - 1),
            "]".repeat(MAX_JSON_CONTAINER_DEPTH - 1)
        );
        assert!(parse_canonical_document(accepted.as_bytes()).is_ok());
        let rejected = format!(
            r#"{{"n":2,"meta":{}0{}}}"#,
            "[".repeat(MAX_JSON_CONTAINER_DEPTH),
            "]".repeat(MAX_JSON_CONTAINER_DEPTH)
        );
        assert_eq!(
            parse_canonical_document(rejected.as_bytes()),
            Err(JsonError::Syntax)
        );
    }

    #[test]
    fn signed_words_use_solidity_int256_encoding() {
        assert_eq!(word_i128(-1), [0xff; 32]);
        assert_eq!(word_i128(0), [0x00; 32]);
        assert_eq!(word_i128(1)[31], 1);
    }
}
