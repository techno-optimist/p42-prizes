#!/usr/bin/env python3
"""Validate TypedTranscriptV1 structure without evaluating a permutation."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parent
SQUEEZE_TAGS = {"squeezeField", "squeezeBits", "squeezeExtension"}


class TranscriptValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def reject(code: str, message: str) -> None:
    raise TranscriptValidationError(code, message)


def load(name: str) -> dict[str, Any]:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def limbs_u64(value: int, radix: int, count: int) -> list[int]:
    if value < 0 or value >= radix**count:
        reject("INTEGER_RANGE", "value is outside the fixed-width u64 encoding")
    result = []
    for _ in range(count):
        result.append(value % radix)
        value //= radix
    return result


def canonical_envelope_bytes(spec: dict[str, Any], profile_name: str) -> bytes:
    profile = spec["fieldProfiles"][profile_name]
    envelope = spec["versionEnvelope"]
    magic = bytes.fromhex(envelope["wireMagicHex"][2:])
    wire = b"".join(
        [
            magic,
            spec["version"].to_bytes(2, "big"),
            bytes(
                [
                    profile["profileId"],
                    profile["fieldId"],
                    profile["permutationId"],
                    profile["rate"],
                    profile["width"],
                    envelope["reservedFinalByte"],
                ]
            ),
        ]
    )
    if len(wire) != envelope["wireLengthBytes"]:
        reject("SPEC_ENVELOPE_LENGTH", "canonical envelope has the wrong length")
    return wire


def canonical_envelope_hex(spec: dict[str, Any], profile_name: str) -> str:
    return "0x" + canonical_envelope_bytes(spec, profile_name).hex()


def envelope_field_words(spec: dict[str, Any], profile_name: str) -> list[int]:
    wire = canonical_envelope_bytes(spec, profile_name)
    word_bytes = spec["versionEnvelope"]["fieldWordBytes"]
    return [
        int.from_bytes(wire[start : start + word_bytes], "big")
        for start in range(0, len(wire), word_bytes)
    ]


def decode_envelope(spec: dict[str, Any], profile_name: str, envelope_hex: str | None) -> bytes:
    if envelope_hex is None:
        reject("ENVELOPE_MISSING", "transcript envelope is required")
    if not envelope_hex.startswith("0x"):
        reject("ENVELOPE_CANONICAL", "envelope must use lowercase 0x-prefixed hex")
    try:
        wire = bytes.fromhex(envelope_hex[2:])
    except ValueError:
        reject("ENVELOPE_CANONICAL", "envelope is not hexadecimal")
    if envelope_hex != "0x" + wire.hex():
        reject("ENVELOPE_CANONICAL", "envelope hex is not canonical lowercase")
    envelope = spec["versionEnvelope"]
    if len(wire) != envelope["wireLengthBytes"]:
        reject("ENVELOPE_LENGTH", "envelope must contain exactly 16 bytes")
    magic = bytes.fromhex(envelope["wireMagicHex"][2:])
    if wire[0:8] != magic:
        reject("ENVELOPE_MAGIC", "envelope magic mismatch")
    if int.from_bytes(wire[8:10], "big") != spec["version"]:
        reject("ENVELOPE_VERSION", "envelope version mismatch")
    profile = spec["fieldProfiles"][profile_name]
    if wire[10] != profile["profileId"]:
        reject("ENVELOPE_PROFILE", "envelope profile mismatch")
    expected_parameters = bytes(
        [
            profile["fieldId"],
            profile["permutationId"],
            profile["rate"],
            profile["width"],
            envelope["reservedFinalByte"],
        ]
    )
    if wire[11:16] != expected_parameters:
        reject("ENVELOPE_PARAMETERS", "envelope field or permutation parameters mismatch")
    return wire


def encode_event(spec: dict[str, Any], event: dict[str, Any]) -> list[int]:
    constants = spec["constants"]
    try:
        event_tag = spec["eventTags"][event["tag"]]
        encoding_tag = spec["encodingTags"][event["encoding"]]
    except KeyError as exc:
        reject("EVENT_TAG", f"unknown event or encoding tag: {exc}")
    payload = [int(word) for word in event["payload"]]
    radix = constants["lengthRadix"]
    limbs = constants["lengthLimbs"]
    return [
        constants["protocolMagic"],
        spec["version"],
        event_tag,
        encoding_tag,
        *limbs_u64(event["counter"], radix, limbs),
        *limbs_u64(event["logicalLength"], radix, limbs),
        *limbs_u64(len(payload), radix, limbs),
        *payload,
        constants["frameEnd"],
    ]


def decompose_packed_word(word: int, digits: int, radix: int, kb_modulus: int) -> list[int]:
    if digits < 1 or digits > 8:
        reject("PACKED_DIGIT_COUNT", "packed word must encode between one and eight digits")
    if word < 0:
        reject("NONCANONICAL_PACKED_WORD", "packed word cannot be negative")
    decomposition = []
    remaining = word
    for _ in range(digits):
        digit = remaining % radix
        if digit >= kb_modulus:
            reject("NONCANONICAL_KB_DIGIT", "packed base-2^31 digit is outside the KoalaBear field")
        decomposition.append(digit)
        remaining //= radix
    if remaining != 0:
        reject("UNDECLARED_PACKED_DIGIT", "packed word contains undeclared high digits")
    return decomposition


def validate_event_shape(
    spec: dict[str, Any], profile_name: str, event: dict[str, Any]
) -> None:
    tag = event["tag"]
    encoding = event["encoding"]
    logical_length = event["logicalLength"]
    payload = [int(word) for word in event["payload"]]
    payload_length = len(payload)
    constants = spec["constants"]
    packed_width = constants["koalaBearValuesPerBn254Word"]
    packing_radix = constants["koalaBearPackingRadix"]
    kb_modulus = int(spec["fieldProfiles"]["inner-koalabear-v1"]["modulus"])
    bn254_modulus = int(spec["fieldProfiles"]["outer-bn254-rate-koalabear-v1"]["modulus"])
    profile = spec["fieldProfiles"][profile_name]
    is_inner = profile_name == "inner-koalabear-v1"
    expected_payload_length: int | None = None

    if tag == "protocolInit":
        expected_payload = envelope_field_words(spec, profile_name)
        if (
            event["counter"] != 0
            or logical_length != spec["versionEnvelope"]["wireLengthBytes"]
            or encoding != "versionEnvelopeU16"
            or payload != expected_payload
        ):
            reject("INIT_ENVELOPE", "protocolInit must absorb the exact canonical version envelope")
        return
    if tag == "baseField":
        if is_inner and encoding == "koalaBearDirect":
            expected_payload_length = logical_length
        elif not is_inner and encoding == "koalaBearPacked8":
            expected_payload_length = (logical_length + packed_width - 1) // packed_width
    elif tag == "extensionField":
        coefficients = logical_length * 4
        if is_inner and encoding == "extension4KoalaBearDirect":
            expected_payload_length = coefficients
        elif not is_inner and encoding == "extension4KoalaBearPacked8":
            expected_payload_length = (coefficients + packed_width - 1) // packed_width
    elif tag in {"digest", "commitment"}:
        if is_inner and encoding == "koalaBearDigest8":
            expected_payload_length = logical_length * 8
        elif not is_inner and encoding == "koalaBearDigest8Packed8":
            expected_payload_length = logical_length
    elif tag in {"sliceBegin", "containerBegin"} and encoding == "container":
        expected_payload_length = 0
    elif tag in {"sliceEnd", "containerEnd"} and encoding == "container":
        if logical_length != 0:
            reject("EVENT_SHAPE", f"{tag} must have logical length zero")
        expected_payload_length = 0
    elif tag in SQUEEZE_TAGS and encoding == "squeezeRequest":
        if logical_length == 0:
            reject("EVENT_SHAPE", f"{tag} must request a nonzero output length")
        if tag == "squeezeBits" and logical_length > profile["maxSqueezeBits"]:
            reject("SQUEEZE_BITS_RANGE", "squeezeBits exceeds the profile bound")
        if tag == "squeezeExtension" and not profile["supportsSqueezeExtension"]:
            reject("EXTENSION_SQUEEZE_FORBIDDEN", "profile has no extension challenge encoding")
        expected_payload_length = 0

    if expected_payload_length is None or payload_length != expected_payload_length:
        reject("EVENT_SHAPE", f"invalid {tag}/{encoding} event shape")

    if encoding in {"koalaBearDirect", "extension4KoalaBearDirect", "koalaBearDigest8"}:
        if any(word < 0 or word >= kb_modulus for word in payload):
            reject("NONCANONICAL_KB_WORD", "direct KoalaBear payload word is noncanonical")
    elif encoding in {"koalaBearPacked8", "extension4KoalaBearPacked8"}:
        source_length = logical_length if encoding == "koalaBearPacked8" else logical_length * 4
        for index, word in enumerate(payload):
            digits = min(packed_width, source_length - index * packed_width)
            decompose_packed_word(word, digits, packing_radix, kb_modulus)
            if word >= bn254_modulus:
                reject("NONCANONICAL_BN254_WORD", "packed payload is outside BN254")
    elif encoding == "koalaBearDigest8Packed8":
        for word in payload:
            decompose_packed_word(word, packed_width, packing_radix, kb_modulus)
            if word >= bn254_modulus:
                reject("NONCANONICAL_BN254_WORD", "packed digest is outside BN254")


def block_control(
    spec: dict[str, Any],
    profile: dict[str, Any],
    phase_name: str,
    index: int,
    occupied: int,
    final: bool,
) -> int:
    constants = spec["constants"]
    if index >= 1 << constants["blockIndexBits"]:
        reject("BLOCK_LIMIT", "transition exceeds the block-index limit")
    return (
        constants["blockControlBase"]
        + (profile["profileId"] << constants["profileShift"])
        + (spec["phases"][phase_name] << constants["phaseShift"])
        + (int(final) << constants["finalShift"])
        + (occupied << constants["occupiedShift"])
        + index
    )


def absorb_blocks(spec: dict[str, Any], profile_name: str, words: list[int]) -> list[dict[str, Any]]:
    profile = spec["fieldProfiles"][profile_name]
    rate = profile["rate"]
    modulus = int(profile["modulus"])
    result = []
    for index, start in enumerate(range(0, len(words), rate)):
        chunk = words[start : start + rate]
        final = start + rate >= len(words)
        control = block_control(spec, profile, "absorbFrame", index, len(chunk), final)
        if control >= modulus or any(word < 0 or word >= modulus for word in chunk):
            reject("NONCANONICAL_BLOCK", "frame or control word is not canonical in the target field")
        result.append(
            {
                "index": index,
                "occupied": len(chunk),
                "final": final,
                "control": str(control),
                "rateWords": [str(word) for word in chunk + [0] * (rate - len(chunk))],
            }
        )
    return result


def squeeze_continuations(
    spec: dict[str, Any], profile_name: str, event: dict[str, Any]
) -> list[dict[str, Any]]:
    if event["tag"] not in SQUEEZE_TAGS:
        return []
    profile = spec["fieldProfiles"][profile_name]
    if event["tag"] == "squeezeBits":
        physical_outputs = 1
    elif event["tag"] == "squeezeExtension":
        physical_outputs = event["logicalLength"] * 4
    else:
        physical_outputs = event["logicalLength"]
    remaining = max(0, physical_outputs - profile["rate"])
    count = (remaining + profile["rate"] - 1) // profile["rate"]
    result = []
    for index in range(count):
        final = index + 1 == count
        control = block_control(spec, profile, "squeezeContinuation", index, 0, final)
        result.append(
            {
                "index": index,
                "occupied": 0,
                "final": final,
                "control": str(control),
                "rateWords": ["0"] * profile["rate"],
            }
        )
    return result


def snapshot(state: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(state)


def observe_child(state: dict[str, Any]) -> None:
    if state["collectionStack"]:
        state["collectionStack"][-1]["observedChildren"] += 1


def apply_event_state(state: dict[str, Any], event: dict[str, Any]) -> str:
    tag = event["tag"]
    if state["mode"] == "uninitialized":
        if tag != "protocolInit":
            reject("INIT_REQUIRED", "protocolInit must be the first event")
    elif tag == "protocolInit":
        reject("INIT_REPEATED", "protocolInit cannot be repeated")
    if event["counter"] != state["nextCounter"]:
        reject("COUNTER", "event counter is not consecutive")
    if tag in SQUEEZE_TAGS and state["collectionStack"]:
        reject(
            "SQUEEZE_IN_CONTAINER",
            "squeeze is forbidden while a slice or container remains open",
        )

    if tag == "protocolInit":
        state["mode"] = "absorbing"
    elif tag in {"sliceBegin", "containerBegin"}:
        observe_child(state)
        state["collectionStack"].append(
            {
                "kind": "slice" if tag == "sliceBegin" else "container",
                "declaredChildren": event["logicalLength"],
                "observedChildren": 0,
            }
        )
    elif tag in {"sliceEnd", "containerEnd"}:
        if not state["collectionStack"]:
            reject("NESTING", "collection end has no matching begin")
        frame = state["collectionStack"][-1]
        expected_kind = "slice" if tag == "sliceEnd" else "container"
        if frame["kind"] != expected_kind:
            reject("NESTING", "collection end kind does not match begin kind")
        if frame["observedChildren"] != frame["declaredChildren"]:
            reject("CHILD_COUNT", "collection child count does not match declaration")
        state["collectionStack"].pop()
    elif tag in SQUEEZE_TAGS:
        pass
    else:
        observe_child(state)

    state["nextCounter"] += 1
    if state["permutationStateStatus"] == "exact":
        state["permutationStateStatus"] = "not-generated"
        state["permutationState"] = None
    return "squeeze" if tag in SQUEEZE_TAGS else "absorb"


def initial_snapshot(spec: dict[str, Any], profile_name: str) -> dict[str, Any]:
    width = spec["fieldProfiles"][profile_name]["width"]
    return {
        "mode": "uninitialized",
        "nextCounter": 0,
        "collectionStack": [],
        "permutationStateStatus": "exact",
        "permutationState": ["0"] * width,
    }


def run_transcript(
    spec: dict[str, Any], profile_name: str, events: list[dict[str, Any]]
) -> dict[str, Any]:
    state = initial_snapshot(spec, profile_name)
    initial = snapshot(state)
    steps = []
    stream: list[int] = []
    for index, event in enumerate(events):
        before = snapshot(state)
        validate_event_shape(spec, profile_name, event)
        words = encode_event(spec, event)
        transition_kind = apply_event_state(state, event)
        after = snapshot(state)
        steps.append(
            {
                "index": index,
                "transitionKind": transition_kind,
                "expectedBefore": before,
                "expectedFrameWords": [str(word) for word in words],
                "expectedAbsorbBlocks": absorb_blocks(spec, profile_name, words),
                "expectedSqueezeContinuations": squeeze_continuations(spec, profile_name, event),
                "expectedAfter": after,
            }
        )
        stream.extend(words)
    if state["mode"] == "uninitialized":
        reject("INIT_REQUIRED", "transcript never initialized")
    if state["collectionStack"]:
        reject("NESTING", "transcript ended with an open collection")
    return {"expectedInitial": initial, "expectedSteps": steps, "expectedFinal": snapshot(state), "stream": stream}


def validate_spec_invariants(spec: dict[str, Any]) -> None:
    expected_profiles = {
        "inner-koalabear-v1": {
            "profileId": 1,
            "fieldId": 1,
            "permutationId": 1,
            "modulus": "2130706433",
            "width": 16,
            "rate": 8,
            "capacity": 8,
            "maxSqueezeBits": 30,
            "supportsSqueezeExtension": True,
            "rateField": "koalabear",
            "challengeField": "koalabear",
        },
        "outer-bn254-rate-koalabear-v1": {
            "profileId": 2,
            "fieldId": 2,
            "permutationId": 2,
            "modulus": "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            "width": 3,
            "rate": 2,
            "capacity": 1,
            "maxSqueezeBits": 30,
            "supportsSqueezeExtension": True,
            "rateField": "bn254",
            "challengeField": "koalabear",
        },
    }
    if spec["fieldProfiles"] != expected_profiles:
        reject("SPEC_PROFILE", "V1 field profiles must match the frozen profile definitions")
    envelope = spec["versionEnvelope"]
    if (
        envelope["wireLengthBytes"] != 16
        or envelope["wireMagicHex"] != "0x5034325454563100"
        or envelope["wireIntegerByteOrder"] != "big-endian"
        or envelope["fieldWordBytes"] != 2
        or envelope["fieldWordByteOrder"] != "big-endian"
        or envelope["reservedFinalByte"] != 0
    ):
        reject("SPEC_ENVELOPE", "V1 envelope parameters must match the frozen definition")
    profiles = list(spec["fieldProfiles"].values())
    for key in ("profileId", "fieldId", "permutationId"):
        if len({profile[key] for profile in profiles}) != len(profiles):
            reject("SPEC_ID", f"{key} values must be unique")
    for profile in profiles:
        if profile["width"] != profile["rate"] + profile["capacity"]:
            reject("SPEC_WIDTH", "profile width must equal rate plus capacity")
        if profile["rate"] > 15:
            reject("SPEC_RATE", "the occupied-lane control field is four bits")
        if profile["maxSqueezeBits"] != 30:
            reject("SPEC_SQUEEZE_BITS", "all exposed V1 bit challenges must be less than 31 bits")
    constants = spec["constants"]
    if not (
        constants["occupiedShift"] == constants["blockIndexBits"]
        and constants["finalShift"] >= constants["occupiedShift"] + 4
        and constants["phaseShift"] > constants["finalShift"]
        and constants["profileShift"] >= constants["phaseShift"] + 2
    ):
        reject("SPEC_CONTROL_LAYOUT", "capacity-control bit fields overlap")
    for namespace in ("eventTags", "encodingTags", "phases"):
        values = list(spec[namespace].values())
        if len(set(values)) != len(values):
            reject("SPEC_TAG", f"{namespace} values must be unique")
    for profile_name, profile in spec["fieldProfiles"].items():
        maximum = block_control(spec, profile, "squeezeContinuation", 65535, profile["rate"], True)
        if maximum >= int(profile["modulus"]):
            reject("SPEC_CONTROL_RANGE", f"capacity control is noncanonical for {profile_name}")
    extraction = spec["outerChallengeExtraction"]
    if extraction != {
        "source": "bn254-rate-word",
        "scalarMethod": "bn254-mod-koalabear",
        "koalaBearModulus": 2130706433,
        "extensionDegree": 4,
        "extensionBasis": "sp1-koalabear-extension4-pinned-by-successor-fork",
        "bitsMethod": "low-bits",
        "minChallengeBits": 1,
        "maxChallengeBits": 30,
        "nativeBn254Challenges": False,
    }:
        reject("SPEC_OUTER_EXTRACTION", "outer challenge extraction parameters are not frozen V1")
    expected_modes = {"core", "compressed", "shrink", "wrap", "groth16", "plonk"}
    if set(spec["proofModeRouting"]) != expected_modes:
        reject("SPEC_PROOF_MODES", "proof-mode routing matrix must be exhaustive")
    for mode, route in spec["proofModeRouting"].items():
        expected_profile = (
            "inner-koalabear-v1" if mode in {"core", "compressed", "shrink"}
            else "outer-bn254-rate-koalabear-v1"
        )
        expected_gateway = "validate-bind-strip-forward" if mode in {"groth16", "plonk"} else "none"
        if route["v1Profile"] != expected_profile or route["gateway"] != expected_gateway:
            reject("SPEC_PROOF_ROUTE", f"invalid V1 route for {mode}")
        if route["v0Decoder"] == route["v1Decoder"]:
            reject("SPEC_DECODER_ALIAS", f"V0 and V1 decoders alias for {mode}")
    gateway = spec["gateway"]
    if not (
        gateway["outerEnvelopeBytes"] == 16
        and gateway["outerProfile"] == "outer-bn254-rate-koalabear-v1"
        and gateway["requiresSuccessorProofEnvelopeBinding"]
        and gateway["stripAfterValidationOnly"]
        and not gateway["silentSdkStrippingAllowed"]
    ):
        reject("SPEC_GATEWAY", "P42 V1 gateway invariants are not frozen")


def validate_rejection(
    spec: dict[str, Any], rejection: dict[str, Any]
) -> None:
    try:
        if rejection["kind"] == "envelope":
            decode_envelope(spec, rejection["profile"], rejection["envelopeHex"])
        else:
            decode_envelope(spec, rejection["profile"], rejection["envelopeHex"])
            run_transcript(spec, rejection["profile"], rejection["events"])
    except TranscriptValidationError as exc:
        if exc.code != rejection["expectedErrorCode"]:
            raise ValueError(
                f"{rejection['id']}: expected {rejection['expectedErrorCode']}, got {exc.code}"
            ) from exc
    else:
        raise ValueError(f"{rejection['id']}: rejection vector was accepted")


def vector_category(vectors: dict[str, Any], category: str) -> list[dict[str, Any]]:
    return {
        "positive": vectors["positiveTranscripts"],
        "collision-negative": vectors["collisionNegativeTranscripts"],
        "rejection": vectors["rejectionVectors"],
        "outer-extraction": vectors["outerChallengeExtractionVectors"],
        "proof-decoding": vectors["proofDecodingVectors"],
        "gateway": vectors["gatewayVectors"],
    }[category]


def validate_global_vector_ids(vectors: dict[str, Any]) -> None:
    seen: set[str] = set()
    ids = []
    for category in (
        "positive", "collision-negative", "rejection", "outer-extraction",
        "proof-decoding", "gateway",
    ):
        for vector in vector_category(vectors, category):
            vector_id = vector["id"]
            if vector_id in seen:
                reject(
                    "DUPLICATE_VECTOR_ID",
                    f"vector ID {vector_id!r} is duplicated across vector categories",
                )
            seen.add(vector_id)
            ids.append(vector_id)
    if vectors["idRegistry"] != sorted(ids):
        reject("ID_REGISTRY", "idRegistry must equal the sorted global vector ID set")


def validate_independent_state_regression(
    spec: dict[str, Any], regression: dict[str, Any]
) -> None:
    state = copy.deepcopy(regression["before"])
    validate_event_shape(spec, regression["profile"], regression["event"])
    expected_error = regression["expectedErrorCode"]
    try:
        apply_event_state(state, regression["event"])
    except TranscriptValidationError as exc:
        if expected_error is None or exc.code != expected_error:
            raise ValueError(
                f"{regression['id']}: expected {expected_error or 'acceptance'}, got {exc.code}"
            ) from exc
    else:
        if expected_error is not None:
            raise ValueError(f"{regression['id']}: state transition was unexpectedly accepted")
    if state != regression["expectedAfter"]:
        raise ValueError(f"{regression['id']}: state transition did not match literal expectation")
    continuations = squeeze_continuations(spec, regression["profile"], regression["event"])
    if continuations != regression["expectedSqueezeContinuations"]:
        raise ValueError(f"{regression['id']}: squeeze continuation expectation mismatch")


def validate_hostile_id_mutation(vectors: dict[str, Any], mutation: dict[str, Any]) -> None:
    hostile = copy.deepcopy(vectors)
    source = vector_category(hostile, mutation["sourceCategory"])[mutation["sourceIndex"]]
    target = vector_category(hostile, mutation["targetCategory"])[mutation["targetIndex"]]
    target["id"] = source["id"]
    try:
        validate_global_vector_ids(hostile)
    except TranscriptValidationError as exc:
        if exc.code != mutation["expectedErrorCode"]:
            raise ValueError(
                f"{mutation['id']}: expected {mutation['expectedErrorCode']}, got {exc.code}"
            ) from exc
    else:
        raise ValueError(f"{mutation['id']}: duplicate ID mutation was accepted")


def extract_outer_challenge(
    spec: dict[str, Any], vector: dict[str, Any]
) -> tuple[list[str], int]:
    outer = spec["fieldProfiles"]["outer-bn254-rate-koalabear-v1"]
    modulus = int(outer["modulus"])
    extraction = spec["outerChallengeExtraction"]
    words = [int(word) for word in vector["rateWords"]]
    if any(word < 0 or word >= modulus for word in words):
        reject("NONCANONICAL_BN254_RATE_WORD", "outer rate word is not canonical BN254")
    kind = vector["kind"]
    if kind == "bits":
        bits = vector.get("bits")
        if bits is None or not extraction["minChallengeBits"] <= bits <= extraction["maxChallengeBits"]:
            reject("SQUEEZE_BITS_RANGE", "outer bit challenge must be in [1, 31)")
        if not words:
            reject("EXTRACTION_EXHAUSTED", "bit extraction requires one rate word")
        return [str(words[0] % (1 << bits))], 1

    required = 1 if kind == "scalar" else extraction["extensionDegree"]
    if len(words) < required:
        reject("EXTRACTION_EXHAUSTED", "rate words contain too few KoalaBear coefficients")
    values = [str(word % extraction["koalaBearModulus"]) for word in words[:required]]
    return values, required


def validate_outer_extraction(spec: dict[str, Any], vector: dict[str, Any]) -> None:
    expected_error = vector["expectedErrorCode"]
    try:
        values, consumed = extract_outer_challenge(spec, vector)
    except TranscriptValidationError as exc:
        if expected_error != exc.code:
            raise ValueError(f"{vector['id']}: expected {expected_error}, got {exc.code}") from exc
    else:
        if expected_error is not None:
            raise ValueError(f"{vector['id']}: extraction was unexpectedly accepted")
        if values != vector["expectedValues"] or consumed != vector["expectedConsumedRateWords"]:
            raise ValueError(f"{vector['id']}: outer extraction expectation mismatch")


def decode_hex_bytes(value: str, code: str) -> bytes:
    if not value.startswith("0x"):
        reject(code, "byte string must use lowercase 0x-prefixed hex")
    try:
        decoded = bytes.fromhex(value[2:])
    except ValueError:
        reject(code, "byte string is not hexadecimal")
    if value != "0x" + decoded.hex():
        reject(code, "byte string is not canonical lowercase hex")
    return decoded


def route_proof_decoder(spec: dict[str, Any], vector: dict[str, Any]) -> str:
    route = spec["proofModeRouting"][vector["proofMode"]]
    decoder_version = vector["decoderVersion"]
    input_version = vector["inputVersion"]
    if decoder_version != input_version:
        reject(
            "V0_TO_V1_DECODER" if decoder_version == "v1" else "V1_TO_V0_DECODER",
            "proof versions cannot be auto-detected, converted, or passed across decoders",
        )
    return route[f"{decoder_version}Decoder"]


def validate_decoding_vector(spec: dict[str, Any], vector: dict[str, Any]) -> None:
    expected_error = vector["expectedErrorCode"]
    try:
        decoder = route_proof_decoder(spec, vector)
    except TranscriptValidationError as exc:
        if expected_error != exc.code:
            raise ValueError(f"{vector['id']}: expected {expected_error}, got {exc.code}") from exc
    else:
        if expected_error is not None:
            raise ValueError(f"{vector['id']}: cross-version decode was unexpectedly accepted")
        if decoder != vector["expectedDecoder"]:
            raise ValueError(f"{vector['id']}: decoder route mismatch")


def run_gateway(spec: dict[str, Any], vector: dict[str, Any]) -> str:
    if vector["proofMode"] not in {"groth16", "plonk"}:
        reject("GATEWAY_PROOF_MODE", "P42 V1 gateway accepts only Groth16 or Plonk")
    presented = vector["presentedEnvelopeHex"]
    if presented is None:
        reject("ENVELOPE_MISSING", "P42 V1 gateway requires the outer envelope")
    presented_bytes = decode_envelope(
        spec, "outer-bn254-rate-koalabear-v1", presented
    )
    bound = vector["successorProofBoundEnvelopeHex"]
    if bound is None:
        reject("GATEWAY_ENVELOPE_UNBOUND", "successor wrapping proof must bind the envelope")
    bound_bytes = decode_hex_bytes(bound, "GATEWAY_BOUND_ENVELOPE")
    if presented_bytes != bound_bytes:
        reject("GATEWAY_ENVELOPE_BINDING", "presented and proof-bound envelopes differ")
    decode_envelope(spec, "outer-bn254-rate-koalabear-v1", bound)
    forwarded = decode_hex_bytes(vector["selectorPayloadHex"], "GATEWAY_SELECTOR_PAYLOAD")
    if len(forwarded) < 4:
        reject("GATEWAY_SELECTOR_PAYLOAD", "legacy-shaped selector plus payload is truncated")
    return "0x" + forwarded.hex()


def validate_gateway_vector(spec: dict[str, Any], vector: dict[str, Any]) -> None:
    expected_error = vector["expectedErrorCode"]
    try:
        forwarded = run_gateway(spec, vector)
    except TranscriptValidationError as exc:
        if expected_error != exc.code:
            raise ValueError(f"{vector['id']}: expected {expected_error}, got {exc.code}") from exc
    else:
        if expected_error is not None:
            raise ValueError(f"{vector['id']}: gateway input was unexpectedly accepted")
        if forwarded != vector["expectedForwardedHex"]:
            raise ValueError(f"{vector['id']}: gateway forwarded bytes mismatch")


def validate_semantics(spec: dict[str, Any], vectors: dict[str, Any]) -> None:
    validate_spec_invariants(spec)
    validate_global_vector_ids(vectors)
    for vector in vectors["positiveTranscripts"]:
        decode_envelope(spec, vector["profile"], vector["envelopeHex"])
        generated = run_transcript(spec, vector["profile"], vector["events"])
        for key in ("expectedInitial", "expectedSteps", "expectedFinal"):
            if vector[key] != generated[key]:
                raise ValueError(f"{vector['id']}: {key} mismatch")

    for pair in vectors["collisionNegativeTranscripts"]:
        left = run_transcript(spec, pair["profile"], pair["left"])
        right = run_transcript(spec, pair["profile"], pair["right"])
        if left["stream"] == right["stream"]:
            raise ValueError(f"{pair['id']}: collision-negative transcripts encoded identically")

    for rejection in vectors["rejectionVectors"]:
        validate_rejection(spec, rejection)

    for vector in vectors["outerChallengeExtractionVectors"]:
        validate_outer_extraction(spec, vector)

    for vector in vectors["proofDecodingVectors"]:
        validate_decoding_vector(spec, vector)

    for vector in vectors["gatewayVectors"]:
        validate_gateway_vector(spec, vector)

    regression_ids: set[str] = set()
    for regression in vectors["independentStateTransitionRegressions"]:
        if regression["id"] in regression_ids:
            raise ValueError("independent regression IDs must be unique")
        regression_ids.add(regression["id"])
        validate_independent_state_regression(spec, regression)

    mutation_ids: set[str] = set()
    for mutation in vectors["hostileCorpusMutations"]:
        if mutation["id"] in mutation_ids:
            raise ValueError("hostile mutation IDs must be unique")
        mutation_ids.add(mutation["id"])
        validate_hostile_id_mutation(vectors, mutation)


def main() -> None:
    spec = load("typed-transcript-v1.json")
    vectors = load("typed-transcript-vectors-v1.json")
    spec_schema = load("typed-transcript-v1.schema.json")
    vector_schema = load("typed-transcript-vectors-v1.schema.json")
    jsonschema.Draft202012Validator.check_schema(spec_schema)
    jsonschema.Draft202012Validator.check_schema(vector_schema)
    jsonschema.Draft202012Validator(spec_schema).validate(spec)
    jsonschema.Draft202012Validator(vector_schema).validate(vectors)
    validate_semantics(spec, vectors)
    print("TypedTranscriptV1 structural transcripts: valid (no cryptographic closure asserted)")


if __name__ == "__main__":
    main()
