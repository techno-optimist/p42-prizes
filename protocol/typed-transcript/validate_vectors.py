#!/usr/bin/env python3
"""Validate TypedTranscriptV1 format vectors without evaluating a permutation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parent


def load(name: str) -> dict[str, Any]:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def limbs_u64(value: int, radix: int, count: int) -> list[int]:
    if value < 0 or value >= radix**count:
        raise ValueError("value is outside the fixed-width u64 encoding")
    result = []
    for _ in range(count):
        result.append(value % radix)
        value //= radix
    return result


def encode_event(spec: dict[str, Any], event: dict[str, Any]) -> list[int]:
    constants = spec["constants"]
    payload = [int(word) for word in event["payload"]]
    radix = constants["lengthRadix"]
    limbs = constants["lengthLimbs"]
    return [
        constants["protocolMagic"],
        spec["version"],
        spec["eventTags"][event["tag"]],
        spec["encodingTags"][event["encoding"]],
        *limbs_u64(event["counter"], radix, limbs),
        *limbs_u64(event["logicalLength"], radix, limbs),
        *limbs_u64(len(payload), radix, limbs),
        *payload,
        constants["frameEnd"],
    ]


def block_control(
    spec: dict[str, Any], profile: dict[str, Any], index: int, occupied: int, final: bool
) -> int:
    constants = spec["constants"]
    if index >= 1 << constants["blockIndexBits"]:
        raise ValueError("frame exceeds the block-index limit")
    return (
        constants["blockControlBase"]
        + (profile["profileId"] << constants["profileShift"])
        + (spec["phases"]["absorbFrame"] << constants["phaseShift"])
        + (int(final) << constants["finalShift"])
        + (occupied << constants["occupiedShift"])
        + index
    )


def blocks(spec: dict[str, Any], profile_name: str, words: list[int]) -> list[dict[str, Any]]:
    profile = spec["fieldProfiles"][profile_name]
    rate = profile["rate"]
    modulus = int(profile["modulus"])
    result = []
    for index, start in enumerate(range(0, len(words), rate)):
        chunk = words[start : start + rate]
        final = start + rate >= len(words)
        control = block_control(spec, profile, index, len(chunk), final)
        if control >= modulus or any(word >= modulus for word in chunk):
            raise ValueError("frame or control word is not canonical in the target field")
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


def canonical_event(spec: dict[str, Any], event: dict[str, Any]) -> tuple[int, ...]:
    return tuple(encode_event(spec, event))


def validate_event_shape(
    spec: dict[str, Any], profile_name: str, event: dict[str, Any]
) -> None:
    tag = event["tag"]
    encoding = event["encoding"]
    logical_length = event["logicalLength"]
    payload = [int(word) for word in event["payload"]]
    payload_length = len(payload)
    packed_width = spec["constants"]["koalaBearValuesPerBn254Word"]
    packing_radix = spec["constants"]["koalaBearPackingRadix"]
    kb_modulus = int(spec["fieldProfiles"]["inner-koalabear-v1"]["modulus"])
    bn254_modulus = int(spec["fieldProfiles"]["outer-bn254-v1"]["modulus"])
    is_inner = profile_name == "inner-koalabear-v1"
    expected: tuple[set[str], int] | None = None

    if tag == "protocolInit":
        if event["counter"] != 0 or logical_length != 0 or payload_length != 0 or encoding != "none":
            raise ValueError("protocolInit must be the empty counter-zero frame")
        return
    if tag == "baseField":
        if is_inner and encoding == "koalaBearDirect":
            expected = ({encoding}, logical_length)
        elif not is_inner and encoding == "koalaBearPacked8":
            expected = ({encoding}, (logical_length + packed_width - 1) // packed_width)
    elif tag == "extensionField":
        coefficients = logical_length * 4
        if is_inner and encoding == "extension4KoalaBearDirect":
            expected = ({encoding}, coefficients)
        elif not is_inner and encoding == "extension4KoalaBearPacked8":
            expected = ({encoding}, (coefficients + packed_width - 1) // packed_width)
    elif tag in {"digest", "commitment"}:
        if is_inner and encoding == "koalaBearDigest8":
            expected = ({encoding}, logical_length * 8)
        elif not is_inner and encoding == "koalaBearDigest8Packed8":
            expected = ({encoding}, logical_length)
        elif not is_inner and encoding == "bn254Native":
            expected = ({encoding}, logical_length)
    elif tag in {"sliceBegin", "containerBegin"}:
        expected = ({"container"}, 0)
    elif tag in {"sliceEnd", "containerEnd"}:
        if logical_length != 0:
            raise ValueError(f"{tag} must have logical length zero")
        expected = ({"container"}, 0)
    elif tag in {"squeezeField", "squeezeBits", "squeezeExtension"}:
        if logical_length == 0:
            raise ValueError(f"{tag} must request a nonzero output length")
        expected = ({"squeezeRequest"}, 0)

    if expected is None or encoding not in expected[0] or payload_length != expected[1]:
        raise ValueError(f"invalid {tag}/{encoding} event shape")

    if encoding in {"koalaBearDirect", "extension4KoalaBearDirect", "koalaBearDigest8"}:
        if any(word >= kb_modulus for word in payload):
            raise ValueError("noncanonical KoalaBear payload word")
    elif encoding in {"koalaBearPacked8", "extension4KoalaBearPacked8"}:
        source_length = logical_length if encoding == "koalaBearPacked8" else logical_length * 4
        for index, word in enumerate(payload):
            remaining = source_length - index * packed_width
            used = min(packed_width, remaining)
            if word >= packing_radix**used or word >= bn254_modulus:
                raise ValueError("packed payload contains undeclared high limbs")
    elif encoding == "koalaBearDigest8Packed8":
        if any(word >= packing_radix**packed_width or word >= bn254_modulus for word in payload):
            raise ValueError("noncanonical packed digest word")
    elif encoding == "bn254Native" and any(word >= bn254_modulus for word in payload):
        raise ValueError("noncanonical BN254 payload word")


def validate_semantics(spec: dict[str, Any], vectors: dict[str, Any]) -> None:
    profiles = list(spec["fieldProfiles"].values())
    if len({p["profileId"] for p in profiles}) != len(profiles):
        raise ValueError("profile IDs must be unique")
    for profile in profiles:
        if profile["width"] != profile["rate"] + profile["capacity"]:
            raise ValueError("profile width must equal rate plus capacity")
        if profile["rate"] > 15:
            raise ValueError("the occupied-lane control field is four bits")
    constants = spec["constants"]
    if not (
        constants["occupiedShift"] == constants["blockIndexBits"]
        and constants["finalShift"] >= constants["occupiedShift"] + 4
        and constants["phaseShift"] > constants["finalShift"]
        and constants["profileShift"] >= constants["phaseShift"] + 2
    ):
        raise ValueError("capacity-control bit fields overlap")
    for namespace in ("eventTags", "encodingTags", "phases"):
        values = list(spec[namespace].values())
        if len(set(values)) != len(values):
            raise ValueError(f"{namespace} values must be unique")

    ids: set[str] = set()
    for vector in vectors["formatVectors"]:
        if vector["id"] in ids:
            raise ValueError("vector IDs must be unique")
        ids.add(vector["id"])
        validate_event_shape(spec, vector["profile"], vector["event"])
        words = encode_event(spec, vector["event"])
        expected_words = [int(word) for word in vector["expectedFrameWords"]]
        if words != expected_words:
            raise ValueError(f"{vector['id']}: expectedFrameWords mismatch")
        expected_blocks = blocks(spec, vector["profile"], words)
        if expected_blocks != vector["expectedBlocks"]:
            raise ValueError(f"{vector['id']}: expectedBlocks mismatch")

    for pair in vectors["negativePairs"]:
        validate_event_shape(spec, pair["profile"], pair["left"])
        validate_event_shape(spec, pair["profile"], pair["right"])
        if canonical_event(spec, pair["left"]) == canonical_event(spec, pair["right"]):
            raise ValueError(f"{pair['id']}: collision-negative pair encoded identically")

    for rejection in vectors["rejectionVectors"]:
        envelope = rejection["envelope"]
        if (
            envelope.get("protocolId") == spec["protocolId"]
            and envelope.get("version") == spec["version"]
            and envelope.get("profile") in spec["fieldProfiles"]
        ):
            raise ValueError(f"{rejection['id']}: rejection envelope is valid V1")


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
    print("TypedTranscriptV1 structural vectors: valid (no cryptographic closure asserted)")


if __name__ == "__main__":
    main()
