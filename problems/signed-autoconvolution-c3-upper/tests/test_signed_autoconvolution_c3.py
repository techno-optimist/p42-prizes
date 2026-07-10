from __future__ import annotations

import importlib.util
import itertools
import json
import os
from pathlib import Path
import subprocess


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
VERIFIER_PATH = PROBLEM / "verifier" / "verify.py"
VERIFIER_SPEC = importlib.util.spec_from_file_location("signed_autoconvolution_c3_verify", VERIFIER_PATH)
assert VERIFIER_SPEC is not None and VERIFIER_SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(VERIFIER_SPEC)
VERIFIER_SPEC.loader.exec_module(VERIFIER)
# Corrected L-infinity score (~4.9875) of the bundled OrganonAgent witness.
# The pre-fix signed-max scorer reported ~1.4523 and wrongly certified it.
EXPECTED_SCORE = (
    "40362551506526560656553725091979410551071047680000000/"
    "8092744874989952471246071559466128309374865340943729"
)
# The signed-max score the buggy verifier used to report for the same witness.
BUGGY_SIGNED_MAX_SCORE = (
    "11753128449293701953238517385067272445617294540800000/"
    "8092744874989952471246071559466128309374865340943729"
)


def run_verify(solution: str | Path) -> tuple[int, dict]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        ["make", "verify", f"SOLUTION={solution}"],
        cwd=PROBLEM,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.stdout, completed.stderr
    return completed.returncode, json.loads(completed.stdout)


def naive_autoconvolution(values: list[int]) -> list[int]:
    coefficients = [0] * (2 * len(values) - 1)
    for left_index, left in enumerate(values):
        for right_index, right in enumerate(values):
            coefficients[left_index + right_index] += left * right
    return coefficients


def signed_packed_autoconvolution(values: list[int]) -> list[int]:
    max_abs = max(abs(value) for value in values)
    bound = len(values) * max_abs * max_abs
    slot_bytes = (bound.bit_length() + 2 + 7) // 8
    packed = VERIFIER.pack_signed(values, slot_bytes)
    return VERIFIER.unpack_signed(packed * packed, slot_bytes, 2 * len(values) - 1)


def test_signed_packing_matches_naive_convolution_with_borrows_and_trailing_zeroes() -> None:
    for values in ([2, -3], [0, 2, -3, 0], [4, -5, 3, -2, 0]):
        assert signed_packed_autoconvolution(values) == naive_autoconvolution(values)

    # The small exhaustive space exercises both borrow directions and carry
    # propagation without relying only on the large production fixture.
    for values in itertools.product(range(-3, 4), repeat=4):
        vector = list(values)
        assert signed_packed_autoconvolution(vector) == naive_autoconvolution(vector)


def test_organon_upper_bound_scores_linf_and_is_rejected() -> None:
    # Regression for the L-infinity scoring fix (audit finding F2): the
    # bundled OrganonAgent witness is negative-dominant, so the signed-max
    # scorer under-reported it and wrongly certified an improvement. The
    # corrected verifier reports the exact L-infinity score (~4.9875 > 3/2)
    # and rejects the witness.
    code, report = run_verify("examples/organon-upper.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SCORE
    assert report["score"] != BUGGY_SIGNED_MAX_SCORE
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["argmax_index"] == 135999
    assert report["details"]["checked_coefficients"] == 199999


def test_lying_claim_is_ignored() -> None:
    code, report = run_verify("examples/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "2/1"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_wrong_shape_fails_with_typed_report() -> None:
    code, report = run_verify("examples/wrong-length.json")
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "WRONG_SHAPE"


def test_negative_dominant_witness_scores_linf_norm(tmp_path: Path) -> None:
    # values = [2, -3, 0, ...] has autoconvolution coefficients
    # c_0 = 4, c_1 = -12, c_2 = 9 and signed sum -1, so (sum)^2 = 1.
    # The signed maximum is 9 (score 2n*9 = 1800000/1) but the reference
    # L-infinity norm is |-12| = 12; the verifier must report 2n*12.
    solution = tmp_path / "negative-dominant.json"
    solution.write_text(
        json.dumps(
            {
                "n": 100000,
                "denominator_power": 0,
                "values": [2, -3] + [0 for _ in range(99998)],
            }
        ),
        encoding="utf-8",
    )

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["score"] == "2400000/1"
    assert report["score"] != "1800000/1"
    assert report["details"]["argmax_index"] == 1


def test_zero_mass_fails(tmp_path: Path) -> None:
    solution = tmp_path / "zero-mass.json"
    solution.write_text(
        json.dumps(
            {
                "n": 100000,
                "denominator_power": 0,
                "values": [1, -1] + [0 for _ in range(99998)],
            }
        ),
        encoding="utf-8",
    )

    code, report = run_verify(solution)
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "ZERO_MASS"
