from __future__ import annotations

from fractions import Fraction
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import jsonschema


PROBLEM = Path(__file__).resolve().parents[1]
ROOT = PROBLEM.parents[1]
FRONTIER = PROBLEM / "examples" / "lnzwz-n512-repaired.json"
UPSTREAM = PROBLEM / "provenance" / "lnzwz-n512-repaired-upstream.json"
REBUILD = PROBLEM / "tools" / "rebuild_frontier.py"
EXPECTED_SCORE = (
    "8906018162028540388168670826976087326497984749751/"
    "23384026197294446691258957323460528314494920687616"
)
HISTORICAL_SCORE = (
    "1424992289798782609633201801352767458976314440679252577/"
    "3741444197802851304404516484910431627947663875649308401"
)
VERDICT_SCHEMA = json.loads(
    (ROOT / "schemas" / "verdict.schema.json").read_text(encoding="utf-8")
)


def load_verifier_module():
    path = PROBLEM / "verifier" / "verify.py"
    spec = importlib.util.spec_from_file_location("erdos_min_overlap_verify", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    report = json.loads(completed.stdout)
    jsonschema.Draft202012Validator(VERDICT_SCHEMA).validate(report)
    canonical = json.dumps(
        report, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    assert completed.stdout.strip() == canonical
    return completed.returncode, report


def write_solution(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "solution.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def load_frontier() -> dict:
    return json.loads(FRONTIER.read_text(encoding="ascii"))


def test_frontier_seed_is_exactly_zero_credit() -> None:
    code, report = run_verify(FRONTIER)
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == EXPECTED_SCORE
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert report["details"]["n"] == 512
    assert report["details"]["argmax_lag"] == 100
    assert report["details"]["checked_lags"] == 1023


def test_historical_bundled_witness_cannot_claim_free_first_improvement() -> None:
    code, report = run_verify("examples/hyra-upper.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == HISTORICAL_SCORE
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"
    assert Fraction(*map(int, HISTORICAL_SCORE.split("/"))) > Fraction(
        *map(int, EXPECTED_SCORE.split("/"))
    )


def test_frontier_rebuild_is_byte_exact(tmp_path: Path) -> None:
    rebuilt = tmp_path / "rebuilt.json"
    completed = subprocess.run(
        [str(REBUILD), "--source", str(UPSTREAM), "--output", str(rebuilt)],
        cwd=PROBLEM,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert rebuilt.read_bytes() == FRONTIER.read_bytes()


def test_frontier_rebuild_rejects_source_byte_tamper(tmp_path: Path) -> None:
    tampered = tmp_path / "tampered-upstream.json"
    raw = UPSTREAM.read_bytes()
    tampered.write_bytes(raw.replace(b'"solId":2407', b'"solId":2408', 1))
    completed = subprocess.run(
        [str(REBUILD), "--source", str(tampered), "--output", str(tmp_path / "out.json")],
        cwd=PROBLEM,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode != 0
    assert "source SHA-256 mismatch" in completed.stderr


def test_frontier_value_tamper_fails_closed(tmp_path: Path) -> None:
    payload = load_frontier()
    payload["values"][0] = (1 << payload["denominator_power"]) + 1
    code, report = run_verify(write_solution(tmp_path, payload))
    assert code != 0
    assert report["valid"] is False
    assert report["reason"] == "RAW_RANGE"
    assert report["improvement"] == "0/1"


def test_lying_claim_is_ignored() -> None:
    code, report = run_verify("examples/lying-claim.json")
    assert code != 0
    assert report["valid"] is False
    assert report["score"] == "1/2"
    assert report["improvement"] == "0/1"
    assert report["reason"] == "NOT_STRICT_IMPROVEMENT"


def test_odd_n_uses_exact_integer_score(tmp_path: Path) -> None:
    # n=3, a=[2,1,1]/4: direct hand computation gives 15/32 at lag +1.
    path = write_solution(
        tmp_path,
        {"n": 3, "denominator_power": 2, "values": [2, 1, 1]},
    )
    _, report = run_verify(path)
    assert report["score"] == "15/32"
    assert report["details"]["argmax_lag"] == 1
    assert report["details"]["checked_lags"] == 5


def test_schema_and_verifier_scope_constants_match() -> None:
    verifier = load_verifier_module()
    schema = json.loads((PROBLEM / "solution.schema.json").read_text(encoding="utf-8"))
    properties = schema["properties"]
    assert schema["x-p42-max-bytes"] == verifier.MAX_SOLUTION_BYTES
    assert properties["n"]["minimum"] == verifier.MIN_N
    assert properties["n"]["maximum"] == verifier.MAX_N
    assert properties["denominator_power"]["maximum"] == verifier.MAX_DENOMINATOR_POWER
    assert properties["values"]["minItems"] == verifier.MIN_N
    assert properties["values"]["maxItems"] == verifier.MAX_N
    assert properties["values"]["items"]["maximum"] == 1 << verifier.MAX_DENOMINATOR_POWER
    assert properties["source"]["maxLength"] == verifier.MAX_SOURCE_CHARS
    assert properties["claimed_score"]["maxLength"] == verifier.MAX_CLAIM_CHARS
    assert properties["claimed_improvement"]["maxLength"] == verifier.MAX_CLAIM_CHARS
    assert set(properties) == verifier.ALLOWED_KEYS
    manifest = (PROBLEM / "problem.yaml").read_text(encoding="utf-8")
    assert f'seed_best: "{EXPECTED_SCORE}"' in manifest
    assert "status: hold-independent-review" in manifest


def test_n_and_shape_bounds_are_typed(tmp_path: Path) -> None:
    cases = (
        ({"n": 1, "denominator_power": 0, "values": [1]}, "N_RANGE"),
        ({"n": 4097, "denominator_power": 0, "values": [1]}, "N_RANGE"),
        ({"n": 4, "denominator_power": 0, "values": [1, 0, 1]}, "WRONG_SHAPE"),
    )
    for payload, expected_reason in cases:
        code, report = run_verify(write_solution(tmp_path, payload))
        assert code != 0
        assert report["reason"] == expected_reason


def test_hostile_types_and_unknown_fields_fail_closed(tmp_path: Path) -> None:
    cases = (
        ({"n": True, "denominator_power": 0, "values": [1, 1]}, "MALFORMED"),
        ({"n": 2, "denominator_power": False, "values": [1, 1]}, "MALFORMED"),
        ({"n": 2, "denominator_power": 0, "values": [1, True]}, "MALFORMED"),
        ({"n": 2, "denominator_power": 0, "values": [1, 1], "unknown": 0}, "MALFORMED"),
        ({"n": 2, "denominator_power": 0, "values": [1, 1], "source": {}}, "MALFORMED"),
        ({"n": 2, "denominator_power": 0, "values": [1, 1], "source": "x" * 4097}, "MALFORMED"),
    )
    for payload, expected_reason in cases:
        code, report = run_verify(write_solution(tmp_path, payload))
        assert code != 0
        assert report["reason"] == expected_reason
        assert report["improvement"] == "0/1"


def test_duplicate_keys_and_oversized_input_fail_closed(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"n":2,"n":3,"denominator_power":0,"values":[1,1]}',
        encoding="ascii",
    )
    _, duplicate_report = run_verify(duplicate)
    assert duplicate_report["reason"] == "MALFORMED_JSON"

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (262144 + 1))
    _, oversized_report = run_verify(oversized)
    assert oversized_report["reason"] == "OVERSIZED"


def test_zero_mass_denominator_and_rescale_bounds(tmp_path: Path) -> None:
    cases = (
        ({"n": 2, "denominator_power": 0, "values": [0, 0]}, "ZERO_MASS"),
        ({"n": 2, "denominator_power": 129, "values": [1, 1]}, "DENOMINATOR_POWER_RANGE"),
        ({"n": 4, "denominator_power": 2, "values": [4, 0, 0, 0]}, "RESCALE_RANGE"),
    )
    for payload, expected_reason in cases:
        _, report = run_verify(write_solution(tmp_path, payload))
        assert report["reason"] == expected_reason
