from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from p42_prizes.verdict import sha256_file


ROOT = Path(__file__).resolve().parents[1]
SEED_EXAMPLES = {
    "hadamard-mini": "valid-4.json",
    "erdos-min-overlap": "hyra-upper.json",
    "edges-vs-triangles": "rational-curve-sample.json",
    "arithmetic-kakeya": "kt-2x2-forcing.json",
    "autoconvolution-c1-upper": "hyra-upper.json",
    "autoconvolution-c2-lower": "hyra-lower.json",
    "signed-autoconvolution-c3-upper": "organon-upper.json",
    "mertens-lp-ceiling-k12000": "certificate-k12000.json",
    "pnt-sparse-mertens-construction": "chronos-96000.json",
    "hadamard-668-defect": "sylvester-prefix.json",
}


def run_verifier(slug: str, solution: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        ["python3", "verifier/verify.py", "--solution", str(solution)],
        cwd=ROOT / "problems" / slug,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize("slug", sorted(SEED_EXAMPLES))
def test_missing_solution_is_a_total_verdict_report(slug: str, tmp_path: Path) -> None:
    completed = run_verifier(slug, tmp_path / "missing.json")

    assert completed.returncode == 1
    assert completed.stderr == ""
    report = json.loads(completed.stdout)
    assert report["problem_id"] == slug
    assert report["reason"] == "INPUT_UNREADABLE"
    assert report["details"]["hash_status"] == "unavailable"


@pytest.mark.parametrize("slug", sorted(SEED_EXAMPLES))
def test_oversized_solution_is_bounded_and_total(slug: str, tmp_path: Path) -> None:
    schema = json.loads((ROOT / "problems" / slug / "solution.schema.json").read_text(encoding="utf-8"))
    max_bytes = schema["x-p42-max-bytes"]
    solution = tmp_path / f"{slug}.json"
    solution.write_bytes(b"x" * (max_bytes + 1))

    completed = run_verifier(slug, solution)

    assert completed.returncode == 1
    assert completed.stderr == ""
    report = json.loads(completed.stdout)
    assert report["reason"] == "OVERSIZED"
    assert report["details"] == {
        "limit_bytes": max_bytes,
        "observed_bytes": max_bytes + 1,
    }
    assert report["solution_hash"] == sha256_file(solution)


def test_solution_json_rejects_nan_even_in_an_ignored_field(tmp_path: Path) -> None:
    solution = tmp_path / "nan.json"
    solution.write_text(
        '{"ignored":NaN,"n":4,"rows":["++++","+-+-","++--","+--+"]}',
        encoding="utf-8",
    )

    completed = run_verifier("hadamard-mini", solution)

    assert completed.returncode == 1
    report = json.loads(completed.stdout)
    assert report["reason"] == "MALFORMED_JSON"
    assert "non-JSON numeric constant" in report["details"]["error"]


@pytest.mark.parametrize("slug, example", sorted(SEED_EXAMPLES.items()))
def test_designated_seed_example_matches_published_solution_schema(slug: str, example: str) -> None:
    problem = ROOT / "problems" / slug
    schema = json.loads((problem / "solution.schema.json").read_text(encoding="utf-8"))
    solution = json.loads((problem / "examples" / example).read_text(encoding="utf-8"))

    jsonschema.validate(solution, schema)
