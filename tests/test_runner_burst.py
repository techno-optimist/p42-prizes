from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import jsonschema
import pytest

from attestation_helpers import AttestationFixture, _sign
from p42_prizes.runner_burst import RunnerBurstError, normalize_runner_burst_report
from p42_prizes.verdict import canonical_json, sha256_bytes

ROOT = Path(__file__).resolve().parents[1]


def _fixture(root: Path) -> tuple[dict, dict[str, dict]]:
    binding = {"drill_id": "burst-7", "started_at_utc": "2026-07-08T22:00:00Z", "completed_at_utc": "2026-07-08T23:00:00Z", "environment": "local-rehearsal", "release": "git:2899cc1", "problem_id": "hadamard-mini", "board_id": "board-hadamard", "verifier_image": "registry/p42@sha256:" + "a"*64, "admission_matrix_hash": "sha256:" + "b"*64, "runner_host": "dgx-hermes"}
    jobs = [{"job_id": f"j{i}", "status": "queued", "required_memory_mb": 64, "created_at_utc": f"2026-07-08T22:0{i}:00Z"} for i in range(1, 4)]
    after = [dict(j, status="failed" if j["job_id"] == "j2" else "succeeded") for j in jobs]
    transcripts = []
    for jid, valid in (("j1", True), ("j2", False), ("j3", True)):
        t = {"binding": binding, "schema_version": "p42-runner-transcript/v1", "job_id": jid, "problem": binding["problem_id"], "verifier": {"valid": valid}}
        t["transcript_hash"] = sha256_bytes(canonical_json(t).encode())
        transcripts.append(t)
    artifacts = {
        "queue_before": {"binding": binding, "jobs": jobs},
        "queue_after": {"binding": binding, "jobs": after},
        "loop_summary": {"binding": binding, "events": [{"kind": "completed", "job_id": t["job_id"], "transcript_hash": t["transcript_hash"], "active_running_count": 1} for t in transcripts]},
        "transcript_archive": {"binding": binding, "transcripts": transcripts},
        "alert_bundle": {"binding": binding, "alerts": [{"job_id": "j2", "category": "verifier_rejected"}]},
        "guard_cases": {"binding": binding, "cases": []},
        "host_observations": {"binding": binding, "oom_kills": 0, "worker_restarts": 0, "queue_corruption_events": 0},
    }
    refs = {}
    for name, value in artifacts.items():
        raw = canonical_json(value).encode(); path = root / f"{name}.json"; path.write_bytes(raw)
        refs[name] = {"path": path.name, "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
    artifacts["guard_cases"]["cases"] = [{"reason": reason, "decision": "wait", "queue_before_hash": refs["queue_before"]["sha256"], "queue_after_hash": refs["queue_before"]["sha256"], "started_verifier": False} for reason in ("memory_guard_tripped", "swap_guard_tripped", "job_exceeds_host_capacity", "runner_concurrency_full")]
    raw = canonical_json(artifacts["guard_cases"]).encode(); (root / "guard_cases.json").write_bytes(raw)
    refs["guard_cases"]["sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    report = {"schema_version": "p42-runner-burst/v1", **binding, "artifacts": refs, "annotation": {"agent_operator": "CHRONOS", "statement": "Unsigned local drill annotation; not an attestation."}}
    return report, artifacts


def test_derives_evidence_and_unsigned_stays_unpassed(tmp_path: Path) -> None:
    report, _ = _fixture(tmp_path)
    out = normalize_runner_burst_report(report, artifact_root=tmp_path)
    assert out["derived"]["submitted_jobs"] == 3
    assert out["derived"]["failed_jobs"] == 1
    assert out["gate_passed"] is False
    jsonschema.validate(out, json.loads((ROOT / "schemas/runner-burst.schema.json").read_text()))


def test_trusted_signature_passes(tmp_path: Path) -> None:
    report, _ = _fixture(tmp_path)
    af = AttestationFixture(tmp_path / "registry")
    identity = af.identity("runner", "Runner Operator", "runner-operator")
    registry = af.trust_registry("p42-runner-burst/v1", [("runner-operator", identity, "2026-07-08T23:00:00Z")])
    unsigned = normalize_runner_burst_report(report, artifact_root=tmp_path)
    signed_hash = sha256_bytes(canonical_json({k: v for k, v in unsigned.items() if k != "burst_hash"}).encode())
    report["attestation"] = {"identity": {k: identity[k] for k in ("name", "organization", "professional_email", "public_key")}, **_sign(identity, "runner-operator", "p42-runner-burst/v1", signed_hash, "2026-07-08T23:00:00Z")}
    assert normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=registry)["gate_passed"] is True


@pytest.mark.parametrize("mutation,match", [
    (lambda r, a, p: r["artifacts"]["queue_before"].update(path="missing.json"), "securely read"),
    (lambda r, a, p: r["artifacts"]["queue_before"].update(path="../escape.json"), "beneath"),
    (lambda r, a, p: r["artifacts"]["queue_before"].update(sha256="sha256:"+"0"*64), "hash mismatch"),
    (lambda r, a, p: r.update(gate_passed=True), "unsigned"),
])
def test_rejects_bad_refs_and_unsigned_claim(tmp_path: Path, mutation, match: str) -> None:
    report, artifacts = _fixture(tmp_path); mutation(report, artifacts, tmp_path)
    with pytest.raises(RunnerBurstError, match=match): normalize_runner_burst_report(report, artifact_root=tmp_path)


def test_rejects_symlink(tmp_path: Path) -> None:
    report, _ = _fixture(tmp_path); target = tmp_path / "queue_before.json"; link = tmp_path / "link.json"; link.symlink_to(target)
    report["artifacts"]["queue_before"]["path"] = "link.json"
    with pytest.raises(RunnerBurstError, match="securely read"): normalize_runner_burst_report(report, artifact_root=tmp_path)


def _rewrite(root: Path, report: dict, name: str, mutate) -> None:
    path = root / report["artifacts"][name]["path"]; value = json.loads(path.read_text()); mutate(value)
    raw = canonical_json(value).encode(); path.write_bytes(raw); report["artifacts"][name]["sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("name,mutate,match", [
    ("loop_summary", lambda x: x["events"].append(dict(x["events"][0])), "duplicate"),
    ("alert_bundle", lambda x: x.update(alerts=[]), "linked alert"),
    ("host_observations", lambda x: x.update(oom_kills=0), "NEVER"),
    ("queue_before", lambda x: x["binding"].update(board_id="other-board"), "binding mismatch"),
])
def test_adversarial_artifact_claims(tmp_path: Path, name: str, mutate, match: str) -> None:
    report, _ = _fixture(tmp_path)
    if match == "NEVER":
        report["burst_metrics"] = {"oom_kills": 0}
        with pytest.raises(RunnerBurstError, match="Additional properties"): normalize_runner_burst_report(report, artifact_root=tmp_path)
        return
    _rewrite(tmp_path, report, name, mutate)
    with pytest.raises(RunnerBurstError, match=match): normalize_runner_burst_report(report, artifact_root=tmp_path)


def test_rejects_fabricated_boolean_and_duplicate_transcript(tmp_path: Path) -> None:
    report, _ = _fixture(tmp_path)
    report["invariants_checked"] = {"fifo_order_preserved": True}
    with pytest.raises(RunnerBurstError, match="Additional properties"): normalize_runner_burst_report(report, artifact_root=tmp_path)
    report.pop("invariants_checked")
    _rewrite(tmp_path, report, "transcript_archive", lambda x: x["transcripts"].append(dict(x["transcripts"][0])))
    with pytest.raises(RunnerBurstError, match="duplicate transcript"): normalize_runner_burst_report(report, artifact_root=tmp_path)


def test_rejects_secret_bearing_transcript(tmp_path: Path) -> None:
    report, _ = _fixture(tmp_path)
    def inject(value: dict) -> None:
        transcript = value["transcripts"][0]
        transcript["debug"] = "api_key=sk_test_abcdefghijklmnop"
        transcript.pop("transcript_hash")
        transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode())
    _rewrite(tmp_path, report, "transcript_archive", inject)
    with pytest.raises(RunnerBurstError, match="secret material"): normalize_runner_burst_report(report, artifact_root=tmp_path)


def test_cli_requires_artifact_root(tmp_path: Path) -> None:
    report, _ = _fixture(tmp_path); path = tmp_path / "report.json"; path.write_text(json.dumps(report))
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    result = subprocess.run(["python3", "-m", "p42_prizes.cli", "runner-burst-validate", "--report", str(path)], cwd=ROOT, env=env, text=True, capture_output=True)
    assert result.returncode == 2 and "--artifact-root" in result.stderr
