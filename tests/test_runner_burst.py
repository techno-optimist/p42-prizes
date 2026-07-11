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


def _signed(identity: dict, role: str, value: dict, at: str) -> dict:
    unsigned = dict(value)
    unsigned.pop("attestation", None)
    digest = sha256_bytes(canonical_json(unsigned).encode())
    return {"identity": {k: identity[k] for k in ("name", "organization", "professional_email", "public_key")}, **_sign(identity, role, "p42-runner-burst/v1", digest, at)}


def _record(sequence: int, queue_hash: str, starts: int) -> dict:
    value = {"sequence": sequence, "queue_state_hash": queue_hash, "verifier_starts": starts}
    value["record_hash"] = sha256_bytes(canonical_json(value).encode())
    return value


def _fixture(root: Path) -> tuple[dict, dict]:
    af = AttestationFixture(root / "registry")
    runner = af.identity("runner", "Runner Operator", "runner-operator")
    authority = af.identity("authority", "Release Authority", "release-authority")
    observer = af.identity("observer", "Independent Host Observer", "host-observer", independent=True)
    host = af.identity("host", "Runner Host", "runner-host")
    registry = af.trust_registry("p42-runner-burst/v1", [("runner-operator", runner, "2026-07-08T23:00:00Z"), ("release-authority", authority, "2026-07-08T23:00:00Z"), ("host-observer", observer, "2026-07-08T23:00:00Z")])
    binding = {
        "drill_id": "burst-7", "started_at_utc": "2026-07-08T22:00:00Z", "completed_at_utc": "2026-07-08T23:00:00Z",
        "environment": "local-rehearsal", "release": "release-2026-07", "git_commit": "2" * 40,
        "problem_id": "hadamard-mini", "board_id": "board-hadamard",
        "verifier_image": "registry.example/p42/verifier@sha256:" + "a" * 64,
        "admission_matrix_hash": "sha256:" + "b" * 64, "runner_host": "dgx-hermes", "runner_host_key": host["public_key"],
    }
    jobs = [{"job_id": f"j{i}", "status": "queued", "created_at_utc": f"2026-07-08T22:0{i}:00Z"} for i in range(1, 4)]
    after = [dict(j, status="failed" if j["job_id"] == "j2" else "succeeded") for j in jobs]
    transcripts = []
    for jid, valid in (("j1", True), ("j2", False), ("j3", True)):
        transcript = {"binding": binding, "schema_version": "p42-runner-transcript/v1", "job_id": jid, "problem": binding["problem_id"], "verifier": {"valid": valid}}
        transcript["transcript_hash"] = sha256_bytes(canonical_json(transcript).encode())
        transcripts.append(transcript)
    events = []
    for index, transcript in enumerate(transcripts):
        events.extend([
            {"kind": "started", "job_id": transcript["job_id"], "at_utc": f"2026-07-08T22:{10 + index * 2}:00Z"},
            {"kind": "completed", "job_id": transcript["job_id"], "at_utc": f"2026-07-08T22:{11 + index * 2}:00Z", "transcript_hash": transcript["transcript_hash"]},
        ])
    authority_resolution = {"binding": binding, "resolution": "approved"}
    authority_resolution["attestation"] = _signed(authority, "release-authority", authority_resolution, "2026-07-08T22:55:00Z")
    host_observations = {
        "binding": binding, "runner_host_key": host["public_key"],
        "before": {"observed_at_utc": "2026-07-08T22:00:00Z", "kernel_oom_kills": 4, "cgroup_oom_kills": 2, "worker_restarts": 7, "queue_corruption_events": 0},
        "after": {"observed_at_utc": "2026-07-08T22:58:00Z", "kernel_oom_kills": 4, "cgroup_oom_kills": 2, "worker_restarts": 7, "queue_corruption_events": 0},
    }
    host_observations["attestation"] = _signed(observer, "host-observer", host_observations, "2026-07-08T22:59:00Z")
    queue_hash = "sha256:" + "c" * 64
    artifacts = {
        "authority_resolution": authority_resolution, "queue_before": {"binding": binding, "jobs": jobs}, "queue_after": {"binding": binding, "jobs": after},
        "loop_summary": {"binding": binding, "events": events}, "transcript_archive": {"binding": binding, "transcripts": transcripts},
        "alert_bundle": {"binding": binding, "alerts": [{"job_id": "j2", "category": "verifier_rejected"}]},
        "guard_cases": {"binding": binding, "cases": [{"reason": reason, "decision": "wait", "before_record": _record(i * 2, queue_hash, 9), "after_record": _record(i * 2 + 1, queue_hash, 9)} for i, reason in enumerate(("memory_guard_tripped", "swap_guard_tripped", "job_exceeds_host_capacity", "runner_concurrency_full"), 1)]},
        "host_observations": host_observations,
    }
    refs = {}
    for name, value in artifacts.items():
        raw = canonical_json(value).encode()
        (root / f"{name}.json").write_bytes(raw)
        refs[name] = {"path": f"{name}.json", "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
    report = {"schema_version": "p42-runner-burst/v1", **binding, "artifacts": refs, "annotation": {"agent_operator": "CHRONOS", "statement": "Local drill annotation."}}
    return report, {"fixture": af, "registry": registry, "runner": runner, "authority": authority, "observer": observer}


def _rewrite(root: Path, report: dict, name: str, mutate) -> None:
    path = root / report["artifacts"][name]["path"]
    value = json.loads(path.read_text())
    mutate(value)
    raw = canonical_json(value).encode()
    path.write_bytes(raw)
    report["artifacts"][name]["sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()


def _operator_sign(report: dict, root: Path, registry: dict, identity: dict, *, signed_at: str = "2026-07-08T23:00:00Z") -> None:
    unsigned = normalize_runner_burst_report(report, artifact_root=root, trust_registry=registry)
    digest = sha256_bytes(canonical_json({k: v for k, v in unsigned.items() if k != "burst_hash"}).encode())
    report["attestation"] = {"identity": {k: identity[k] for k in ("name", "organization", "professional_email", "public_key")}, **_sign(identity, "runner-operator", "p42-runner-burst/v1", digest, signed_at)}


def test_three_party_attestation_is_valid_but_gate_remains_blocked(tmp_path: Path) -> None:
    report, support = _fixture(tmp_path)
    registry = support["registry"]
    unsigned = normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=registry)
    assert unsigned["attestation_valid"] is False
    assert unsigned["gate_passed"] is False
    assert unsigned["derived"]["completed_jobs"] == 3
    _operator_sign(report, tmp_path, registry, support["runner"])
    out = normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=registry)
    assert out["attestation_valid"] is True
    assert out["gate_passed"] is False
    assert out["derived"]["live_authority_resolution_required"] is True
    jsonschema.validate(out, json.loads((ROOT / "schemas/runner-burst.schema.json").read_text()))


@pytest.mark.parametrize("field,value,match", [
    ("completed_at_utc", "2099-01-01T00:00:00Z", "future"),
    ("verifier_image", "not-an-image", "immutable image"),
    ("git_commit", "deadbeef", "40-character"),
])
def test_rejects_unpinned_authority_binding(tmp_path: Path, field: str, value: str, match: str) -> None:
    report, support = _fixture(tmp_path)
    report[field] = value
    with pytest.raises(RunnerBurstError, match=match):
        normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=support["registry"])


def test_operator_claim_cannot_replace_authority_resolution(tmp_path: Path) -> None:
    report, support = _fixture(tmp_path)
    _rewrite(tmp_path, report, "authority_resolution", lambda value: value.update(resolution="approved-by-operator"))
    with pytest.raises(RunnerBurstError, match="explicitly approve"):
        normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=support["registry"])


def test_rejects_caller_provided_gate_passed_true(tmp_path: Path) -> None:
    report, support = _fixture(tmp_path)
    report["gate_passed"] = True
    with pytest.raises(RunnerBurstError, match="caller-provided gate_passed"):
        normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=support["registry"])


def test_one_real_world_identity_cannot_use_three_keys(tmp_path: Path) -> None:
    report, support = _fixture(tmp_path)
    af = support["fixture"]
    common = {"organization": "Meridian Systems", "professional_email": "alex.morgan@meridian.systems"}
    authority = af.identity("same-authority", "Alex Morgan", "release-authority", **common)
    observer = af.identity("same-observer", "Alex Morgan", "host-observer", **common)
    runner = af.identity("same-runner", "Alex Morgan", "runner-operator", **common)
    registry = af.trust_registry("p42-runner-burst/v1", [("release-authority", authority, "2026-07-08T22:55:00Z"), ("host-observer", observer, "2026-07-08T22:59:00Z"), ("runner-operator", runner, "2026-07-08T23:00:00Z")])
    def resign_authority(value: dict) -> None:
        value["attestation"] = _signed(authority, "release-authority", value, "2026-07-08T22:55:00Z")
    def resign_observer(value: dict) -> None:
        value["attestation"] = _signed(observer, "host-observer", value, "2026-07-08T22:59:00Z")
    _rewrite(tmp_path, report, "authority_resolution", resign_authority)
    _rewrite(tmp_path, report, "host_observations", resign_observer)
    with pytest.raises(RunnerBurstError, match="distinct identities"):
        normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=registry)


@pytest.mark.parametrize("name,mutate,match", [
    ("queue_before", lambda value: value["jobs"][0].update(created_at_utc="2099-01-01T00:00:00Z"), "job created_at_utc"),
    ("loop_summary", lambda value: value["events"][0].update(at_utc="2099-01-01T00:00:00Z"), "event timestamp"),
    ("host_observations", lambda value: value["after"].update(observed_at_utc="2099-01-01T00:00:00Z"), "host observations"),
    ("authority_resolution", lambda value: value["attestation"].update(signed_at_utc="2099-01-01T00:00:00Z"), "signed_at_utc"),
    ("host_observations", lambda value: value["attestation"].update(signed_at_utc="2099-01-01T00:00:00Z"), "signed_at_utc"),
])
def test_rejects_2099_evidence_timestamps(tmp_path: Path, name: str, mutate, match: str) -> None:
    report, support = _fixture(tmp_path)
    _rewrite(tmp_path, report, name, mutate)
    with pytest.raises(RunnerBurstError, match=match):
        normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=support["registry"])


def test_rejects_2099_operator_signature(tmp_path: Path) -> None:
    report, support = _fixture(tmp_path)
    _operator_sign(report, tmp_path, support["registry"], support["runner"], signed_at="2099-01-01T00:00:00Z")
    with pytest.raises(RunnerBurstError, match="signed_at_utc"):
        normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=support["registry"])


@pytest.mark.parametrize("mutate,match", [
    (lambda value: value.update(events=[]), "nonempty complete"),
    (lambda value: value["events"].pop(), "exactly cover"),
    (lambda value: value["events"].insert(1, {"kind": "started", "job_id": "j2", "at_utc": "2026-07-08T22:10:30Z"}), "exactly one active"),
])
def test_rejects_incomplete_or_claimed_loop_metrics(tmp_path: Path, mutate, match: str) -> None:
    report, support = _fixture(tmp_path)
    _rewrite(tmp_path, report, "loop_summary", mutate)
    with pytest.raises(RunnerBurstError, match=match):
        normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=support["registry"])


def test_guard_requires_distinct_hashed_no_mutation_records(tmp_path: Path) -> None:
    report, support = _fixture(tmp_path)
    def mutate(value: dict) -> None:
        value["cases"][0]["after_record"] = dict(value["cases"][0]["before_record"])
    _rewrite(tmp_path, report, "guard_cases", mutate)
    with pytest.raises(RunnerBurstError, match="distinct ordered"):
        normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=support["registry"])


def test_host_observer_must_be_independent_and_counters_unchanged(tmp_path: Path) -> None:
    report, support = _fixture(tmp_path)
    _rewrite(tmp_path, report, "host_observations", lambda value: value["after"].update(cgroup_oom_kills=3))
    with pytest.raises(RunnerBurstError, match="cgroup_oom_kills"):
        normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=support["registry"])


@pytest.mark.parametrize("name,mutate", [
    ("transcript_archive", lambda value: value["transcripts"][0].update(api_key={"value": "redacted"})),
    ("alert_bundle", lambda value: value["alerts"][0].update(detail="Bearer abcdefghijklmnop")),
])
def test_recursive_secret_scan(tmp_path: Path, name: str, mutate) -> None:
    report, support = _fixture(tmp_path)
    _rewrite(tmp_path, report, name, mutate)
    with pytest.raises(RunnerBurstError, match="secret"):
        normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=support["registry"])


def test_external_live_blocker_is_preserved(tmp_path: Path) -> None:
    report, support = _fixture(tmp_path)
    out = normalize_runner_burst_report(report, artifact_root=tmp_path, trust_registry=support["registry"])
    assert out["derived"]["external_live_blocker"] is True


def test_cli_requires_artifact_root(tmp_path: Path) -> None:
    report, _ = _fixture(tmp_path)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    result = subprocess.run(["python3", "-m", "p42_prizes.cli", "runner-burst-validate", "--report", str(path)], cwd=ROOT, env=env, text=True, capture_output=True)
    assert result.returncode == 2 and "--artifact-root" in result.stderr
