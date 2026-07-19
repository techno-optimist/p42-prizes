from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from p42_prizes.verdict import canonical_json
import scripts.verify_production_board_bindings as bindings_module
from scripts.verify_production_board_bindings import (
    BoardBindingError,
    _canonical_digest,
    _verify_guest_evidence,
    canonical_math_review_fixtures,
    verify_board_bindings,
)


ROOT = Path(__file__).resolve().parents[1]
DOSSIER = ROOT / "protocol/production-board-bindings-v1.json"
ARTIFACT_DIRECTORY = ROOT / "objective-programs/artifacts/hadamard-668-defect/v0.1.0"


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _hadamard_record() -> dict[str, object]:
    dossier = json.loads(DOSSIER.read_text())
    return deepcopy(dossier["records"][9])


def _write_coherent_guest_evidence(tmp_path: Path) -> tuple[dict[str, object], dict[str, Path]]:
    record = _hadamard_record()
    identity = json.loads((ARTIFACT_DIRECTORY / "identity.json").read_text())
    execution = json.loads((ARTIFACT_DIRECTORY / "execution.json").read_text())
    profile = json.loads((ARTIFACT_DIRECTORY / "resource-profile.json").read_text())

    identity_path = tmp_path / "identity.json"
    identity_path.write_text(json.dumps(identity, sort_keys=True))
    identity_digest = _digest_bytes(identity_path.read_bytes())
    execution["identitySha256"] = identity_digest
    execution["guestElfSha256"] = identity["guestElfSha256"]
    execution["programVKey"] = identity["programVKey"]
    profile["program"] = identity["program"]
    profile["version"] = identity["version"]
    profile["reproduction"]["guestElfSha256"] = identity["guestElfSha256"]
    profile["reproduction"]["programVKey"] = identity["programVKey"]
    record["guest"]["identity"]["sha256"] = identity_digest

    execution_path = tmp_path / "execution.json"
    execution_path.write_text(json.dumps(execution))
    profile_path = tmp_path / "resource-profile.json"
    profile_path.write_text(json.dumps(profile))
    return record, {
        "identity": identity_path,
        "execution": execution_path,
        "resource_profile": profile_path,
    }


def _synthetic_v2_dossier(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    root = tmp_path / "repo"
    for directory in ("src", "schemas", "problems", "docs"):
        shutil.copytree(ROOT / directory, root / directory)
    shutil.copytree(ROOT / "objective-programs/artifacts", root / "objective-programs/artifacts")
    for filename in ("Dockerfile.verifier", ".dockerignore", "requirements.runtime.lock"):
        (root / filename).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / filename, root / filename)
    for directory in ("protocol", "evidence", "artifacts"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for relative in (
        "protocol/production-board-bindings-v2.schema.json",
        "protocol/objective-proof-promotion-evidence-v2.schema.json",
        "protocol/production-board-set-v1.json",
        "protocol/production-board-bindings-v1.json",
    ):
        (root / relative).write_bytes((ROOT / relative).read_bytes())

    def write_canonical(relative: str, value: dict[str, object]) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(canonical_json(value) + "\n", encoding="ascii")
        return path

    def artifact(relative: str, content: bytes) -> dict[str, str]:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return {"path": relative, "sha256": _digest_bytes(content)}

    roles = {
        "build": "build-authority",
        "proof": "proof-authority",
        "solidity": "solidity-replay-authority",
        "economics": "economics-authority",
        "matrix": "host-matrix-authority",
        "dependency": "dependency-security-authority",
        "runtime": "external-runtime-authority",
        "release": "release-authority",
        "review-math": "math-reviewer",
        "review-provenance": "provenance-reviewer",
        "review-rights": "rights-reviewer",
        "review-scope": "scope-reviewer",
        "host-0": "host-operator",
        "host-1": "host-operator",
        "host-2": "host-operator",
    }
    private_keys: dict[str, Ed25519PrivateKey] = {}
    authorities = []
    for name, role in roles.items():
        private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"typed-v2:{name}".encode()).digest())
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        identity_id = f"identity:{name}"
        private_keys[identity_id] = private
        authorities.append({
            "identity_id": identity_id,
            "role": role,
            "operator_id": f"operator:{name}",
            "public_key": "ed25519:" + public.hex(),
        })
    registry = {
        "schema_version": "p42-prizes/objective-proof-authority-registry/v1",
        "authorities": authorities,
    }
    registry["registry_hash"] = _digest_bytes(canonical_json(registry).encode("ascii"))
    registry_path = write_canonical("protocol/objective-proof-promotion-authorities-v1.json", registry)
    registry_digest = _digest_bytes(registry_path.read_bytes())
    (root / "protocol/objective-proof-promotion-authorities-v1.sha256").write_text(
        registry_digest + "\n", encoding="ascii"
    )

    observed = "2026-07-19T11:00:00Z"

    def signed_evidence(
        name: str,
        schema_version: str,
        status: str,
        signer: str,
        claims: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, str]]:
        value = {
            "schema_version": schema_version,
            "status": status,
            "issued_at_utc": observed,
            "signer_identity_id": f"identity:{signer}",
            "claims": claims,
        }
        artifact_hash = _digest_bytes(canonical_json(value).encode("ascii"))
        message = (
            b"P42-OBJECTIVE-PROMOTION-V2\0"
            + schema_version.encode("ascii")
            + b"\0"
            + bytes.fromhex(artifact_hash.removeprefix("sha256:"))
        )
        value["artifact_hash"] = artifact_hash
        value["signature"] = {
            "algorithm": "ed25519",
            "value": "ed25519:" + private_keys[f"identity:{signer}"].sign(message).hex(),
        }
        path = write_canonical(f"evidence/{name}.json", value)
        return value, {"path": path.relative_to(root).as_posix(), "sha256": _digest_bytes(path.read_bytes())}

    elf = artifact("artifacts/program.elf", b"\x7fELFtyped-v2-test")
    proof_file = artifact("artifacts/proof.bin", b"typed-groth16-proof-test-vector")
    fixture = artifact("artifacts/worst-case.json", b'{"worst":true}\n')
    image_digest = "sha256:" + "a" * 64
    release_digest = "sha256:" + "b" * 64
    admission_digest = "sha256:" + "c" * 64
    journal_digest = "0x" + "d" * 64
    vkey = "0x" + "e" * 64
    program, program_ref = signed_evidence(
        "program", "p42-prizes/objective-program-identity-evidence/v2", "frozen", "build",
        {"slug": "q6-intersecting-hypergraph", "source_commit": "1" * 40, "elf": elf,
         "program_vkey": vkey, "verifier_image_digest": image_digest, "build_id": "build:q6-v2"},
    )
    binding = {
        "slug": "q6-intersecting-hypergraph", "release_digest": release_digest,
        "admission_digest": admission_digest, "program_identity_digest": program["artifact_hash"],
        "elf_sha256": elf["sha256"], "program_vkey": vkey,
        "verifier_image_digest": image_digest, "journal_digest": journal_digest, "build_id": "build:q6-v2",
    }
    public_bytes = b"typed-public-values"
    public_values, public_ref = signed_evidence(
        "public-values", "p42-prizes/objective-public-values/v2", "canonical", "proof",
        {"binding": binding, "encoding": "hex", "bytes_hex": "0x" + public_bytes.hex(),
         "bytes_sha256": _digest_bytes(public_bytes)},
    )
    proof, proof_ref = signed_evidence(
        "proof", "p42-prizes/groth16-proof-receipt/v2", "verified-non-mock", "proof",
        {"binding": binding, "proof": proof_file, "proof_kind": "groth16", "mock": False,
         "public_values_digest": public_values["artifact_hash"]},
    )
    proof_digest = proof["artifact_hash"]
    solidity, solidity_ref = signed_evidence(
        "solidity", "p42-prizes/solidity-objective-replay/v2", "exact-match", "solidity",
        {"binding": binding, "proof_receipt_digest": proof_digest,
         "public_values_digest": public_values["artifact_hash"], "contract_codehash": "sha256:" + "f" * 64,
         "chain_id": 84532},
    )
    measured = {"total_instruction_count": 100, "proof_generation_ms": 200, "peak_rss_bytes": 300,
                "proof_size_bytes": 400, "verification_gas": 500, "prover_cost_microusd": 600}
    limits = {key: value + 100 for key, value in measured.items()}
    economics, economics_ref = signed_evidence(
        "economics", "p42-prizes/objective-proof-economics/v2", "worst-case-within-limits", "economics",
        {"binding": binding, "proof_receipt_digest": proof_digest, "worst_case_fixture": fixture,
         "measured": measured, "limits": limits},
    )

    entries = []
    for index in range(3):
        signer = f"identity:host-{index}"
        entry = {
            "host_id": f"host:{index}", "identity_id": signer, "operator_id": f"operator:host-{index}",
            "hardware_fingerprint": "sha256:" + str(index + 2) * 64, "runtime_id": f"runtime:host-{index}",
            "binding": binding, "proof_receipt_digest": proof_digest, "observed_at_utc": observed,
        }
        entry_hash = _digest_bytes(canonical_json(entry).encode("ascii"))
        message = (b"P42-OBJECTIVE-HOST-ENTRY-V2\0p42-prizes/objective-host-entry/v2\0"
                   + bytes.fromhex(entry_hash.removeprefix("sha256:")))
        entry["entry_hash"] = entry_hash
        entry["signature"] = {"algorithm": "ed25519", "value": "ed25519:" + private_keys[signer].sign(message).hex()}
        entries.append(entry)
    matrix, matrix_ref = signed_evidence(
        "host-matrix", "p42-prizes/objective-host-matrix/v2", "independent-match", "matrix",
        {"binding": binding, "proof_receipt_digest": proof_digest, "required_hosts": 3, "entries": entries},
    )
    reviews: dict[str, dict[str, str]] = {}
    review_values: dict[str, dict[str, object]] = {}
    for role in ("math", "provenance", "rights", "scope"):
        value, ref = signed_evidence(
            f"review-{role}", "p42-prizes/objective-review/v2", "completed-approved", f"review-{role}",
            {"binding": binding, "proof_receipt_digest": proof_digest, "review_kind": role, "decision": "approve"},
        )
        reviews[role], review_values[role] = ref, value
    dependency, dependency_ref = signed_evidence(
        "dependency", "p42-prizes/sp1-dependency-clearance/v2", "cleared", "dependency",
        {"binding": binding, "proof_receipt_digest": proof_digest, "policy_digest": "sha256:" + "1" * 64,
         "lockfile_digest": "sha256:" + "2" * 64, "advisory_database_digest": "sha256:" + "3" * 64,
         "findings": []},
    )
    runtime, runtime_ref = signed_evidence(
        "runtime", "p42-prizes/objective-external-runtime/v2", "externally-bound", "runtime",
        {"binding": binding, "proof_receipt_digest": proof_digest, "runtime_id": "runtime:external",
         "operator_id": "operator:runtime"},
    )
    release, release_ref = signed_evidence(
        "release", "p42-prizes/objective-admission-release-receipt/v2", "admitted-released", "release",
        {"binding": binding, "proof_receipt_digest": proof_digest,
         "public_values_digest": public_values["artifact_hash"], "solidity_replay_digest": solidity["artifact_hash"],
         "economics_digest": economics["artifact_hash"], "host_matrix_digest": matrix["artifact_hash"],
         "review_digests": {role: value["artifact_hash"] for role, value in review_values.items()},
         "dependency_security_digest": dependency["artifact_hash"], "external_runtime_digest": runtime["artifact_hash"]},
    )
    promotion = {
        "schema_version": "p42-prizes/objective-proof-promotion/v2", "program_identity": program_ref,
        "proof_receipt": proof_ref, "public_values": public_ref, "solidity_replay": solidity_ref,
        "economics": economics_ref, "host_matrix": matrix_ref, "reviews": reviews,
        "dependency_security": dependency_ref, "external_runtime": runtime_ref, "release_receipt": release_ref,
    }
    base_path = root / "protocol/production-board-bindings-v1.json"
    base = json.loads(base_path.read_text())
    dossier = {
        "schema_version": "p42-prizes/production-board-bindings/v2", "board_set": base["board_set"],
        "base_bindings": {"path": "protocol/production-board-bindings-v1.json",
                          "sha256": _digest_bytes(base_path.read_bytes()),
                          "schema_version": "p42-prizes/production-board-bindings/v1",
                          "schema_sha256": "sha256:8c88f88842c8c32dd8699b250ae339a454faa95fc112049cd24148c967869f98"},
        "authority_registry": {"path": "protocol/objective-proof-promotion-authorities-v1.json",
                               "sha256": registry_digest,
                               "pin_path": "protocol/objective-proof-promotion-authorities-v1.sha256"},
        "evaluated_at_utc": "2026-07-19T12:00:00Z", "max_evidence_age_seconds": 7200,
        "minimum_independent_hosts": 3,
        "records": [{"slug": record["slug"], "v1_record_sha256": _canonical_digest(record),
                     "activation_eligible": False, "promotion": promotion if index == 0 else None}
                    for index, record in enumerate(base["records"])],
    }
    dossier_path = root / "bindings-v2.json"
    dossier_path.write_text(json.dumps(dossier))
    return root, dossier_path, dossier


def _resign_typed_evidence(value: dict[str, object]) -> None:
    identity = value["signer_identity_id"]
    name = identity.removeprefix("identity:")
    private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"typed-v2:{name}".encode()).digest())
    unsigned = {key: item for key, item in value.items() if key not in {"artifact_hash", "signature"}}
    artifact_hash = _digest_bytes(canonical_json(unsigned).encode("ascii"))
    message = (b"P42-OBJECTIVE-PROMOTION-V2\0" + value["schema_version"].encode("ascii") + b"\0"
               + bytes.fromhex(artifact_hash.removeprefix("sha256:")))
    value["artifact_hash"] = artifact_hash
    value["signature"] = {"algorithm": "ed25519", "value": "ed25519:" + private.sign(message).hex()}


def _rewrite_typed_evidence(root: Path, ref: dict[str, str], value: dict[str, object]) -> None:
    _resign_typed_evidence(value)
    path = root / ref["path"]
    path.write_text(canonical_json(value) + "\n", encoding="ascii")
    ref["sha256"] = _digest_bytes(path.read_bytes())


def _fast_recursive_v1(monkeypatch: pytest.MonkeyPatch, dossier: dict[str, object]) -> None:
    original = bindings_module.verify_board_bindings
    slugs = [record["slug"] for record in dossier["records"]]

    def fast(root: Path, path: Path) -> dict[str, bool]:
        if Path(path).name == "production-board-bindings-v1.json":
            return {slug: False for slug in slugs}
        return original(root, path)

    monkeypatch.setattr(bindings_module, "verify_board_bindings", fast)


def test_exact_ten_board_bindings_recompute() -> None:
    eligibility = verify_board_bindings(ROOT, DOSSIER)
    assert eligibility == {record["slug"]: False for record in json.loads(DOSSIER.read_text())["records"]}


def test_v2_validates_synthetic_evidence_but_never_promotes_it(tmp_path: Path) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    eligibility = verify_board_bindings(root, dossier_path)
    assert eligibility[dossier["records"][0]["slug"]] is False
    assert sum(eligibility.values()) == 0
    assert all(record["guest"]["activation_eligible"] is False for record in json.loads(DOSSIER.read_text())["records"])


@pytest.mark.parametrize("bad_time", ["20260719T120000Z", "2026-07-19X12:00:00Z"])
def test_v2_rejects_non_rfc3339_evaluation_time(tmp_path: Path, bad_time: str) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    dossier["evaluated_at_utc"] = bad_time
    dossier_path.write_text(json.dumps(dossier))
    with pytest.raises(BoardBindingError, match="RFC 3339|schema validation failed"):
        verify_board_bindings(root, dossier_path)


def test_v2_rejects_non_rfc3339_signed_evidence_time(tmp_path: Path) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    ref = dossier["records"][0]["promotion"]["external_runtime"]
    value = json.loads((root / ref["path"]).read_text())
    value["issued_at_utc"] = "2026-07-19X11:00:00Z"
    _rewrite_typed_evidence(root, ref, value)
    release_ref = dossier["records"][0]["promotion"]["release_receipt"]
    release = json.loads((root / release_ref["path"]).read_text())
    release["claims"]["external_runtime_digest"] = value["artifact_hash"]
    _rewrite_typed_evidence(root, release_ref, release)
    dossier_path.write_text(json.dumps(dossier))
    with pytest.raises(BoardBindingError, match="RFC 3339|typed evidence validation failed"):
        verify_board_bindings(root, dossier_path)


@pytest.mark.parametrize(
    ("attack", "message"),
    [
        ("missing", "schema validation failed"),
        ("mixed-release", "mixed release, admission, program, or proof"),
        ("mixed-admission", "mixed release, admission, program, or proof"),
        ("schema-downgrade", "typed evidence validation failed"),
        ("status-downgrade", "typed evidence validation failed"),
        ("copied-review", "distinct content digests"),
        ("review-role-key", "trusted rights-reviewer"),
        ("permutation", "exact-ten order"),
        ("cohort-substitution", "exact-ten order"),
        ("mock", "typed evidence validation failed"),
        ("non-groth16", "typed evidence validation failed"),
        ("stale", "is stale"),
        ("future", "later than evaluated"),
        ("same-host-operator", "must be independent"),
        ("metadata-rewrite", "schema validation failed"),
        ("v1-record-substitution", "substitutes the canonical v1 record"),
        ("overlay-downgrade", "schema validation failed"),
    ],
)
def test_v2_rejects_hostile_promotion_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
    message: str,
) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    _fast_recursive_v1(monkeypatch, dossier)
    promotion = dossier["records"][0]["promotion"]
    if attack == "missing":
        del promotion["dependency_security"]
    elif attack in {"mixed-release", "mixed-admission"}:
        ref = promotion["economics"]
        value = json.loads((root / ref["path"]).read_text())
        field = "release_digest" if attack == "mixed-release" else "admission_digest"
        value["claims"]["binding"][field] = "sha256:" + "9" * 64
        _rewrite_typed_evidence(root, ref, value)
    elif attack == "mock":
        ref = promotion["proof_receipt"]
        value = json.loads((root / ref["path"]).read_text())
        value["claims"]["mock"] = True
        _rewrite_typed_evidence(root, ref, value)
    elif attack == "non-groth16":
        ref = promotion["proof_receipt"]
        value = json.loads((root / ref["path"]).read_text())
        value["claims"]["proof_kind"] = "plonk"
        _rewrite_typed_evidence(root, ref, value)
    elif attack in {"schema-downgrade", "status-downgrade"}:
        ref = promotion["solidity_replay"]
        value = json.loads((root / ref["path"]).read_text())
        if attack == "schema-downgrade":
            value["schema_version"] = "p42-prizes/solidity-objective-replay/v1"
        else:
            value["status"] = "pending"
        _rewrite_typed_evidence(root, ref, value)
    elif attack == "stale":
        ref = promotion["external_runtime"]
        value = json.loads((root / ref["path"]).read_text())
        value["issued_at_utc"] = "2026-07-18T00:00:00Z"
        _rewrite_typed_evidence(root, ref, value)
        release_ref = promotion["release_receipt"]
        release = json.loads((root / release_ref["path"]).read_text())
        release["claims"]["external_runtime_digest"] = value["artifact_hash"]
        _rewrite_typed_evidence(root, release_ref, release)
    elif attack == "future":
        ref = promotion["external_runtime"]
        value = json.loads((root / ref["path"]).read_text())
        value["issued_at_utc"] = "2026-07-19T13:00:00Z"
        _rewrite_typed_evidence(root, ref, value)
        release_ref = promotion["release_receipt"]
        release = json.loads((root / release_ref["path"]).read_text())
        release["claims"]["external_runtime_digest"] = value["artifact_hash"]
        _rewrite_typed_evidence(root, release_ref, release)
    elif attack == "copied-review":
        source = root / promotion["reviews"]["math"]["path"]
        target = root / "evidence/review-scope-copy.json"
        target.write_bytes(source.read_bytes())
        promotion["reviews"]["scope"] = {
            "path": target.relative_to(root).as_posix(), "sha256": _digest_bytes(target.read_bytes())
        }
    elif attack == "review-role-key":
        ref = promotion["reviews"]["rights"]
        value = json.loads((root / ref["path"]).read_text())
        value["signer_identity_id"] = "identity:review-math"
        _rewrite_typed_evidence(root, ref, value)
    elif attack == "same-host-operator":
        ref = promotion["host_matrix"]
        value = json.loads((root / ref["path"]).read_text())
        first, second = value["claims"]["entries"][:2]
        second["host_id"] = first["host_id"]
        second["operator_id"] = first["operator_id"]
        second["identity_id"] = first["identity_id"]
        unsigned = {key: item for key, item in second.items() if key not in {"entry_hash", "signature"}}
        entry_hash = _digest_bytes(canonical_json(unsigned).encode("ascii"))
        private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"typed-v2:host-0").digest())
        host_message = (b"P42-OBJECTIVE-HOST-ENTRY-V2\0p42-prizes/objective-host-entry/v2\0"
                        + bytes.fromhex(entry_hash.removeprefix("sha256:")))
        second["entry_hash"] = entry_hash
        second["signature"] = {"algorithm": "ed25519", "value": "ed25519:" + private.sign(host_message).hex()}
        _rewrite_typed_evidence(root, ref, value)
    elif attack == "permutation":
        dossier["records"][0], dossier["records"][1] = dossier["records"][1], dossier["records"][0]
    elif attack == "cohort-substitution":
        dossier["records"][0]["slug"] = "substituted-board"
    elif attack == "metadata-rewrite":
        promotion.update({"release_digest": "sha256:" + "b" * 64,
                          "admission_digest": "sha256:" + "c" * 64,
                          "program_vkey": "0x" + "e" * 64})
    elif attack == "v1-record-substitution":
        dossier["records"][0]["v1_record_sha256"] = "sha256:" + "0" * 64
    elif attack == "overlay-downgrade":
        dossier["schema_version"] = "p42-prizes/production-board-bindings/v1"
    dossier_path.write_text(json.dumps(dossier))

    with pytest.raises(BoardBindingError, match=message):
        verify_board_bindings(root, dossier_path)


@pytest.mark.parametrize("attack", ["v1-activation", "board-permutation", "coordinated-substitution"])
def test_v2_rejects_rehashed_canonical_base_substitution(tmp_path: Path, attack: str) -> None:
    root, dossier_path, dossier = _synthetic_v2_dossier(tmp_path)
    base_path = root / "protocol/production-board-bindings-v1.json"
    board_path = root / "protocol/production-board-set-v1.json"
    base = json.loads(base_path.read_text())
    board = json.loads(board_path.read_text())
    if attack == "v1-activation":
        base["records"][0]["guest"]["activation_eligible"] = True
    elif attack == "board-permutation":
        board["boards"][0], board["boards"][1] = board["boards"][1], board["boards"][0]
    else:
        board["boards"][0] = "substituted-board"
        base["records"][0]["slug"] = "substituted-board"
    base_path.write_text(json.dumps(base, sort_keys=True))
    board_path.write_text(json.dumps(board, sort_keys=True))
    dossier["base_bindings"]["sha256"] = _digest_bytes(base_path.read_bytes())
    dossier["board_set"]["sha256"] = _digest_bytes(board_path.read_bytes())
    dossier_path.write_text(json.dumps(dossier))

    with pytest.raises(BoardBindingError, match="schema validation failed"):
        verify_board_bindings(root, dossier_path)


def test_exact_ten_board_bindings_reject_source_drift(tmp_path: Path) -> None:
    value = deepcopy(json.loads(DOSSIER.read_text()))
    value["records"][0]["problem_yaml"]["sha256"] = "sha256:" + "0" * 64
    mutated = tmp_path / "bindings.json"
    mutated.write_text(json.dumps(value))
    with pytest.raises(BoardBindingError, match="problem_yaml.sha256"):
        verify_board_bindings(ROOT, mutated)


def test_exact_ten_math_review_fixture_corpora_are_deterministic() -> None:
    dossier = json.loads(DOSSIER.read_text())
    for record in dossier["records"]:
        corpus = canonical_math_review_fixtures(ROOT, record)
        assert record["math_review_fixtures"] == corpus
        seed = next(item for item in corpus if item["path"] == record["seed"]["path"])
        assert seed["expected_verdict"]["status"] == "rejected"
        assert seed["expected_verdict"]["reason"] == "NOT_STRICT_IMPROVEMENT"
        assert all(item["expected_verdict"]["status"] == "rejected" for item in corpus)


@pytest.mark.parametrize(
    "attack",
    ["invent", "omit", "status-flip", "reason-substitution", "report-substitution", "hash-substitution"],
)
def test_exact_ten_board_bindings_reject_fixture_corpus_substitution(
    tmp_path: Path, attack: str,
) -> None:
    value = deepcopy(json.loads(DOSSIER.read_text()))
    fixtures = value["records"][0]["math_review_fixtures"]
    if attack == "invent":
        fixtures.append({
            "path": "problems/q6-intersecting-hypergraph/tests/invented.json",
            "sha256": "sha256:" + "0" * 64,
            "expected_verdict": deepcopy(fixtures[0]["expected_verdict"]),
        })
    elif attack == "omit":
        fixtures.pop()
    elif attack == "status-flip":
        fixtures[0]["expected_verdict"].update(status="accepted", valid=True, returncode=0)
    elif attack == "reason-substitution":
        fixtures[0]["expected_verdict"]["reason"] = "SUBSTITUTED_REASON"
    elif attack == "report-substitution":
        fixtures[0]["expected_verdict"]["report_sha256"] = "sha256:" + "0" * 64
    else:
        fixtures[0]["sha256"] = "sha256:" + "0" * 64
    mutated = tmp_path / "bindings.json"
    mutated.write_text(json.dumps(value))

    with pytest.raises(BoardBindingError, match="math_review_fixtures"):
        verify_board_bindings(ROOT, mutated)


def test_hadamard_guest_evidence_is_cross_bound(tmp_path: Path) -> None:
    record, evidence_paths = _write_coherent_guest_evidence(tmp_path)
    _verify_guest_evidence(
        ROOT,
        record,
        "records[9] (hadamard-668-defect)",
        evidence_paths,
    )


def test_hadamard_guest_paths_are_schema_pinned(tmp_path: Path) -> None:
    value = json.loads(DOSSIER.read_text())
    value["records"][9]["guest"]["identity"]["path"] = (
        "objective-programs/artifacts/different-objective-program/v0.1.0/identity.json"
    )
    mutated = tmp_path / "bindings.json"
    mutated.write_text(json.dumps(value))

    with pytest.raises(BoardBindingError, match="schema validation failed"):
        verify_board_bindings(ROOT, mutated)


def test_guest_evidence_rejects_rehashed_wrong_program_swap(tmp_path: Path) -> None:
    record, evidence_paths = _write_coherent_guest_evidence(tmp_path)
    identity_path = evidence_paths["identity"]
    execution_path = evidence_paths["execution"]
    profile_path = evidence_paths["resource_profile"]
    identity = json.loads(identity_path.read_text())
    execution = json.loads(execution_path.read_text())
    profile = json.loads(profile_path.read_text())
    identity["program"] = "different-objective-program"
    profile["program"] = "different-objective-program"

    identity_bytes = json.dumps(identity, sort_keys=True).encode()
    identity_path.write_bytes(identity_bytes)
    execution["identitySha256"] = _digest_bytes(identity_bytes)
    execution_path.write_text(json.dumps(execution))
    profile_path.write_text(json.dumps(profile))
    record["guest"]["identity"]["sha256"] = _digest_bytes(identity_bytes)

    with pytest.raises(BoardBindingError, match="identity.program does not match board slug"):
        _verify_guest_evidence(
            ROOT,
            record,
            "records[9] (hadamard-668-defect)",
            evidence_paths,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("identitySha256", "sha256:" + "0" * 64, "identity digest does not match identity.json"),
        ("programVKey", "0x" + "0" * 64, "program vkeys do not match across evidence"),
        ("solutionPath", "problems/different-objective/solution.json", "solution paths do not match the bound seed"),
    ],
)
def test_guest_evidence_rejects_cross_file_tamper(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    record, evidence_paths = _write_coherent_guest_evidence(tmp_path)
    execution_path = evidence_paths["execution"]
    execution = json.loads(execution_path.read_text())
    execution[field] = value
    execution_path.write_text(json.dumps(execution))

    with pytest.raises(BoardBindingError, match=message):
        _verify_guest_evidence(ROOT, record, "records[9] (hadamard-668-defect)", evidence_paths)
