from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import sys
from urllib import request as urllib_request

import jsonschema

from p42_prizes.admission import (
    AdmissionError,
    build_admission_matrix,
    build_verifier_env,
    compute_source_hash,
    detect_host,
    generate_host_evidence,
    load_evidence_file,
    run_verifier_once,
)
from p42_prizes.adversarial import AdversarialCampaignError, normalize_adversarial_campaign_report
from p42_prizes.da import DaEvidenceError, build_da_evidence, validate_da_evidence
from p42_prizes.governance import GovernanceSignoffError, normalize_governance_signoff
from p42_prizes.incident import IncidentDrillError, normalize_incident_drill_report
from p42_prizes.legal import ChainReader, LegalMemoError, normalize_legal_memo
from p42_prizes.lint import lint_verifier
from p42_prizes.mechanism import Credit, settle_pool
from p42_prizes.operational_controls import (
    OperationalControlsError,
    normalize_operational_controls,
)
from p42_prizes.problem import load_manifest, repo_root_from_problem, validate_problem
from p42_prizes.readiness import validate_fundable_admission
from p42_prizes.runner_alerts import RunnerAlertError, build_runner_alerts
from p42_prizes.runner_burst import RunnerBurstError, normalize_runner_burst_report
from p42_prizes.runner_queue import (
    MemorySnapshot,
    RunnerPolicy,
    RunnerQueueError,
    memory_snapshot_from_proc,
    plan_runner_queue,
)
from p42_prizes.runner_worker import RunnerWorkerError, drain_runner_queue, run_next_job_once
from p42_prizes.secure_json import read_strict_json_stream
from p42_prizes.verdict import canonical_json, parse_rational, sha256_bytes


# Gate validators enforce the published schemas' additionalProperties:false, so a
# gate report with unknown top-level keys is rejected at the CLI boundary.
_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"
_RPC_MAX_RESPONSE_BYTES = 1024 * 1024
_RPC_MAX_RESPONSE_DEPTH = 64
_PRODUCTION_TRUST_ROOT = Path("/etc/p42/production-attestation-root.sha256")


def _enforce_gate_schema(report: dict, schema_name: str) -> None:
    schema = json.loads((_SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    jsonschema.validate(report, schema, format_checker=jsonschema.FormatChecker())


def _load_pinned_trust_registry(path: str, *, allow_test: bool) -> dict:
    trust_registry = load_evidence_file(path)
    _enforce_gate_schema(trust_registry, "attestation-trust-registry.schema.json")
    if trust_registry.get("environment") == "production":
        expected_registry_hash = _read_production_trust_root()
        actual_registry_hash = sha256_bytes(canonical_json(trust_registry).encode("utf-8"))
        if expected_registry_hash != actual_registry_hash:
            raise AdmissionError(
                "production trust registry does not match the protected root digest"
            )
    elif not allow_test:
        raise AdmissionError(
            "test trust registries are rejected by default; use a production root registry or explicitly allow test trust"
        )
    return trust_registry


def _read_production_trust_root() -> str:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise AdmissionError("production trust roots require platform O_NOFOLLOW support")
    try:
        fd = os.open(_PRODUCTION_TRUST_ROOT, os.O_RDONLY | nofollow)
    except OSError as exc:
        raise AdmissionError(
            f"production trust requires protected root file {_PRODUCTION_TRUST_ROOT}"
        ) from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise AdmissionError("production trust root must be a regular file")
        if metadata.st_mode & 0o0222:
            raise AdmissionError("production trust root must not be writable")
        raw = os.read(fd, 256)
        if os.read(fd, 1):
            raise AdmissionError("production trust root file is oversized")
    finally:
        os.close(fd)
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise AdmissionError("production trust root must be ASCII") from exc
    if (
        len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise AdmissionError("production trust root must be sha256:<64-lowercase-hex>")
    return value


def _load_attestation_inputs(args: argparse.Namespace) -> tuple[dict, Path, ChainReader]:
    trust_registry = _load_pinned_trust_registry(
        args.trust_registry,
        allow_test=args.allow_test_trust_registry,
    )
    artifact_root = Path(args.artifact_root).resolve()
    if not artifact_root.is_dir():
        raise AdmissionError("--artifact-root must be an existing directory")
    return trust_registry, artifact_root, _build_http_chain_reader(args.chain_rpc_url)


def _build_http_chain_reader(rpc_url: str) -> ChainReader:
    request_id = 0
    cached_chain_id: int | None = None

    def rpc_call(method: str, params: list[object]) -> object:
        nonlocal request_id
        request_id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            separators=(",", ":"),
        ).encode("utf-8")
        rpc_request = urllib_request.Request(
            rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(rpc_request, timeout=10) as response:
            parsed = read_strict_json_stream(
                response,
                max_bytes=_RPC_MAX_RESPONSE_BYTES,
                max_depth=_RPC_MAX_RESPONSE_DEPTH,
            )
        if not isinstance(parsed, dict) or "error" in parsed or "result" not in parsed:
            raise ValueError(f"JSON-RPC {method} returned an error or malformed response")
        return parsed["result"]

    def read_chain(network: str, chain_id: int, address: str, block_number: int) -> dict[str, str]:
        nonlocal cached_chain_id
        del network
        if cached_chain_id is None:
            chain_result = rpc_call("eth_chainId", [])
            if not isinstance(chain_result, str):
                raise ValueError("eth_chainId returned a non-string result")
            cached_chain_id = int(chain_result, 16)
        if cached_chain_id != chain_id:
            raise ValueError(f"RPC chain ID {cached_chain_id} does not match release chain ID {chain_id}")
        block_tag = hex(block_number)
        block = rpc_call("eth_getBlockByNumber", [block_tag, False])
        runtime_bytecode = rpc_call("eth_getCode", [address, block_tag])
        if not isinstance(block, dict) or not isinstance(block.get("hash"), str):
            raise ValueError("eth_getBlockByNumber did not return a block hash")
        if not isinstance(runtime_bytecode, str):
            raise ValueError("eth_getCode returned a non-string result")
        return {"block_hash": block["hash"], "runtime_bytecode": runtime_bytecode}

    return read_chain


def _add_attestation_validation_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--trust-registry",
        required=True,
        help="owner-controlled signer registry supplied out of band from the report",
    )
    parser.add_argument(
        "--artifact-root",
        required=True,
        help="local bound Git repository containing every referenced evidence file",
    )
    parser.add_argument(
        "--chain-rpc-url",
        required=True,
        help="JSON-RPC endpoint queried at each recorded bytecode evidence block",
    )
    parser.add_argument(
        "--allow-test-trust-registry",
        action="store_true",
        help="allow an explicitly marked test registry for local validation only",
    )


def _cmd_validate(args: argparse.Namespace) -> int:
    errors = validate_problem(args.problem)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"OK: {Path(args.problem)}")
    return 0


def _cmd_lint(args: argparse.Namespace) -> int:
    problem = Path(args.problem)
    findings = lint_verifier(problem)
    if findings:
        root = repo_root_from_problem(problem)
        for finding in findings:
            print(finding.format(root), file=sys.stderr)
        return 1
    print(f"OK: {problem / 'verifier'}")
    return 0


def _cmd_source_hash(args: argparse.Namespace) -> int:
    """Emit the versioned verifier source-tree digest used by fresh ceremonies."""

    print(compute_source_hash(Path(args.problem).resolve()))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    problem = Path(args.problem).resolve()
    solution = Path(args.solution).resolve()
    manifest = load_manifest(problem)
    command_template = manifest["verifier"]["command"]
    command = [
        part.format(solution=str(solution))
        for part in shlex.split(command_template)
    ]
    wall_seconds = int(manifest["verifier"].get("max_compute", {}).get("wall_seconds", 30))

    # Scrub the environment so the untrusted verifier cannot read host secrets,
    # and run it in its own session/process group so a timeout kills the whole
    # tree (no surviving orphans) — matching the runner and admission paths
    # (audit L7 / secret-env).
    env = build_verifier_env(problem)
    process = subprocess.Popen(command, cwd=problem, env=env, start_new_session=True)
    try:
        return process.wait(timeout=wall_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        print(f"verifier timed out after {wall_seconds}s", file=sys.stderr)
        return 124


def _cmd_simulate(args: argparse.Namespace) -> int:
    credits = [Credit.parse(raw) for raw in args.credit]
    result = settle_pool(args.pool_wei, credits, fee_bps=args.fee_bps)
    print(canonical_json(result))
    return 0


def _write_or_print_json(value: dict, output: str | None) -> None:
    encoded = canonical_json(value) + "\n"
    if output:
        Path(output).write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


def _cmd_admit_host(args: argparse.Namespace) -> int:
    host = detect_host(args.host_label)
    try:
        evidence = generate_host_evidence(
            args.problem,
            args.solution,
            host=host,
            runs=args.runs,
            image_ref=args.image_ref,
            runtime=args.runtime,
            signing_key=args.signing_key,
        )
        _enforce_gate_schema(evidence, "admission-host.schema.json")
    except (AdmissionError, OSError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(evidence, args.output)
    return 0


def _cmd_admit_matrix(args: argparse.Namespace) -> int:
    try:
        evidence = [load_evidence_file(path) for path in args.evidence]
        matrix = build_admission_matrix(evidence)
        _enforce_gate_schema(matrix, "admission-matrix.schema.json")
    except (AdmissionError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(matrix, args.output)
    return 0


def _cmd_admit_ready(args: argparse.Namespace) -> int:
    errors = validate_fundable_admission(args.problem, args.matrix)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"OK: {Path(args.problem)} is fundable-admission ready")
    return 0


def _cmd_seed_check(args: argparse.Namespace) -> int:
    problem = Path(args.problem).resolve()
    solution = Path(args.solution).resolve()
    try:
        manifest = load_manifest(problem)
        run = run_verifier_once(problem, solution)
        seed_best = parse_rational(manifest["objective"]["seed_best"])
        score = parse_rational(run.report["score"])
        improvement = parse_rational(run.report["improvement"])
    except (AdmissionError, OSError, KeyError, TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if run.report["valid"] and improvement > 0:
        status = "STRICT_WITNESS"
        release_ready = True
    elif not run.report["valid"] and run.report["reason"] == "NOT_STRICT_IMPROVEMENT" and improvement == 0:
        status = "FRONTIER_MATCH_ONLY" if score == seed_best else "NONFRONTIER_FIXTURE"
        release_ready = False
    else:
        print(
            f"{manifest['problem_id']}: designated seed fixture is neither a strict witness nor an exact frontier match",
            file=sys.stderr,
        )
        return 1

    print(
        canonical_json(
            {
                "problem_id": manifest["problem_id"],
                "release_ready": release_ready,
                "report_hash": run.report_hash,
                "score": run.report["score"],
                "status": status,
            }
        )
    )
    if args.require_strict and not release_ready:
        return 1
    return 0


def _cmd_da_receipt(args: argparse.Namespace) -> int:
    try:
        evidence = build_da_evidence(
            args.problem,
            args.solution,
            solution_cid=args.solution_cid,
            solver_address=args.solver_address,
            salt=args.salt,
            commit_provider=args.commit_provider,
            commit_receipt_uri=args.commit_receipt_uri,
            commit_block_reference=args.commit_block_reference,
            da_mode=args.da_mode,
            reveal_tx=args.reveal_tx,
            store_locator=args.store_locator,
            solution_bytes_length=args.solution_bytes_length,
            arweave_txid=args.arweave_txid,
            arweave_receipt_uri=args.arweave_receipt_uri,
        )
    except DaEvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(evidence, args.output)
    return 0


def _cmd_da_verify(args: argparse.Namespace) -> int:
    try:
        evidence = validate_da_evidence(
            load_evidence_file(args.evidence),
            problem_dir=args.problem,
            solution_path=args.solution,
        )
    except (AdmissionError, DaEvidenceError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    # Also enforce the published JSON schema (like the sibling gate validators),
    # so a structurally-malformed receipt is rejected at the CLI boundary and not
    # only by the pure-Python semantic checks.
    try:
        _enforce_gate_schema(evidence, "da-receipt.schema.json")
    except jsonschema.ValidationError as exc:
        print(f"da-receipt schema validation failed: {exc.message}", file=sys.stderr)
        return 1
    if args.solution is None:
        # Without --solution the sha256 content binding to the actual solution
        # bytes is skipped, so this pass proves structure only. Say so loudly and
        # exit 3 (distinct from 0/1) so a structure-only pass can never be
        # mistaken for a content/availability proof (audit F30).
        print(
            "OK (structure only; solution bytes NOT verified): "
            f"DA evidence {evidence['evidence_hash']}"
        )
        return 3
    print(f"OK: DA evidence {evidence['evidence_hash']}")
    return 0


def _cmd_runner_plan(args: argparse.Namespace) -> int:
    try:
        queue = load_evidence_file(args.queue)
        decision = plan_runner_queue(
            queue,
            memory=_runner_memory_from_args(args),
            policy=_runner_policy_from_args(args),
            now_utc=args.now_utc,
        )
    except (AdmissionError, RunnerQueueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(decision))
    return 0


def _runner_memory_from_args(args: argparse.Namespace) -> MemorySnapshot:
    if (
        args.total_memory_mb is None
        or args.available_memory_mb is None
        or args.swap_used_mb is None
    ):
        return memory_snapshot_from_proc()
    return MemorySnapshot(
        total_mb=args.total_memory_mb,
        available_mb=args.available_memory_mb,
        swap_used_mb=args.swap_used_mb,
    )


def _runner_policy_from_args(args: argparse.Namespace) -> RunnerPolicy:
    return RunnerPolicy(
        max_running=args.max_running,
        reserve_memory_mb=args.reserve_memory_mb,
        max_swap_used_mb=args.max_swap_used_mb,
        memory_safety_factor=args.memory_safety_factor,
        sandbox=args.sandbox,
        sandbox_pids_limit=args.sandbox_pids_limit,
        sandbox_cpus=args.sandbox_cpus,
    )


def _cmd_runner_work_once(args: argparse.Namespace) -> int:
    try:
        result = run_next_job_once(
            args.queue,
            args.transcripts,
            memory=_runner_memory_from_args(args),
            policy=_runner_policy_from_args(args),
            now_utc=args.now_utc,
            lease_seconds=args.lease_seconds,
        )
    except (AdmissionError, RunnerQueueError, RunnerWorkerError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(result))
    return 0


def _cmd_runner_drain(args: argparse.Namespace) -> int:
    try:
        result = drain_runner_queue(
            args.queue,
            args.transcripts,
            memory_provider=lambda: _runner_memory_from_args(args),
            policy=_runner_policy_from_args(args),
            lease_seconds=args.lease_seconds,
            poll_seconds=args.poll_seconds,
            max_iterations=args.max_iterations,
            max_jobs=args.max_jobs,
        )
    except (AdmissionError, RunnerQueueError, RunnerWorkerError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(canonical_json(result))
    return 0


def _cmd_runner_alerts(args: argparse.Namespace) -> int:
    transcript_paths: list[str] = []
    if args.transcripts:
        transcript_paths.extend(str(path) for path in sorted(Path(args.transcripts).glob("*.json")))
    transcript_paths.extend(args.transcript or [])
    if not transcript_paths:
        print("no runner transcripts provided", file=sys.stderr)
        return 1
    try:
        result = build_runner_alerts(transcript_paths, now_utc=args.now_utc)
    except RunnerAlertError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(result, args.output)
    if args.fail_on_alert and result["alert_count"] > 0:
        return 2
    return 0


def _cmd_runner_burst_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry = _load_pinned_trust_registry(
            args.trust_registry,
            allow_test=args.allow_test_trust_registry,
        )
        report = normalize_runner_burst_report(
            load_evidence_file(args.report),
            artifact_root=args.artifact_root,
            trust_registry=trust_registry,
        )
        _enforce_gate_schema(report, "runner-burst.schema.json")
    except (AdmissionError, RunnerBurstError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_incident_drill_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry, artifact_root, chain_reader = _load_attestation_inputs(args)
        report = normalize_incident_drill_report(
            load_evidence_file(args.report),
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
        )
        _enforce_gate_schema(report, "incident-drill.schema.json")
    except (AdmissionError, IncidentDrillError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_adversarial_campaign_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry, artifact_root, chain_reader = _load_attestation_inputs(args)
        report = normalize_adversarial_campaign_report(
            load_evidence_file(args.report),
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
        )
        _enforce_gate_schema(report, "adversarial-campaign.schema.json")
    except (AdmissionError, AdversarialCampaignError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_governance_signoff_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry, artifact_root, chain_reader = _load_attestation_inputs(args)
        report = normalize_governance_signoff(
            load_evidence_file(args.report),
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
        )
        _enforce_gate_schema(report, "governance-signoff.schema.json")
    except (AdmissionError, GovernanceSignoffError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_legal_memo_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry, artifact_root, chain_reader = _load_attestation_inputs(args)
        report = normalize_legal_memo(
            load_evidence_file(args.report),
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
        )
        _enforce_gate_schema(report, "legal-memo.schema.json")
    except (AdmissionError, LegalMemoError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def _cmd_operational_controls_validate(args: argparse.Namespace) -> int:
    try:
        trust_registry, artifact_root, chain_reader = _load_attestation_inputs(args)
        report = normalize_operational_controls(
            load_evidence_file(args.report),
            trust_registry=trust_registry,
            artifact_root=artifact_root,
            chain_reader=chain_reader,
        )
        _enforce_gate_schema(report, "operational-controls.schema.json")
    except (AdmissionError, OperationalControlsError, jsonschema.ValidationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _write_or_print_json(report, args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="p42-prizes")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate a p42-problem repository")
    validate.add_argument("--problem", required=True)
    validate.set_defaults(func=_cmd_validate)

    lint = subparsers.add_parser("lint", help="lint verifier code for exact-path hazards")
    lint.add_argument("--problem", required=True)
    lint.set_defaults(func=_cmd_lint)

    source_hash = subparsers.add_parser(
        "source-hash",
        help="emit the canonical p42-source-tree-sha256/v1 verifier digest",
    )
    source_hash.add_argument("--problem", required=True)
    source_hash.set_defaults(func=_cmd_source_hash)

    verify = subparsers.add_parser("verify", help="run a problem's configured verifier")
    verify.add_argument("--problem", required=True)
    verify.add_argument("--solution", required=True)
    verify.set_defaults(func=_cmd_verify)

    simulate = subparsers.add_parser("simulate", help="settle exact improvement credits")
    simulate.add_argument("--pool-wei", type=int, required=True)
    simulate.add_argument("--fee-bps", type=int, default=250)
    simulate.add_argument(
        "--credit",
        action="append",
        default=[],
        help="solver improvement, e.g. alice=6/1; repeat for each finalized advance",
    )
    simulate.set_defaults(func=_cmd_simulate)

    admit_host = subparsers.add_parser(
        "admit-host",
        help="run a verifier repeatedly on one host and emit host admission evidence",
    )
    admit_host.add_argument("--problem", required=True)
    admit_host.add_argument("--solution", required=True)
    admit_host.add_argument("--runs", type=int, default=3)
    admit_host.add_argument("--host-label")
    admit_host.add_argument(
        "--image-ref",
        help="registry repository@sha256:digest; required when problem.yaml pins an immutable image",
    )
    admit_host.add_argument("--runtime", default="docker", help="OCI runtime used for immutable admission")
    admit_host.add_argument(
        "--signing-key",
        help="Ed25519 SSH private key whose public key is trusted by problem.yaml",
    )
    admit_host.add_argument("--output")
    admit_host.set_defaults(func=_cmd_admit_host)

    admit_matrix = subparsers.add_parser(
        "admit-matrix",
        help="combine host evidence and enforce the N-host verifier matrix gate",
    )
    admit_matrix.add_argument(
        "--evidence",
        action="append",
        required=True,
        help="host evidence JSON file; repeat for every matrix host",
    )
    admit_matrix.add_argument("--output")
    admit_matrix.set_defaults(func=_cmd_admit_matrix)

    admit_ready = subparsers.add_parser(
        "admit-ready",
        help="check a problem manifest plus N-host matrix before funding/admission",
    )
    admit_ready.add_argument("--problem", required=True)
    admit_ready.add_argument("--matrix", required=True)
    admit_ready.set_defaults(func=_cmd_admit_ready)

    seed_check = subparsers.add_parser(
        "seed-check",
        help="classify a designated fixture as a strict open witness or exact frontier match",
    )
    seed_check.add_argument("--problem", required=True)
    seed_check.add_argument("--solution", required=True)
    seed_check.add_argument("--require-strict", action="store_true")
    seed_check.set_defaults(func=_cmd_seed_check)

    da_receipt = subparsers.add_parser(
        "da-receipt",
        help="build canonical DA-reference evidence: sha256(solution)==commitDaHash anchor "
        "plus reveal-tx (onchain) or store locator (offchain); optional Arweave mirror",
    )
    da_receipt.add_argument("--problem", required=True)
    da_receipt.add_argument("--solution", required=True)
    da_receipt.add_argument("--solution-cid", required=True)
    da_receipt.add_argument("--solver-address", required=True)
    da_receipt.add_argument("--salt", required=True)
    # Legacy commit-time off-chain-blob receipt metadata: optional. The DA proof
    # is the sha256 anchor + reveal-tx/store-locator, not these fields.
    da_receipt.add_argument("--commit-provider", help="optional legacy commit-receipt provider")
    da_receipt.add_argument("--commit-receipt-uri", help="optional legacy commit-receipt URI")
    da_receipt.add_argument("--commit-block-reference", help="optional legacy commit-receipt block reference")
    # DA mode: on-chain problems carry bytes in the reveal calldata (--reveal-tx
    # required); off-chain (large-certificate) problems keep bytes in a
    # content-addressed store gated by the same sha256 anchor (--store-locator).
    da_receipt.add_argument("--da-mode", choices=["onchain", "offchain"], default="onchain")
    da_receipt.add_argument("--reveal-tx", help="reveal tx hash carrying the solution calldata (required for onchain da-mode)")
    da_receipt.add_argument("--store-locator", help="content-addressed store locator (required for offchain da-mode)")
    da_receipt.add_argument("--solution-bytes-length", type=int)
    # Arweave is now an OPTIONAL off-chain mirror, no longer required.
    da_receipt.add_argument("--arweave-txid")
    da_receipt.add_argument("--arweave-receipt-uri")
    da_receipt.add_argument("--output")
    da_receipt.set_defaults(func=_cmd_da_receipt)

    da_verify = subparsers.add_parser(
        "da-verify",
        help="verify canonical DA/permanence evidence before finalize",
    )
    da_verify.add_argument("--evidence", required=True)
    da_verify.add_argument("--problem")
    da_verify.add_argument(
        "--solution",
        help="solution file to bind by sha256; omitting it downgrades the pass to structure-only (exit 3)",
    )
    da_verify.set_defaults(func=_cmd_da_verify)

    runner_plan = subparsers.add_parser(
        "runner-plan",
        help="decide whether the verifier runner may start the next queued job",
    )
    runner_plan.add_argument("--queue", required=True)
    runner_plan.add_argument("--total-memory-mb", type=int)
    runner_plan.add_argument("--available-memory-mb", type=int)
    runner_plan.add_argument("--swap-used-mb", type=int)
    runner_plan.add_argument("--max-running", type=int, default=1)
    runner_plan.add_argument("--reserve-memory-mb", type=int, default=8192)
    runner_plan.add_argument("--max-swap-used-mb", type=int, default=1024)
    runner_plan.add_argument("--memory-safety-factor", type=float, default=2.0)
    runner_plan.add_argument("--sandbox", choices=["none", "docker"], default="none")
    runner_plan.add_argument("--sandbox-pids-limit", type=int, default=256)
    runner_plan.add_argument("--sandbox-cpus", type=float, default=1.0)
    runner_plan.add_argument("--now-utc")
    runner_plan.set_defaults(func=_cmd_runner_plan)

    runner_work = subparsers.add_parser(
        "runner-work-once",
        help="lease one queued verifier job, run it, write transcript, update queue",
    )
    runner_work.add_argument("--queue", required=True)
    runner_work.add_argument("--transcripts", required=True)
    runner_work.add_argument("--lease-seconds", type=int, default=3600)
    runner_work.add_argument("--total-memory-mb", type=int)
    runner_work.add_argument("--available-memory-mb", type=int)
    runner_work.add_argument("--swap-used-mb", type=int)
    runner_work.add_argument("--max-running", type=int, default=1)
    runner_work.add_argument("--reserve-memory-mb", type=int, default=8192)
    runner_work.add_argument("--max-swap-used-mb", type=int, default=1024)
    runner_work.add_argument("--memory-safety-factor", type=float, default=2.0)
    runner_work.add_argument("--sandbox", choices=["none", "docker"], default="none")
    runner_work.add_argument("--sandbox-pids-limit", type=int, default=256)
    runner_work.add_argument("--sandbox-cpus", type=float, default=1.0)
    runner_work.add_argument("--now-utc")
    runner_work.set_defaults(func=_cmd_runner_work_once)

    runner_drain = subparsers.add_parser(
        "runner-drain",
        help="keep draining queued verifier jobs, rechecking memory before each lease",
    )
    runner_drain.add_argument("--queue", required=True)
    runner_drain.add_argument("--transcripts", required=True)
    runner_drain.add_argument("--lease-seconds", type=int, default=3600)
    runner_drain.add_argument("--poll-seconds", type=float, default=30.0)
    runner_drain.add_argument("--max-iterations", type=int)
    runner_drain.add_argument("--max-jobs", type=int)
    runner_drain.add_argument("--total-memory-mb", type=int)
    runner_drain.add_argument("--available-memory-mb", type=int)
    runner_drain.add_argument("--swap-used-mb", type=int)
    runner_drain.add_argument("--max-running", type=int, default=1)
    runner_drain.add_argument("--reserve-memory-mb", type=int, default=8192)
    runner_drain.add_argument("--max-swap-used-mb", type=int, default=1024)
    runner_drain.add_argument("--memory-safety-factor", type=float, default=2.0)
    runner_drain.add_argument("--sandbox", choices=["none", "docker"], default="none")
    runner_drain.add_argument("--sandbox-pids-limit", type=int, default=256)
    runner_drain.add_argument("--sandbox-cpus", type=float, default=1.0)
    runner_drain.set_defaults(func=_cmd_runner_drain)

    runner_alerts = subparsers.add_parser(
        "runner-alerts",
        help="build challenge/ops alerts from runner transcripts",
    )
    runner_alerts.add_argument("--transcripts", help="directory containing runner transcript JSON files")
    runner_alerts.add_argument(
        "--transcript",
        action="append",
        help="single runner transcript JSON file; repeat as needed",
    )
    runner_alerts.add_argument("--now-utc")
    runner_alerts.add_argument("--output")
    runner_alerts.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="return exit code 2 when any alert is emitted",
    )
    runner_alerts.set_defaults(func=_cmd_runner_alerts)

    runner_burst = subparsers.add_parser(
        "runner-burst-validate",
        help="validate and hash a Gate 1 verifier runner burst/OOM rehearsal report",
    )
    runner_burst.add_argument("--report", required=True)
    runner_burst.add_argument("--artifact-root", required=True)
    runner_burst.add_argument("--trust-registry", required=True)
    runner_burst.add_argument("--allow-test-trust-registry", action="store_true")
    runner_burst.add_argument("--output")
    runner_burst.set_defaults(func=_cmd_runner_burst_validate)

    incident_drill = subparsers.add_parser(
        "incident-drill-validate",
        help="validate and hash a completed incident drill / bug bounty evidence report",
    )
    incident_drill.add_argument("--report", required=True)
    _add_attestation_validation_args(incident_drill)
    incident_drill.add_argument("--output")
    incident_drill.set_defaults(func=_cmd_incident_drill_validate)

    adversarial_campaign = subparsers.add_parser(
        "adversarial-campaign-validate",
        help="validate and hash a Gate 1 adversarial testnet campaign report",
    )
    adversarial_campaign.add_argument("--report", required=True)
    _add_attestation_validation_args(adversarial_campaign)
    adversarial_campaign.add_argument("--output")
    adversarial_campaign.set_defaults(func=_cmd_adversarial_campaign_validate)

    governance_signoff = subparsers.add_parser(
        "governance-signoff-validate",
        help="validate and hash Gate 2 custody/governance signoff evidence",
    )
    governance_signoff.add_argument("--report", required=True)
    _add_attestation_validation_args(governance_signoff)
    governance_signoff.add_argument("--output")
    governance_signoff.set_defaults(func=_cmd_governance_signoff_validate)

    legal_memo = subparsers.add_parser(
        "legal-memo-validate",
        help="validate and hash Gate 2 legal/compliance memo evidence",
    )
    legal_memo.add_argument("--report", required=True)
    _add_attestation_validation_args(legal_memo)
    legal_memo.add_argument("--output")
    legal_memo.set_defaults(func=_cmd_legal_memo_validate)

    operational_controls = subparsers.add_parser(
        "operational-controls-validate",
        help="validate and hash Gate 2 wallet/session and abuse-control evidence",
    )
    operational_controls.add_argument("--report", required=True)
    _add_attestation_validation_args(operational_controls)
    operational_controls.add_argument("--output")
    operational_controls.set_defaults(func=_cmd_operational_controls_validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
