from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import subprocess
import threading
from typing import Any, Mapping

from p42_prizes.legal import _attestation_message, _ed_decode_point, _ed_scalar_mult, ethereum_keccak256
from p42_prizes.verdict import canonical_json, sha256_bytes


_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_BASE = _ed_decode_point(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))
assert _BASE is not None

REPOSITORY_URI = "https://github.com/techno-optimist/p42-prizes"
CONTRACT_NAMES = [
    "P42BountyPool",
    "P42PayoutLedger",
    "P42SubmissionManager",
    "P42ChallengeManager",
    "P42ProblemRegistry",
]
CANONICAL_SHARED_CONTRACTS = [
    ("timelock", "P42MultisigTimelock"),
    ("registry", "P42ProblemRegistry"),
    ("rolloverVault", "P42RolloverVault"),
    ("submissionManagerFactory", "P42SubmissionManagerFactory"),
    ("challengeManagerFactory", "P42ChallengeManagerFactory"),
    ("objectiveVerifier", "P42SP1VerifierGateway"),
    ("resolverQuorum", "P42ResolverQuorum"),
]
CANONICAL_BOARD_CONTRACTS = [
    ("pool", "P42BountyPool"),
    ("ledger", "P42PayoutLedger"),
    ("submissions", "P42SubmissionManager"),
    ("challenges", "P42ChallengeManager"),
]

_SIGNING_SEEDS: dict[str, bytes] = {}


class AttestationFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._artifacts: dict[str, dict[str, str]] = {}
        self._chain_id: int | None = None
        self._chain_state: dict[tuple[int, str, int], dict[str, str]] = {}
        self._run("git", "init", "-q")
        self._run("git", "config", "user.name", "P42 Test Attestor")
        self._run("git", "config", "user.email", "attestor@p42-fixtures.dev")
        self._run("git", "remote", "add", "origin", REPOSITORY_URI)

    def artifact(
        self,
        label: str,
        *,
        content: Any | None = None,
        created_at_utc: str = "2026-07-08T15:00:00Z",
        suffix: str = ".json",
    ) -> dict[str, str]:
        key = f"{label}{suffix}"
        if key in self._artifacts:
            return dict(self._artifacts[key])
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-")
        relative = Path("evidence") / f"{safe_label}{suffix}"
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            encoded = content
        elif isinstance(content, str):
            encoded = content.encode("utf-8")
        else:
            encoded = canonical_json(content if content is not None else {"evidence": label}).encode("utf-8")
        path.write_bytes(encoded)
        reference = {
            "uri": f"repo://{relative.as_posix()}",
            "local_path": relative.as_posix(),
            "sha256": "sha256:" + hashlib.sha256(encoded).hexdigest(),
            "created_at_utc": created_at_utc,
        }
        self._artifacts[key] = reference
        return dict(reference)

    def identity(
        self,
        label: str,
        name: str,
        role: str,
        *,
        organization: str = "Project Forty Two Labs",
        independent: bool = False,
        **extra: Any,
    ) -> dict[str, Any]:
        seed = hashlib.sha256(("ed25519-test-seed:" + label).encode("utf-8")).digest()
        expanded = hashlib.sha512(seed).digest()
        scalar_bytes = bytearray(expanded[:32])
        scalar_bytes[0] &= 248
        scalar_bytes[31] &= 63
        scalar_bytes[31] |= 64
        public_bytes = _encode_point(_ed_scalar_mult(int.from_bytes(scalar_bytes, "little"), _BASE))
        public_key = "ed25519:" + public_bytes.hex()
        _SIGNING_SEEDS[public_key] = seed
        result: dict[str, Any] = {
            "name": name,
            "organization": organization,
            "professional_email": f"{label}@attestors.dev",
            "role": role,
            "public_key": public_key,
            "identity_evidence": self.artifact(f"identity-{label}"),
        }
        if independent:
            result["independent_from_p42"] = True
        result.update(extra)
        return result

    def release_binding(self, network: str = "base-mainnet") -> dict[str, Any]:
        chain_id = {"local": 31337, "base-sepolia": 84532, "base-mainnet": 8453}[network]
        contracts: list[dict[str, Any]] = []
        manifest_contracts: list[dict[str, Any]] = []
        configured_addresses: dict[str, str] = {}
        for index, name in enumerate(CONTRACT_NAMES):
            contract_address = address(f"{network}-{name}")
            runtime_bytes = hashlib.sha256(f"runtime:{network}:{name}".encode("utf-8")).digest()[:16]
            runtime_hash = "sha256:" + hashlib.sha256(runtime_bytes).hexdigest()
            runtime_artifact = self.artifact(
                f"release-{network}-runtime-{name}",
                content="0x" + runtime_bytes.hex(),
                created_at_utc="2026-07-08T14:00:00Z",
                suffix=".hex",
            )
            chain_artifact = self.artifact(
                f"release-{network}-chain-{name}",
                content={
                    "jsonrpc": "2.0",
                    "method": "eth_getCode",
                    "network": network,
                    "chain_id": chain_id,
                    "address": contract_address,
                    "block_number": 4200 + index,
                    "block_hash": "0x" + hashlib.sha256(f"block:{network}:{index}".encode()).hexdigest(),
                    "result": "0x" + runtime_bytes.hex(),
                },
                created_at_utc="2026-07-08T14:05:00Z",
            )
            block_number = 4200 + index
            block_hash = "0x" + hashlib.sha256(f"block:{network}:{index}".encode()).hexdigest()
            self._chain_id = chain_id
            self._chain_state[(chain_id, contract_address.casefold(), block_number)] = {
                "block_hash": block_hash,
                "runtime_bytecode": "0x" + runtime_bytes.hex(),
            }
            source_artifact = self.artifact(
                f"release-{network}-source-{name}",
                content=f"// exact release source for {name}\ncontract {name} {{}}\n",
                created_at_utc="2026-07-08T13:30:00Z",
                suffix=".sol",
            )
            contract = {
                "name": name,
                "address": contract_address,
                "runtime_bytecode_hash": runtime_hash,
                "source_artifact": source_artifact,
                "runtime_bytecode_artifact": runtime_artifact,
                "chain_bytecode_artifact": chain_artifact,
            }
            contracts.append(contract)
            manifest_contracts.append(
                {"name": name, "address": contract_address, "runtime_bytecode_hash": runtime_hash}
            )
            configured_addresses[name] = contract_address
        deployment_manifest = self.artifact(
            f"release-{network}-deployment",
            content={
                "repository_uri": REPOSITORY_URI,
                "network": network,
                "chain_id": chain_id,
                "contracts": manifest_contracts,
            },
            created_at_utc="2026-07-08T14:10:00Z",
        )
        configuration_artifact = self.artifact(
            f"release-{network}-configuration",
            content={"network": network, "chain_id": chain_id, "contracts": configured_addresses},
            created_at_utc="2026-07-08T13:45:00Z",
        )
        self._run("git", "add", ".")
        self._run(
            "git",
            "-c",
            "user.name=P42 Test Attestor",
            "-c",
            "user.email=attestor@p42-fixtures.dev",
            "commit",
            "-q",
            "-m",
            f"fixture release {network}",
        )
        commit = self._run("git", "rev-parse", "HEAD").stdout.strip()
        return {
            "repository_uri": REPOSITORY_URI,
            "git_commit": commit,
            "network": network,
            "chain_id": chain_id,
            "deployment_manifest": deployment_manifest,
            "configuration_artifact": configuration_artifact,
            "contracts": contracts,
        }

    def canonical_release_binding(
        self,
        network: str = "base-sepolia",
        *,
        problem_overrides: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        chain_id = {"local": 31337, "base-sepolia": 84532, "base-mainnet": 8453}[network]
        topology = {
            "schema": "p42-prizes/canonical-contract-topology/v1",
            "boardCount": 10,
            "shared": [{"key": key, "name": name} for key, name in CANONICAL_SHARED_CONTRACTS],
            "perBoard": [{"key": key, "name": name} for key, name in CANONICAL_BOARD_CONTRACTS],
        }
        topology_artifact = self.artifact(
            f"release-{network}-canonical-topology", content=topology, created_at_utc="2026-07-08T13:00:00Z"
        )
        slots = [(f"shared.{key}", name) for key, name in CANONICAL_SHARED_CONTRACTS]
        slots.extend(
            (f"board.{board}.{key}", name)
            for board in range(1, 11)
            for key, name in CANONICAL_BOARD_CONTRACTS
        )
        contracts: list[dict[str, Any]] = []
        manifest_contracts: dict[str, dict[str, str]] = {}
        for index, (topology_key, name) in enumerate(slots):
            contract_address = address(f"{network}-{topology_key}-{name}")
            runtime_bytes = hashlib.sha256(f"runtime:{network}:{name}".encode()).digest()[:16]
            runtime_hash = "sha256:" + hashlib.sha256(runtime_bytes).hexdigest()
            manifest_runtime_hash = ethereum_keccak256(runtime_bytes)
            runtime_artifact = self.artifact(
                f"canonical-{network}-runtime-{name}",
                content="0x" + runtime_bytes.hex(),
                created_at_utc="2026-07-08T14:00:00Z",
                suffix=".hex",
            )
            source_artifact = self.artifact(
                f"canonical-{network}-source-{name}",
                content=f"// exact release source for {name}\ncontract {name} {{}}\n",
                created_at_utc="2026-07-08T13:30:00Z",
                suffix=".sol",
            )
            block_number = 5200 + index
            block_hash = "0x" + hashlib.sha256(f"canonical-block:{network}:{index}".encode()).hexdigest()
            chain_artifact = self.artifact(
                f"canonical-{network}-chain-{topology_key}",
                content={
                    "jsonrpc": "2.0",
                    "method": "eth_getCode",
                    "network": network,
                    "chain_id": chain_id,
                    "address": contract_address,
                    "block_number": block_number,
                    "block_hash": block_hash,
                    "result": "0x" + runtime_bytes.hex(),
                },
                created_at_utc="2026-07-08T14:05:00Z",
            )
            self._chain_id = chain_id
            self._chain_state[(chain_id, contract_address.casefold(), block_number)] = {
                "block_hash": block_hash,
                "runtime_bytecode": "0x" + runtime_bytes.hex(),
            }
            contracts.append(
                {
                    "topology_key": topology_key,
                    "name": name,
                    "address": contract_address,
                    "runtime_bytecode_hash": runtime_hash,
                    "manifest_runtime_code_hash": manifest_runtime_hash,
                    "source_artifact": source_artifact,
                    "runtime_bytecode_artifact": runtime_artifact,
                    "chain_bytecode_artifact": chain_artifact,
                }
            )
            manifest_contracts[topology_key] = {
                "name": name,
                "address": contract_address,
                "runtimeCodeHash": manifest_runtime_hash,
            }

        self._run("git", "add", ".")
        self._run("git", "commit", "-q", "-m", f"freeze canonical topology {network}")
        deployment_commit = self._run("git", "rev-parse", "HEAD").stdout.strip()
        deployment_config_hash = "0x" + hashlib.sha256(
            f"deployment-config:{network}:{deployment_commit}".encode()
        ).hexdigest()
        deployment = {
            "schema": "p42-prizes/deployment-manifest/v2",
            "deploymentCommit": deployment_commit,
            "network": {"name": "baseSepolia" if network == "base-sepolia" else network, "chainId": chain_id},
            "releaseMode": "production",
            "status": "governance-setup-complete",
            "deploymentConfigHash": deployment_config_hash,
            "releaseEvidence": {"contractCount": 47, "boardCount": 10},
            "contracts": {
                key: manifest_contracts[f"shared.{key}"] for key, _ in CANONICAL_SHARED_CONTRACTS
            },
            "problems": [
                {
                    "problemId": str(board),
                    "contracts": {
                        key: manifest_contracts[f"board.{board}.{key}"]
                        for key, _ in CANONICAL_BOARD_CONTRACTS
                    },
                    **dict((problem_overrides or {}).get(str(board), {})),
                }
                for board in range(1, 11)
            ],
        }
        deployment_manifest = self.artifact(
            f"canonical-{network}-deployment", content=deployment, created_at_utc="2026-07-08T14:10:00Z"
        )
        expected_contracts = {
            contract["topology_key"]: {
                "name": contract["name"],
                "address": contract["address"].casefold(),
                "manifest_runtime_code_hash": contract["manifest_runtime_code_hash"].casefold(),
            }
            for contract in contracts
        }
        configuration_artifact = self.artifact(
            f"canonical-{network}-configuration",
            content={
                "schema": "p42-adversarial-release-configuration/v2",
                "network": network,
                "chain_id": chain_id,
                "deployment_config_hash": deployment_config_hash,
                "contracts": expected_contracts,
            },
            created_at_utc="2026-07-08T14:10:00Z",
        )
        self._run("git", "add", ".")
        self._run("git", "commit", "-q", "-m", f"publish deployment evidence {network}")
        commit = self._run("git", "rev-parse", "HEAD").stdout.strip()
        return {
            "binding_version": "p42-release-binding/v2",
            "repository_uri": REPOSITORY_URI,
            "deployment_commit": deployment_commit,
            "git_commit": commit,
            "network": network,
            "chain_id": chain_id,
            "canonical_topology": topology_artifact,
            "deployment_manifest": deployment_manifest,
            "configuration_artifact": configuration_artifact,
            "contracts": contracts,
        }

    def trust_registry(
        self,
        schema_version: str,
        signers: list[tuple[str, Mapping[str, Any], str]],
    ) -> dict[str, Any]:
        registrations = []
        for role, signer, _ in signers:
            identity_fields = {
                key: signer[key]
                for key in (
                    "name",
                    "organization",
                    "professional_email",
                    "bar_jurisdiction",
                    "license_identifier",
                    "address",
                )
                if key in signer
            }
            registrations.append(
                {
                    "attestation_class": schema_version,
                    "signer_role": role,
                    "identity": identity_fields,
                    "public_key": signer["public_key"],
                    "valid_from_utc": "2026-07-01T00:00:00Z",
                }
            )
        return {
            "schema_version": "p42-attestation-trust-registry/v1",
            "environment": "test",
            "registry_id": f"fixture-registry-{schema_version.replace('/', '-')}",
            "created_at_utc": "2026-07-01T00:00:00Z",
            "registrations": registrations,
        }

    def write_registry(self, registry: Mapping[str, Any]) -> Path:
        path = self.root / "test-trust-registry.json"
        path.write_text(canonical_json(registry), encoding="utf-8")
        return path

    def chain_reader(self, network: str, chain_id: int, address_value: str, block_number: int) -> dict[str, str]:
        del network
        return dict(self._chain_state[(chain_id, address_value.casefold(), block_number)])

    @contextmanager
    def chain_rpc_server(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                request = json.loads(self.rfile.read(length))
                method = request.get("method")
                params = request.get("params", [])
                result: Any
                if method == "eth_chainId":
                    result = hex(fixture._chain_id or 0)
                elif method == "eth_getBlockByNumber":
                    block_number = int(params[0], 16)
                    match = next(
                        (
                            state
                            for (chain_id, _, recorded_block), state in fixture._chain_state.items()
                            if chain_id == fixture._chain_id and recorded_block == block_number
                        ),
                        None,
                    )
                    result = {"hash": match["block_hash"]} if match else None
                elif method == "eth_getCode":
                    address_value = str(params[0]).casefold()
                    block_number = int(params[1], 16)
                    state = fixture._chain_state.get((fixture._chain_id or 0, address_value, block_number))
                    result = state["runtime_bytecode"] if state else "0x"
                else:
                    result = None
                body = json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                del format, args

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def _run(self, *command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            cwd=self.root,
            text=True,
            capture_output=True,
            check=True,
        )


def address(label: str) -> str:
    return "0x" + hashlib.sha256(("address:" + label).encode("utf-8")).hexdigest()[:40]


def attach_signatures(
    report: dict[str, Any],
    *,
    schema_version: str,
    hash_field: str,
    signatures_field: str,
    signers: list[tuple[str, Mapping[str, Any], str]],
    singular: bool = False,
) -> dict[str, Any]:
    unsigned = dict(report)
    unsigned.pop(hash_field, None)
    unsigned.pop(signatures_field, None)
    artifact_hash = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
    signatures = [
        _sign(identity_value, role, schema_version, artifact_hash, signed_at)
        for role, identity_value, signed_at in signers
    ]
    report[hash_field] = artifact_hash
    report[signatures_field] = signatures[0] if singular else signatures
    return report


def unsigned_hash(report: Mapping[str, Any], hash_field: str, signatures_field: str) -> str:
    unsigned = dict(report)
    unsigned.pop(hash_field, None)
    unsigned.pop(signatures_field, None)
    return sha256_bytes(canonical_json(unsigned).encode("utf-8"))


def _sign(
    identity_value: Mapping[str, Any],
    role: str,
    schema_version: str,
    artifact_hash: str,
    signed_at_utc: str,
) -> dict[str, str]:
    public_key = identity_value["public_key"]
    seed = _SIGNING_SEEDS[public_key]
    message = _attestation_message(
        schema_version,
        artifact_hash,
        role,
        signed_at_utc,
    )
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public_bytes = bytes.fromhex(public_key.removeprefix("ed25519:"))
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % _L
    encoded_r = _encode_point(_ed_scalar_mult(nonce, _BASE))
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public_bytes + message).digest(), "little") % _L
    scalar_s = (nonce + challenge * scalar) % _L
    return {
        "algorithm": "ed25519",
        "signer_role": role,
        "public_key": public_key,
        "signed_hash": artifact_hash,
        "signed_at_utc": signed_at_utc,
        "signature": "ed25519:" + (encoded_r + scalar_s.to_bytes(32, "little")).hex(),
    }


def _encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    inverse_z = pow(z, _Q - 2, _Q)
    affine_x = x * inverse_z % _Q
    affine_y = y * inverse_z % _Q
    encoded = affine_y | ((affine_x & 1) << 255)
    return encoded.to_bytes(32, "little")
