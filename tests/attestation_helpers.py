from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import subprocess
import threading
from typing import Any, Mapping

from legal_release_fixture import (
    install_pinned_contract_build_inputs,
    schema_valid_manifest_shell,
)
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
PRODUCTION_CONTRACT_NAMES = [
    "P42MultisigTimelock", "P42ChallengeManagerFactory", "P42SubmissionManagerFactory",
    "P42RolloverVault", "P42SP1VerifierGateway", "P42ResolverQuorum", "P42BountyPool",
    "P42PayoutLedger", "P42SubmissionManager", "P42ChallengeManager", "P42ProblemRegistry",
]
IMMUTABLES = {
    "P42MultisigTimelock": ["delay", "overrideDelay", "operationGracePeriod"],
    "P42ChallengeManagerFactory": [], "P42SubmissionManagerFactory": [],
    "P42RolloverVault": [], "P42SP1VerifierGateway": [],
    "P42ResolverQuorum": ["owner", "expectedTreasury", "expectedDecisionBondWei", "managerFactory", "objectiveVerifier", "objectiveVerifierCodehash"],
    "P42BountyPool": ["owner", "fundingCap"],
    "P42PayoutLedger": ["owner", "pool", "treasury", "feeBps", "earliestCloseTimestamp", "closeByTimestamp"],
    "P42SubmissionManager": ["owner", "treasury", "fundingAuthorizer", "boardSetDigest", "releaseBindingDigest", "productionLaunchAuthority", "independentSecurityAuthority", "governanceAuthority", "pool", "ledger", "alphaBps", "minPostingBondWei", "challengeWindowSeconds", "deployedAt", "armNotBefore", "onchainDa", "maxSolutionBytes", "seedScoreAtoms", "minImprovementAtoms"],
    "P42ChallengeManager": ["owner", "resolver", "treasury", "submissionManager", "challengeWindowSeconds", "betaBps", "rerunCostMultiplierBps", "minCounterBondWei", "rerunCostWei", "resolverDecisionBondWei", "resolverFraudWindowSeconds"],
    "P42ProblemRegistry": ["owner"],
}
ADDRESS_IMMUTABLES = {"owner", "expectedTreasury", "managerFactory", "objectiveVerifier", "pool", "treasury", "fundingAuthorizer", "productionLaunchAuthority", "independentSecurityAuthority", "governanceAuthority", "ledger", "resolver", "submissionManager"}
BYTES32_IMMUTABLES = {"objectiveVerifierCodehash", "boardSetDigest", "releaseBindingDigest"}

_SIGNING_SEEDS: dict[str, bytes] = {}


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _immutable_type(name: str) -> str:
    if name in ADDRESS_IMMUTABLES:
        return "address"
    if name in BYTES32_IMMUTABLES:
        return "bytes32"
    if name == "onchainDa":
        return "bool"
    return "uint256"


def _constructor_abi(name: str) -> list[dict[str, Any]]:
    if name == "P42MultisigTimelock":
        inputs = [
            {"name": "signers_", "type": "address[]"},
            {"name": "threshold_", "type": "uint256"},
            {"name": "delaySeconds_", "type": "uint256"},
            {"name": "guardian_", "type": "address"},
        ]
    elif name == "P42RolloverVault":
        inputs = [
            {"name": "registry_", "type": "address"},
            {"name": "owner_", "type": "address"},
        ]
    elif name == "P42ResolverQuorum":
        inputs = [
            {"name": "owner_", "type": "address"},
            {"name": "expectedTreasury_", "type": "address"},
            {"name": "expectedDecisionBondWei_", "type": "uint256"},
            {"name": "managerFactory_", "type": "address"},
            {"name": "signers_", "type": "address[]"},
            {"name": "threshold_", "type": "uint256"},
            {"name": "allowedManagers_", "type": "address[]"},
            {"name": "objectiveVerifier_", "type": "address"},
            {"name": "objectiveVerifierCodehash_", "type": "bytes32"},
        ]
    elif name == "P42PayoutLedger":
        inputs = [
            {"name": "pool_", "type": "address"},
            {"name": "owner_", "type": "address"},
            {"name": "treasury_", "type": "address"},
            {"name": "feeBps_", "type": "uint256"},
            {"name": "earliestCloseTimestamp_", "type": "uint256"},
            {"name": "closeByTimestamp_", "type": "uint256"},
        ]
    elif name == "P42SubmissionManager":
        deployment = [
            "pool", "ledger", "owner", "treasury", "alphaBps", "minPostingBondWei",
            "challengeWindowSeconds", "onchainDa", "maxSolutionBytes", "seedScoreAtoms",
            "minImprovementAtoms",
        ]
        funding = [
            "boardSetDigest", "releaseBindingDigest", "productionLaunchAuthority",
            "independentSecurityAuthority", "governanceAuthority",
        ]
        inputs = [
            {"name": "deployment", "type": "tuple", "components": [{"name": item, "type": _immutable_type(item)} for item in deployment]},
            {"name": "funding", "type": "tuple", "components": [{"name": item, "type": _immutable_type(item)} for item in funding]},
        ]
    else:
        inputs = [{"name": f"{item}_", "type": _immutable_type(item)} for item in IMMUTABLES[name]]
    return [{"type": "constructor", "inputs": inputs, "stateMutability": "nonpayable"}]


def _synthetic_capsule(git_commit: str) -> tuple[dict[str, Any], dict[str, str]]:
    contracts = []
    build_infos = []
    sources: dict[str, str] = {}
    for contract_index, name in enumerate(PRODUCTION_CONTRACT_NAMES):
        source_name = f"src/{name}.sol"
        input_source_name = f"project/{source_name}"
        source = f"// canonical test source for {name}\ncontract {name} {{}}\n"
        sources[name] = source
        bindings = []
        references: dict[str, list[dict[str, int]]] = {}
        nodes = []
        for immutable_index, immutable in enumerate(IMMUTABLES[name]):
            ast_id = str(1000 + contract_index * 100 + immutable_index)
            immutable_type = _immutable_type(immutable)
            ranges = [{"start": immutable_index * 32, "length": 32}]
            references[ast_id] = ranges
            bindings.append({"astId": ast_id, "name": immutable, "type": immutable_type, "ranges": ranges})
            nodes.append({"nodeType": "VariableDeclaration", "id": int(ast_id), "name": immutable, "stateVariable": True, "mutability": "immutable", "typeDescriptions": {"typeString": immutable_type}})
        runtime = "0x" + "00" * max(1, 32 * len(bindings))
        abi = _constructor_abi(name)
        build_id = hashlib.sha256(name.encode()).hexdigest()
        settings = {"optimizer": {"enabled": True, "runs": 200}, "evmVersion": "shanghai"}
        build_input = {"id": build_id, "solcVersion": "0.8.24", "solcLongVersion": "0.8.24+commit.e11b9ed9", "input": {"settings": settings, "sources": {input_source_name: {"content": source}}}}
        compiled = {"abi": abi, "evm": {"bytecode": {"object": "6000", "linkReferences": {}}, "deployedBytecode": {"object": runtime[2:], "linkReferences": {}, "immutableReferences": references}}}
        build_output = {"id": build_id, "output": {"sources": {input_source_name: {"ast": {"nodeType": "SourceUnit", "nodes": [{"nodeType": "ContractDefinition", "name": name, "nodes": nodes}]}}}, "contracts": {input_source_name: {name: compiled}}}}
        artifact = {"_format": "hh3-artifact-1", "contractName": name, "sourceName": source_name, "abi": abi, "bytecode": "0x6000", "deployedBytecode": runtime, "linkReferences": {}, "deployedLinkReferences": {}, "immutableReferences": references, "inputSourceName": input_source_name, "buildInfoId": build_id}
        contracts.append({"name": name, "sourceName": source_name, "buildInfoId": build_id, "artifactDigest": _digest(artifact), "abi": abi, "creationCode": "0x6000", "runtimeTemplate": runtime, "immutableReferences": references, "immutableBindings": bindings, "linkReferences": {}, "deployedLinkReferences": {}})
        build_infos.append({"id": build_id, "inputDigest": _digest(build_input), "outputDigest": _digest(build_output), "compiler": {"version": "0.8.24", "longVersion": "0.8.24+commit.e11b9ed9"}, "settings": settings, "input": build_input, "output": build_output})
    external = json.loads((Path(__file__).resolve().parents[1] / "protocol" / "external-dependencies-v1.json").read_text())["dependencies"]
    sp1_runtime_attestation = {
        "schema": "p42-prizes/sp1-external-runtime-attestation/v1",
        "evidenceDigest": "sha256:" + "e" * 64,
        "capturedAt": "2026-07-17T15:12:28Z",
        "expiresAt": "2026-07-18T15:12:28Z",
        "chains": [
            {
                "chainId": chain_id,
                "network": network,
                "address": "0xb69f2584cbcff99a58c4e7002e8b89af54a6f4e2",
                "anchorMode": "agreed-finalized",
                "finalizedSkewBlocks": 0,
                "providers": [
                    {"operator": "base-foundation", "endpointOrigin": "https://mainnet.base.org" if chain_id == 8453 else "https://sepolia.base.org", "finalizedAnchor": {"blockNumber": 1, "blockHash": "0x" + "1" * 64, "blockTimestamp": 1}},
                    {"operator": "tenderly", "endpointOrigin": "https://base.gateway.tenderly.co" if chain_id == 8453 else "https://base-sepolia.gateway.tenderly.co", "finalizedAnchor": {"blockNumber": 1, "blockHash": "0x" + "1" * 64, "blockTimestamp": 1}},
                ],
                "runtime": {"byteLength": 6741, "keccak256": "0xcceb864cd8a5a36b2073a8f2b32a773835cd2dd2c78a56f8e6fdb942feff04dd"},
            }
            for chain_id, network in [(8453, "base"), (84532, "base-sepolia")]
        ],
    }
    body = {"schema": "p42-prizes/release-capsule/v2", "gitCommit": git_commit, "contracts": contracts, "externalDependencies": external, "sp1RuntimeAttestation": sp1_runtime_attestation, "buildInfos": sorted(build_infos, key=lambda item: item["id"])}
    return {**body, "capsuleDigest": _digest(body)}, sources


def _default_value(kind: str) -> Any:
    if kind == "address":
        return "0x" + "01" * 20
    if kind == "bytes32":
        return "0x" + "02" * 32
    if kind == "bool":
        return False
    return "1"


def _constructor_args(name: str, manifest: Mapping[str, Any], problem: Mapping[str, Any] | None) -> list[Any]:
    if name == "P42MultisigTimelock":
        return [
            manifest["governance"]["signers"],
            manifest["governance"]["threshold"],
            manifest["governance"]["delaySeconds"],
            manifest["roles"]["guardian"],
        ]
    if name == "P42RolloverVault":
        return [manifest["contracts"]["registry"]["address"], manifest["roles"]["owner"]]
    if name == "P42ResolverQuorum":
        return [
            manifest["roles"]["owner"],
            manifest["roles"]["treasury"],
            "1",
            manifest["contracts"]["submissionManagerFactory"]["address"],
            manifest["governance"]["signers"],
            manifest["governance"]["threshold"],
            [item["contracts"]["submissions"]["address"] for item in manifest["problems"]],
            manifest["contracts"]["objectiveVerifier"]["address"],
            manifest["contracts"]["objectiveVerifier"]["runtimeCodeHash"],
        ]
    if name == "P42BountyPool":
        return [manifest["roles"]["owner"], "1"]
    if name == "P42PayoutLedger":
        assert problem is not None
        return [
            problem["contracts"]["pool"]["address"],
            manifest["roles"]["owner"],
            manifest["roles"]["treasury"],
            "1",
            "1800000000",
            "1800000001",
        ]
    if name == "P42SubmissionManager":
        assert problem is not None
        return [[problem["contracts"]["pool"]["address"], problem["contracts"]["ledger"]["address"], manifest["roles"]["owner"], manifest["roles"]["treasury"], "1", "1", "1", False, "0", "1", "1"], ["0x" + manifest["releaseEvidence"]["boardSetDigest"][7:], "0x" + manifest["releaseEvidence"]["releaseBindingDigest"][7:], manifest["roles"]["productionLaunchAuthority"], manifest["roles"]["independentSecurityAuthority"], manifest["roles"]["governanceAuthority"]]]
    if name == "P42ChallengeManager":
        assert problem is not None
        return [
            manifest["roles"]["owner"],
            manifest["roles"]["resolver"],
            manifest["roles"]["treasury"],
            problem["contracts"]["submissions"]["address"],
            "1", "1", "1", "1", "1", "1", "1",
        ]
    if name == "P42ProblemRegistry":
        return [manifest["roles"]["owner"]]
    return []


def _runtime(contract: Mapping[str, Any], args: list[Any], timestamp: int) -> bytes:
    name = str(contract["name"])
    names = IMMUTABLES[name]
    constructor = next((item for item in contract["abi"] if item.get("type") == "constructor"), {"inputs": []})
    values = {
        item["name"].removesuffix("_"): args[index]
        for index, item in enumerate(constructor["inputs"])
        if item["name"].removesuffix("_") in names
    }
    if name == "P42MultisigTimelock":
        delay = int(args[2])
        values = {"delay": delay, "overrideDelay": delay * 2, "operationGracePeriod": 7 * 24 * 60 * 60}
    elif name == "P42SubmissionManager":
        deployment, funding = args
        values = dict(zip(["pool", "ledger", "owner", "treasury", "alphaBps", "minPostingBondWei", "challengeWindowSeconds", "onchainDa", "maxSolutionBytes", "seedScoreAtoms", "minImprovementAtoms"], deployment))
        values.update(zip(["boardSetDigest", "releaseBindingDigest", "productionLaunchAuthority", "independentSecurityAuthority", "governanceAuthority"], funding))
        values.update(deployedAt=timestamp, armNotBefore=timestamp + int(values["challengeWindowSeconds"]), fundingAuthorizer=values["treasury"])
    runtime = bytearray.fromhex(str(contract["runtimeTemplate"])[2:])
    for binding in contract["immutableBindings"]:
        value = values[binding["name"]]
        integer = int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)
        for byte_range in binding["ranges"]:
            length = int(byte_range["length"])
            if integer < 0:
                integer = (1 << (length * 8)) + integer
            start = int(byte_range["start"])
            runtime[start:start + length] = integer.to_bytes(length, "big")
    return bytes(runtime)


def _deep_update(target: dict[str, Any], override: Mapping[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = value


class AttestationFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._artifacts: dict[str, dict[str, str]] = {}
        self._chain_id: int | None = None
        self._chain_state: dict[tuple[int, str, int], dict[str, Any]] = {}
        self._capsule_authority_signer: dict[str, Any] | None = None
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
        # Freeze the complete pinned build input set before publishing the
        # capsule that names this exact deployment commit.
        install_pinned_contract_build_inputs(self.root)
        template, _ = _synthetic_capsule("1" * 40)
        template_by_name = {item["name"]: item for item in template["contracts"]}
        template_build_infos = {item["id"]: item for item in template["buildInfos"]}
        for name in PRODUCTION_CONTRACT_NAMES:
            contract = template_by_name[name]
            build_info = template_build_infos[contract["buildInfoId"]]
            source = build_info["input"]["input"]["sources"][f"project/{contract['sourceName']}"]["content"]
            self.artifact(
                f"canonical-{network}-source-{name}",
                content=source,
                created_at_utc="2026-07-08T13:30:00Z",
                suffix=".sol",
            )
        self._run("git", "add", ".")
        self._run("git", "commit", "-q", "-m", f"freeze canonical topology {network}")
        deployment_commit = self._run("git", "rev-parse", "HEAD").stdout.strip()
        capsule, _ = _synthetic_capsule(deployment_commit)
        capsule_build_infos = {item["id"]: item for item in capsule["buildInfos"]}
        sources = {
            item["name"]: capsule_build_infos[item["buildInfoId"]]["input"]["input"]["sources"]
            [f"project/{item['sourceName']}"]["content"]
            for item in capsule["contracts"]
        }
        capsule_by_name = {item["name"]: item for item in capsule["contracts"]}
        deployment = schema_valid_manifest_shell()
        deployment["deploymentCommit"] = deployment_commit
        deployment["roleAcceptances"]["deploymentCommit"] = deployment_commit
        deployment["network"] = {"name": "baseSepolia", "chainId": 84532, "explorerBaseUrl": "https://sepolia.basescan.org"}
        deployment["releaseEvidence"]["capsuleDigest"] = capsule["capsuleDigest"]
        deployment_config_hash = "0x" + hashlib.sha256(f"deployment-config:{network}:{deployment_commit}".encode()).hexdigest()
        deployment["deploymentConfigHash"] = deployment_config_hash

        contracts: list[dict[str, Any]] = []
        manifest_contracts: dict[str, dict[str, Any]] = {}
        for index, (topology_key, name) in enumerate(slots):
            contract_address = address(f"{network}-{topology_key}-{name}")
            problem = deployment["problems"][int(topology_key.split(".")[1]) - 1] if topology_key.startswith("board.") else None
            args = _constructor_args(name, deployment, problem)
            timestamp = 1_800_000_000 + index
            runtime_bytes = _runtime(capsule_by_name[name], args, timestamp)
            runtime_hash = "sha256:" + hashlib.sha256(runtime_bytes).hexdigest()
            manifest_runtime_hash = ethereum_keccak256(runtime_bytes)
            runtime_artifact = self.artifact(f"canonical-{network}-runtime-{topology_key}", content="0x" + runtime_bytes.hex(), created_at_utc="2026-07-08T14:00:00Z", suffix=".hex")
            source_artifact = self.artifact(f"canonical-{network}-source-{name}", content=sources[name], created_at_utc="2026-07-08T13:30:00Z", suffix=".sol")
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
            entry = (deployment["contracts"][topology_key.split(".")[1]] if topology_key.startswith("shared.") else deployment["problems"][int(topology_key.split(".")[1]) - 1]["contracts"][topology_key.split(".")[2]])
            entry.update(name=name, address=contract_address, constructorArgs=args, deploymentBlockTimestamp=timestamp, capsuleArtifactDigest=capsule_by_name[name]["artifactDigest"], runtimeCodeHash=manifest_runtime_hash, deployedCodeHash=manifest_runtime_hash, expectedRuntimeCodeHash=manifest_runtime_hash, primaryObservedRuntimeCodeHash=manifest_runtime_hash, secondaryObservedRuntimeCodeHash=manifest_runtime_hash)
            if "factoryCreation" in entry:
                entry["factoryCreation"]["createdAddress"] = contract_address
            manifest_contracts[topology_key] = entry

        for board, problem in enumerate(deployment["problems"], start=1):
            problem.update(pool=problem["contracts"]["pool"]["address"], ledger=problem["contracts"]["ledger"]["address"], submissionManager=problem["contracts"]["submissions"]["address"], challengeManager=problem["contracts"]["challenges"]["address"])
            _deep_update(problem, (problem_overrides or {}).get(str(board), {}))
        capsule_artifact = self.artifact(
            f"canonical-{network}-release-capsule",
            content=json.dumps(capsule, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            created_at_utc="2026-07-08T14:10:00Z",
        )
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
        object_ids = sorted(
            set(
                self._run("git", "rev-list", "--objects", "--no-object-names", commit)
                .stdout.strip()
                .splitlines()
            )
        )
        closure_bytes = ("\n".join(object_ids) + "\n").encode("ascii")
        authority_signer = self.identity(
            "capsule-build-authority",
            "Morgan Vale",
            "capsule-build-authority",
            organization="Independent Reproducible Build Lab",
        )
        self._capsule_authority_signer = authority_signer
        authority = {
            key: authority_signer[key]
            for key in ("name", "organization", "professional_email", "public_key")
        }
        capsule_bytes = (self.root / capsule_artifact["local_path"]).read_bytes()
        rebuild_attestation = {
            "schema_version": "p42-capsule-rebuild-attestation/v1",
            "attestation_id": f"capsule-rebuild-{deployment_commit[:16]}",
            "generated_at_utc": "2026-07-08T14:20:00Z",
            "repository": {
                "canonical_uri": REPOSITORY_URI,
                "deployment_commit": deployment_commit,
                "evidence_commit": commit,
                "object_format": "sha1",
                "ancestry": "deployment-ancestor-of-evidence",
                "object_closure_algorithm": "git-rev-list-object-ids+sha256/v1",
                "object_closure_digest": "sha256:" + hashlib.sha256(closure_bytes).hexdigest(),
                "object_count": len(object_ids),
            },
            "capsule": {
                "bytes_sha256": "sha256:" + hashlib.sha256(capsule_bytes).hexdigest(),
                "capsule_digest": capsule["capsuleDigest"],
                "git_commit": deployment_commit,
            },
            "build": {
                "build_info_digests": [
                    {
                        "id": item["id"],
                        "input_digest": item["inputDigest"],
                        "output_digest": item["outputDigest"],
                    }
                    for item in capsule["buildInfos"]
                ],
                "contract_artifact_digests": [
                    {"name": item["name"], "artifact_digest": item["artifactDigest"]}
                    for item in capsule["contracts"]
                ],
                "toolchain_image_digest": "sha256:"
                + hashlib.sha256(b"p42-test-toolchain-image:v1").hexdigest(),
                "policy": {
                    "network_access": "denied",
                    "root_filesystem": "read-only",
                    "source_mount": "read-only",
                    "dependency_mount": "read-only",
                    "output_mount": "isolated-write-only",
                    "privileges": "none",
                    "legal_validator_execution": "forbidden",
                },
            },
            "authority": authority,
        }
        attach_signatures(
            rebuild_attestation,
            schema_version="p42-capsule-rebuild-attestation/v1",
            hash_field="attestation_hash",
            signatures_field="signature",
            signers=[
                ("capsule-build-authority", authority_signer, rebuild_attestation["generated_at_utc"])
            ],
            singular=True,
        )
        rebuild_attestation_artifact = self.artifact(
            f"canonical-{network}-capsule-rebuild-attestation",
            content=rebuild_attestation,
            created_at_utc=rebuild_attestation["generated_at_utc"],
        )
        return {
            "binding_version": "p42-release-binding/v2",
            "repository_uri": REPOSITORY_URI,
            "deployment_commit": deployment_commit,
            "git_commit": commit,
            "network": network,
            "chain_id": chain_id,
            "canonical_topology": topology_artifact,
            "release_capsule": capsule_artifact,
            "capsule_rebuild_attestation": rebuild_attestation_artifact,
            "deployment_manifest": deployment_manifest,
            "configuration_artifact": configuration_artifact,
            "contracts": contracts,
        }

    def trust_registry(
        self,
        schema_version: str,
        signers: list[tuple[str, Mapping[str, Any], str]],
        *,
        include_capsule_authority: bool = True,
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
        if include_capsule_authority and self._capsule_authority_signer is not None:
            signer = self._capsule_authority_signer
            registrations.append(
                {
                    "attestation_class": "p42-capsule-rebuild-attestation/v1",
                    "signer_role": "capsule-build-authority",
                    "identity": {
                        key: signer[key]
                        for key in ("name", "organization", "professional_email")
                    },
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

    def write_governance_rpc_policy(
        self,
        rpc_urls: list[str],
        *,
        network: str = "base-sepolia",
        chain_id: int = 84532,
        quorum: int = 2,
        ownership_groups: list[str] | None = None,
        max_head_lag_blocks: int = 8,
        max_finalized_lag_blocks: int = 64,
    ) -> tuple[Path, Path]:
        groups = ownership_groups or [
            f"test-operator-{index + 1}" for index in range(len(rpc_urls))
        ]
        policy = {
            "schema_version": "p42-governance-rpc-policy/v2",
            "environment": "test",
            "network": network,
            "chain_id": chain_id,
            "rpc_quorum": quorum,
            "max_head_lag_blocks": max_head_lag_blocks,
            "max_finalized_lag_blocks": max_finalized_lag_blocks,
            "rpc_endpoints": [
                {
                    "provider_id": f"test-provider-{index + 1}",
                    "ownership_group": groups[index],
                    "url": url,
                }
                for index, url in enumerate(rpc_urls)
            ],
        }
        policy_path = self.root / "governance-rpc-policy.json"
        policy_path.write_text(canonical_json(policy), encoding="utf-8")
        digest_path = self.root / "governance-rpc-policy.sha256"
        digest_path.write_text(
            sha256_bytes(canonical_json(policy).encode("utf-8")) + "\n", encoding="ascii"
        )
        return policy_path, digest_path

    def record_governance_state(
        self,
        *,
        chain_id: int,
        address_value: str,
        block_number: int,
        block_hash: str,
        runtime_bytecode: str,
        governance_state: Mapping[str, Any],
    ) -> None:
        self._chain_state[(chain_id, address_value.casefold(), block_number)] = {
            "block_hash": block_hash,
            "runtime_bytecode": runtime_bytecode,
            "governance_state": dict(governance_state),
        }

    def chain_reader(self, network: str, chain_id: int, address_value: str, block_number: int) -> dict[str, Any]:
        del network
        return dict(self._chain_state[(chain_id, address_value.casefold(), block_number)])

    @contextmanager
    def chain_rpc_server(
        self,
        *,
        finalized_block_number: int | None = None,
        finalized_block_hash: str | None = None,
        head_block_number: int | None = None,
        head_block_hash: str | None = None,
        governance_state_overrides: Mapping[str, Any] | None = None,
        live_governance_state_overrides: Mapping[str, Any] | None = None,
    ):
        fixture = self

        recorded_numbers = [
            block_number for chain_id, _address, block_number in self._chain_state
            if chain_id == (self._chain_id or 0)
        ]
        default_tip = max(recorded_numbers, default=0)
        finalized_number = finalized_block_number if finalized_block_number is not None else default_tip
        head_number = head_block_number if head_block_number is not None else max(finalized_number, default_tip)

        def recorded_hash(block_number: int) -> str | None:
            match = next(
                (
                    state
                    for (chain_id, _address, recorded_block), state in fixture._chain_state.items()
                    if chain_id == fixture._chain_id and recorded_block == block_number
                ),
                None,
            )
            return str(match["block_hash"]) if match else None

        final_hash = finalized_block_hash or recorded_hash(finalized_number) or (
            "0x" + hashlib.sha256(f"fixture-finalized:{finalized_number}".encode()).hexdigest()
        )
        latest_hash = head_block_hash or (
            final_hash
            if head_number == finalized_number
            else recorded_hash(head_number)
            or "0x" + hashlib.sha256(f"fixture-head:{head_number}".encode()).hexdigest()
        )

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
                    tag = params[0]
                    if tag == "finalized":
                        block_number, block_hash = finalized_number, final_hash
                    elif tag == "latest":
                        block_number, block_hash = head_number, latest_hash
                    else:
                        block_number = int(tag, 16)
                        block_hash = recorded_hash(block_number)
                        if block_number == finalized_number:
                            block_hash = final_hash
                        if block_number == head_number:
                            block_hash = latest_hash
                    result = (
                        {"number": hex(block_number), "hash": block_hash}
                        if block_hash is not None
                        else None
                    )
                elif method == "eth_getCode":
                    address_value = str(params[0]).casefold()
                    block_number = int(params[1], 16)
                    state = fixture._chain_state.get((fixture._chain_id or 0, address_value, block_number))
                    result = state["runtime_bytecode"] if state else "0x"
                elif method == "eth_call":
                    call = params[0] if params and isinstance(params[0], dict) else {}
                    address_value = str(call.get("to", "")).casefold()
                    data = str(call.get("data", ""))
                    block_number = int(params[1], 16)
                    state = fixture._chain_state.get((fixture._chain_id or 0, address_value, block_number))
                    governance = state.get("governance_state") if state else None
                    if governance is None:
                        governance = next(
                            (
                                item.get("governance_state")
                                for (chain_id, recorded_address, _), item in fixture._chain_state.items()
                                if chain_id == fixture._chain_id
                                and recorded_address == address_value
                                and isinstance(item.get("governance_state"), Mapping)
                            ),
                            None,
                        )
                    if isinstance(governance, Mapping):
                        governance = dict(governance)
                        governance.update(governance_state_overrides or {})
                        if block_number == finalized_number:
                            governance.update(live_governance_state_overrides or {})
                    selectors = {
                        ethereum_keccak256(signature.encode("ascii"))[:10]: signature
                        for signature in (
                            "signerCount()",
                            "signers(uint256)",
                            "threshold()",
                            "delay()",
                            "guardian()",
                            "governanceEpoch()",
                        )
                    }
                    signature = selectors.get(data[:10])
                    value: Any = None
                    if isinstance(governance, Mapping):
                        if signature == "signerCount()":
                            value = governance.get("signer_count")
                        elif signature == "signers(uint256)":
                            index = int(data[10:] or "0", 16)
                            signers = governance.get("signers")
                            value = signers[index] if isinstance(signers, list) and index < len(signers) else None
                        elif signature == "threshold()":
                            value = governance.get("threshold")
                        elif signature == "delay()":
                            value = governance.get("delay_seconds")
                        elif signature == "guardian()":
                            value = governance.get("guardian")
                        elif signature == "governanceEpoch()":
                            value = governance.get("governance_epoch")
                    if isinstance(value, int) and not isinstance(value, bool):
                        result = "0x" + value.to_bytes(32, "big").hex()
                    elif isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
                        result = "0x" + bytes.fromhex(value[2:]).rjust(32, b"\x00").hex()
                    else:
                        result = None
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
        env = dict(os.environ)
        if command and command[0] == "git" and "commit" in command:
            env["GIT_AUTHOR_DATE"] = "2026-07-08T12:00:00Z"
            env["GIT_COMMITTER_DATE"] = "2026-07-08T12:00:00Z"
        return subprocess.run(
            command,
            cwd=self.root,
            env=env,
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
