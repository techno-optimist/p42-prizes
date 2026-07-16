from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
import shutil
import subprocess
from typing import Any, Mapping

from p42_prizes.verdict import canonical_json


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "deployment-manifest-v2.schema.json").read_text())


def install_pinned_contract_build_inputs(target: Path) -> None:
    for relative in (
        Path(".gitignore"),
        Path("contracts/hardhat.config.js"),
        Path("contracts/package.json"),
        Path("contracts/package-lock.json"),
        Path("protocol/external-dependencies-v1.json"),
    ):
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    shutil.copytree(ROOT / "contracts/src", target / "contracts/src", dirs_exist_ok=True)


@lru_cache(maxsize=4)
def _production_capsule_json(git_commit: str) -> str:
    script = """
import { createReleaseCapsule } from './contracts/scripts/release-capsule-helper.js';
const capsule = await createReleaseCapsule({ contractsRoot: './contracts', gitCommit: process.argv[1] });
process.stdout.write(JSON.stringify(capsule));
"""
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", script, git_commit],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return completed.stdout


def production_capsule_template() -> dict[str, Any]:
    return json.loads(_production_capsule_json("1" * 40))


def production_capsule(git_commit: str) -> dict[str, Any]:
    return json.loads(_production_capsule_json(git_commit))


def _merge(left: Any, right: Any) -> Any:
    if not isinstance(left, Mapping) or not isinstance(right, Mapping):
        return right
    result = dict(left)
    for key, value in right.items():
        if key == "required":
            result[key] = list(dict.fromkeys([*result.get(key, []), *value]))
        elif key == "properties":
            prior = result.get(key, {})
            result[key] = {
                name: _merge(prior.get(name, {}), item)
                for name, item in {**prior, **value}.items()
            }
        else:
            result[key] = value
    return result


def _resolve(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if "$ref" not in value:
        return value
    target: Any = SCHEMA
    for part in value["$ref"][2:].split("/"):
        target = target[part]
    return _merge(target, {key: item for key, item in value.items() if key != "$ref"})


def _normalize(value: Mapping[str, Any]) -> Mapping[str, Any]:
    result = _resolve(value)
    for branch in result.get("allOf", []):
        branch = _normalize(branch)
        if "if" not in branch:
            result = _merge(result, branch)
    return result


def _string(value: Mapping[str, Any], index: int) -> str:
    pattern = value.get("pattern", "")
    if value.get("format") == "date-time":
        return "2026-07-08T14:00:00Z"
    if value.get("format") == "uri":
        return "https://projectforty2.ai/evidence"
    if pattern.startswith("^0x") and "{130}" in pattern:
        return "0x" + "ab" * 65
    if pattern.startswith("^0x") and "{40}" in pattern:
        return "0x" + f"{index + 1:040x}"
    if pattern.startswith("^0x") and "{64}" in pattern:
        return "0x" + f"{index + 1:064x}"
    if "sha256:" in pattern:
        return "sha256:" + f"{index + 1:064x}"
    if "[0-9a-f]{40}" in pattern:
        return f"{index + 1:040x}"
    if pattern.startswith("^0x"):
        return "0x" + "aa" * 4
    if pattern.startswith("^(?:ipfs|ar)"):
        return f"ipfs://fixture-{index + 1}"
    if pattern.startswith("^-?[0-9]"):
        return str(index)
    if pattern.startswith("^[1-9]"):
        return str(index + 1)
    if pattern == "^[0-9]+$":
        return str(index)
    if pattern.startswith("^[a-z0-9]"):
        return f"operator-{index + 1}"
    return "1.0.0" if "\\." in pattern else f"value-{index + 1}"


def sample(value: Mapping[str, Any], index: int = 0) -> Any:
    value = _normalize(value)
    if "const" in value:
        return value["const"]
    if "enum" in value:
        return value["enum"][0]
    if "oneOf" in value:
        return sample(value["oneOf"][0], index)
    kind = value.get("type")
    if isinstance(kind, list):
        kind = next(item for item in kind if item != "null")
    if kind == "object" or "properties" in value or "required" in value:
        return {
            key: sample(value.get("properties", {}).get(key, {}), index + offset)
            for offset, key in enumerate(value.get("required", []))
        }
    if kind == "array":
        return [sample(value.get("items", {}), index + offset) for offset in range(value.get("minItems", 0))]
    if kind in {"integer", "number"}:
        return max(index, value.get("minimum", 0))
    if kind == "boolean":
        return False
    if kind == "null":
        return None
    return _string(value, index)


def schema_valid_manifest_shell() -> dict[str, Any]:
    manifest = sample(SCHEMA)
    complete = SCHEMA["allOf"][0]["then"]["properties"]
    manifest["status"] = "governance-setup-complete"
    manifest["releaseMode"] = "production"
    manifest["deploymentCommit"] = "1" * 40
    manifest["releaseEvidence"] = sample(SCHEMA["properties"]["releaseEvidence"]["oneOf"][1])
    manifest["roleAcceptances"] = sample(SCHEMA["$defs"]["roleAcceptances"])
    manifest["roleAcceptances"]["deploymentCommit"] = "1" * 40
    for acceptance in manifest["roleAcceptances"]["acceptances"]:
        acceptance["signature"] = "0x" + "ab" * 65

    setup_schema = _merge(SCHEMA["$defs"]["setupOperation"], complete["setupTransactions"]["items"])
    manifest["setupTransactions"] = [sample(setup_schema, index) for index in range(11)]
    governance_schema = _merge(
        SCHEMA["properties"]["governanceSetup"],
        complete["governanceSetup"],
    )
    governance_schema = _merge(
        governance_schema,
        {
            "required": [
                "finalityAnchor", "acceptanceValidatedAt", "completionBlockTimestamp",
                "completionBlockHash", "completionBlockEvidence",
            ]
        },
    )
    manifest["governanceSetup"] = sample(governance_schema)
    manifest["governanceSetup"]["completedAt"] = "2026-07-08T14:00:00Z"
    manifest["governanceSetup"]["completionBlock"] = 100
    for index, operation in enumerate(manifest["setupTransactions"]):
        operation["executedOperationId"] = "0x" + f"{index + 1:064x}"
        operation["txHash"] = "0x" + f"{index + 101:064x}"
        operation["blockNumber"] = 100 + index

    complete_problem = complete["problems"]["items"]
    production_problem = SCHEMA["allOf"][4]["then"]["properties"]["problems"]["items"]
    problem_schema = _merge(_merge(SCHEMA["$defs"]["problem"], complete_problem), production_problem)
    manifest["problems"] = [sample(problem_schema, index * 100) for index in range(10)]
    for index, problem in enumerate(manifest["problems"], start=1):
        problem["problemId"] = str(index)
        problem["admissionMatrixURI"] = f"ipfs://fixture-{index}"
        problem["onchainDa"] = False
        problem["maxSolutionBytes"] = "0"
        problem["registerTxHash"] = "0x" + f"{index + 200:064x}"
        problem["registerBlockNumber"] = 200 + index
        factory_creation = sample(SCHEMA["$defs"]["contract"]["properties"]["factoryCreation"], index)
        problem["contracts"]["submissions"]["factoryCreation"] = factory_creation
        problem["contracts"]["challenges"]["factoryCreation"] = dict(factory_creation)

    manifest["governance"]["signers"] = ["0x" + f"{index + 1:040x}" for index in range(3)]
    manifest["sourceVerification"]["status"] = "verified"
    manifest["sourceVerification"]["dossierDigest"] = "sha256:" + "d" * 64
    for key in (
        "timelock", "registry", "rolloverVault", "submissionManagerFactory",
        "challengeManagerFactory", "objectiveVerifier", "resolverQuorum",
    ):
        manifest["sourceVerification"]["contracts"][key] = f"https://projectforty2.ai/source/{key}"
    board = SCHEMA["properties"]["sourceVerification"]["properties"]["contracts"]["properties"]["boards"]["items"]
    manifest["sourceVerification"]["contracts"]["boards"] = [sample(board, index) for index in range(10)]
    for index, item in enumerate(manifest["sourceVerification"]["contracts"]["boards"], start=1):
        item["problemId"] = str(index)
        for key in ("pool", "ledger", "submissions", "challenges"):
            item[key] = f"https://projectforty2.ai/source/{index}/{key}"
    return json.loads(canonical_json(manifest))
