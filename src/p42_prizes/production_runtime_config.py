"""Deterministic production executor configuration from reviewed protocol inputs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .admission import compute_source_hash
from .problem import load_manifest
from .verdict import canonical_json


class ProductionRuntimeConfigError(ValueError):
    pass


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def generate_production_executor_config(root: Path) -> dict[str, Any]:
    root = root.resolve()
    board_set_path = root / "protocol/production-board-set-v1.json"
    bindings_path = root / "protocol/production-board-bindings-v1.json"
    projection_path = root / "scripts/release-guard-problems-v1.json"
    board_set = _load(board_set_path)
    bindings = _load(bindings_path)
    projection = _load(projection_path)
    slugs = board_set.get("boards")
    records = bindings.get("records")
    projected = projection.get("boards")
    if (
        not isinstance(slugs, list) or len(slugs) != 10 or len(set(slugs)) != 10
        or not isinstance(records, list) or [record.get("slug") for record in records] != slugs
        or not isinstance(projected, list) or [board.get("slug") for board in projected] != slugs
    ):
        raise ProductionRuntimeConfigError("production executor inputs are not the ordered exact-ten board set")
    boards = []
    for slug, record, public in zip(slugs, records, projected, strict=True):
        manifest = load_manifest(root / "problems" / slug)
        verifier = manifest["verifier"]
        resource = verifier["max_compute"]
        source_hash = compute_source_hash(root / "problems" / slug)
        if source_hash != record["verifier"]["source_tree_sha256"]:
            raise ProductionRuntimeConfigError(f"{slug} source identity differs from production bindings")
        board_number = public.get("id")
        if not isinstance(board_number, int) or board_number < 1:
            raise ProductionRuntimeConfigError(f"{slug} has no canonical registry problem id")
        base = f"/var/lib/p42/verifier-executor/boards/{board_number}"
        boards.append({
            "alerts": f"{base}/ALERTS.log",
            "board_id": f"84532:{board_number}:{slug}",
            "deadline_seconds": int(resource["wall_seconds"]) + 60,
            "identity": {
                "slug": slug,
                "verifier_command": verifier["command"],
                "verifier_image": verifier["image"],
                "verifier_source_sha256": source_hash,
                "verifier_version": verifier["version"],
                "wall_seconds": int(resource["wall_seconds"]),
                "memory_mb": int(resource["memory_mb"]),
            },
            "queue": f"{base}/runner-queue.json",
            # The host-global cgroup policy deliberately allocates one uniform
            # 4 GiB slot while identity records the verifier's exact reviewed cap.
            "required_memory_mb": 4096,
            "staging": f"{base}/sandbox-staging",
            "transcripts": f"{base}/transcripts",
        })
    return {
        "schema_version": "p42-verifier-executor-config/v2",
        "board_set": {"path": "protocol/production-board-set-v1.json", "sha256": _sha256(board_set_path)},
        "board_bindings": {"path": "protocol/production-board-bindings-v1.json", "sha256": _sha256(bindings_path)},
        "boards": boards,
    }


def validate_production_executor_config(value: Mapping[str, Any], root: Path) -> None:
    expected = generate_production_executor_config(root)
    if canonical_json(value) != canonical_json(expected):
        raise ProductionRuntimeConfigError(
            "executor config differs from the ordered exact-ten production identity projection"
        )
