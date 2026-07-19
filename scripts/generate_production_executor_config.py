#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from p42_prizes.production_runtime_config import (  # noqa: E402
    ProductionRuntimeConfigError, generate_production_executor_config, validate_production_executor_config,
)
from p42_prizes.secure_json import read_strict_json_file
from p42_prizes.verdict import canonical_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    if args.check:
        validate_production_executor_config(read_strict_json_file(args.check), ROOT)
        print("production executor exact-ten config verified")
    else:
        print(canonical_json(generate_production_executor_config(ROOT)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, ProductionRuntimeConfigError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
