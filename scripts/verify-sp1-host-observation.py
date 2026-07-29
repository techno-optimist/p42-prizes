#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys


STRICT_VERIFIER = Path(__file__).with_name("verify-sp1-objective-reproduction.py")
CANDIDATES = ("edges-vs-triangles", "q6-intersecting-hypergraph")


def load_strict_verifier():
    spec = importlib.util.spec_from_file_location("p42_strict_sp1_reproduction", STRICT_VERIFIER)
    if spec is None or spec.loader is None:
        raise SystemExit("SP1 host observation invalid: strict verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--program", choices=CANDIDATES, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--write-source-manifest", action="store_true")
    args = parser.parse_args()

    verifier = load_strict_verifier()
    expected = dict(verifier.PROGRAMS[args.program])
    expected["journal"] = None
    expected["instructions"] = None
    verifier.PROGRAMS[args.program] = expected

    delegated = [
        str(STRICT_VERIFIER),
        "--program",
        args.program,
        "--directory",
        str(args.directory),
    ]
    if args.write_source_manifest:
        delegated.append("--write-source-manifest")
    sys.argv = delegated
    verifier.main()
    print(f"SP1 untrusted native host observation verified: {args.program}")


if __name__ == "__main__":
    main()
