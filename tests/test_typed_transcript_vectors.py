from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "protocol" / "typed-transcript" / "validate_vectors.py"


def test_typed_transcript_structural_contract_executes_in_ci() -> None:
    result = subprocess.run(
        [sys.executable, str(VALIDATOR)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "TypedTranscriptV1 structural transcripts: valid "
        "(no cryptographic closure asserted)"
    )
