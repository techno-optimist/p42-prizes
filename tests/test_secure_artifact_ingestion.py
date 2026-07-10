from __future__ import annotations

from pathlib import Path

import pytest

from p42_prizes.admission import AdmissionError, load_evidence_file
from p42_prizes.runner_alerts import build_runner_alerts


AMBIGUOUS_JSON = (
    ('{"a":1,"a":2}\n', "duplicate object key"),
    ('{"a":1,"\\u0061":2}\n', "duplicate object key"),
    ('{"__proto__":1}\n', "forbidden object key"),
    ('{"n":9007199254740993}\n', "safe numeric range"),
    ("[" * 129 + "null" + "]" * 129 + "\n", "maxDepth"),
)


@pytest.mark.parametrize(("payload", "message"), AMBIGUOUS_JSON)
def test_admission_file_loader_rejects_ambiguous_json(
    tmp_path: Path,
    payload: str,
    message: str,
) -> None:
    path = tmp_path / "evidence.json"
    path.write_text(payload, encoding="utf-8")

    with pytest.raises(AdmissionError, match=message):
        load_evidence_file(path)


def test_admission_file_loader_is_bounded_and_rejects_symlinks(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(AdmissionError, match="maxBytes"):
        load_evidence_file(oversized)

    target = tmp_path / "target.json"
    target.write_text('{"ok":true}', encoding="utf-8")
    link = tmp_path / "evidence-link.json"
    link.symlink_to(target)
    with pytest.raises(AdmissionError, match="could not read evidence JSON"):
        load_evidence_file(link)


def test_admission_file_loader_preserves_noncanonical_user_config(tmp_path: Path) -> None:
    path = tmp_path / "trust-registry.json"
    path.write_text('{ "trusted" : true }', encoding="utf-8")

    assert load_evidence_file(path) == {"trusted": True}


@pytest.mark.parametrize(("payload", "message"), AMBIGUOUS_JSON)
def test_runner_alerts_quarantine_ambiguous_transcript_json(
    tmp_path: Path,
    payload: str,
    message: str,
) -> None:
    path = tmp_path / "transcript.json"
    path.write_text(payload, encoding="utf-8")

    result = build_runner_alerts([path], now_utc="2026-07-10T00:00:00Z")

    assert result["alerts"][0]["category"] == "transcript_malformed"
    assert message in result["alerts"][0]["reason"]


def test_runner_alerts_require_canonical_exactly_one_lf(tmp_path: Path) -> None:
    for index, payload in enumerate(("{}", "{}\n\n", "{ }\n")):
        path = tmp_path / f"transcript-{index}.json"
        path.write_text(payload, encoding="utf-8")
        result = build_runner_alerts([path], now_utc="2026-07-10T00:00:00Z")
        assert result["alerts"][0]["category"] == "transcript_malformed"


def test_runner_alerts_reject_oversized_and_symlink_transcripts(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (1024 * 1024 + 1))
    target = tmp_path / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    link = tmp_path / "transcript-link.json"
    link.symlink_to(target)

    result = build_runner_alerts(
        [oversized, link],
        now_utc="2026-07-10T00:00:00Z",
    )

    assert result["alert_count"] == 2
    assert all(alert["category"] == "transcript_malformed" for alert in result["alerts"])
    assert any("maxBytes" in alert["reason"] for alert in result["alerts"])
