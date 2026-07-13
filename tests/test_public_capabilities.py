from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


SHIPPED_ASSET_CLAIMS = (
    re.compile(r"\bETH\s*/\s*USDC\s+bounties\b", re.IGNORECASE),
    re.compile(r"\bETH\s+(?:and|or)\s+USDC\s+bounties\b", re.IGNORECASE),
    re.compile(r"\b(?:USDC|ERC-?20)(?:[- ](?:based|denominated))?\s+bounties\b", re.IGNORECASE),
    re.compile(r"\bbounties\s+(?:in|using)\s+(?:USDC|ERC-?20)\b", re.IGNORECASE),
    re.compile(r"\b(?:supports?|accepts?|enables?|offers?)\s+(?:native\s+)?(?:USDC|ERC-?20)\b", re.IGNORECASE),
)


def _advertises_unsupported_asset(text: str) -> bool:
    disclosures_removed = re.sub(
        r"\b(?:do|does)\s+not\s+(?:accept|support|enable|offer)s?\b|"
        r"\bnot\s+(?:implemented|accepted|supported|enabled|offered)\b|"
        r"\b(?:future|design)\s+target\b|\bnot\s+a\s+shipped\s+capability\b",
        "",
        text,
        flags=re.IGNORECASE,
    )
    return any(pattern.search(disclosures_removed) for pattern in SHIPPED_ASSET_CLAIMS)


def _public_sources() -> list[Path]:
    sources = [ROOT / "README.md", ROOT / "docs" / "BUILD.md", ROOT / "docs" / "FUNDING.md"]
    web_root = ROOT / "web" / "src"
    sources.extend(
        path
        for path in web_root.rglob("*")
        if path.suffix in {".ts", ".tsx", ".md"} and not path.name.endswith(".test.ts")
    )
    return sources


def test_public_copy_does_not_advertise_unimplemented_usdc_or_erc20() -> None:
    for source in _public_sources():
        text = source.read_text(encoding="utf-8")
        assert not _advertises_unsupported_asset(text), (
            f"{source.relative_to(ROOT)} advertises an unsupported asset path"
        )


def test_asset_claim_classifier_distinguishes_shipped_claims_from_disclosures() -> None:
    forbidden = (
        "ETH/USDC bounties",
        "ETH and USDC bounties",
        "USDC-denominated bounties",
        "Bounties in ERC-20",
        "P42 supports USDC",
        "The portal accepts ERC20",
    )
    allowed = (
        "USDC/ERC-20 is not implemented or accepted.",
        "ERC-20 not supported",
        "Do not accept USDC.",
        "USDC support is a future design target, not a shipped capability.",
    )

    assert all(_advertises_unsupported_asset(text) for text in forbidden)
    assert not any(_advertises_unsupported_asset(text) for text in allowed)


def test_contract_fee_cap_and_public_copy_agree() -> None:
    contract = (ROOT / "contracts" / "src" / "P42PayoutLedger.sol").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    build = (ROOT / "docs" / "BUILD.md").read_text(encoding="utf-8")

    assert "uint16 public constant MAX_FEE_BPS = 250;" in contract
    assert "MAX_FEE_BPS = 250" in readme
    assert "MAX_FEE_BPS = 250" in build
