from __future__ import annotations

from fractions import Fraction

from p42_prizes.mechanism import Credit, claimable_amount, required_posting_bond, settle_pool


def test_final_denominator_settlement_matches_worked_example() -> None:
    result = settle_pool(
        1300,
        [
            Credit("alice", Fraction(6, 1)),
            Credit("bob", Fraction(3, 1)),
            Credit("carol", Fraction(4, 1)),
        ],
        fee_bps=0,
    )
    assert [payout["amount_wei"] for payout in result["payouts"]] == [600, 300, 400]
    assert result["total_improvement"] == "13/1"
    assert result["dust_wei"] == 0


def test_sybil_split_is_payout_neutral() -> None:
    single = settle_pool(
        1000,
        [Credit("honest", Fraction(9, 10)), Credit("attacker", Fraction(1, 10))],
        fee_bps=0,
    )
    split = settle_pool(
        1000,
        [Credit("honest", Fraction(9, 10))]
        + [Credit(f"attacker_{i}", Fraction(1, 100)) for i in range(10)],
        fee_bps=0,
    )
    single_attacker = single["payouts"][1]["amount_wei"]
    split_attacker = sum(payout["amount_wei"] for payout in split["payouts"][1:])
    assert single_attacker == split_attacker == 100


def test_fee_is_capped_and_dust_is_explicit() -> None:
    result = settle_pool(
        101,
        [Credit("alice", Fraction(1, 2)), Credit("bob", Fraction(1, 2))],
        fee_bps=250,
    )
    assert result["fee_wei"] == 2
    assert [payout["amount_wei"] for payout in result["payouts"]] == [49, 49]
    assert result["dust_wei"] == 1


def test_claim_is_capped_by_final_entitlement_after_dilution() -> None:
    assert claimable_amount(vested_wei=10_000, final_entitlement_wei=5_060) == 5_060
    assert claimable_amount(vested_wei=3_000, final_entitlement_wei=5_060) == 3_000


def test_posting_bond_is_fixed_from_pool_at_submission() -> None:
    assert required_posting_bond(pool_at_submission_wei=100_000, alpha_bps=200, min_bond_wei=1_000) == 2_000
    assert required_posting_bond(pool_at_submission_wei=0, alpha_bps=200, min_bond_wei=1_000) == 1_000
