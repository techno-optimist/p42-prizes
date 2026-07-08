from __future__ import annotations

from fractions import Fraction

import pytest

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


def test_credit_rejects_non_positive_improvement() -> None:
    # Positivity must hold for every construction path, not only Credit.parse,
    # so a negative credit can never let another payout exceed the pool.
    with pytest.raises(ValueError):
        Credit("mallory", Fraction(-1, 1))
    with pytest.raises(ValueError):
        Credit("mallory", Fraction(0, 1))


def test_settlement_never_exceeds_pool() -> None:
    # A negative credit used to make honest's payout exceed the pool; it is now
    # unconstructible, so conservation holds for every settleable input.
    result = settle_pool(1000, [Credit("honest", Fraction(3, 1))], fee_bps=0)
    assert sum(payout["amount_wei"] for payout in result["payouts"]) + result["dust_wei"] == 1000


def test_zero_payout_pool_charges_no_fee() -> None:
    # Fee is a skim on payouts, not on funding: a pool that closes with no
    # accepted improvement refunds 100% to funders.
    result = settle_pool(1_000_000, [], fee_bps=250)
    assert result["fee_wei"] == 0
    assert result["dust_wei"] == 1_000_000


def test_settlement_rejects_unrepresentable_denominator() -> None:
    with pytest.raises(ValueError):
        settle_pool(
            1000,
            [Credit("a", Fraction(1, 2**300)), Credit("b", Fraction(1, 3))],
        )
