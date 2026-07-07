from __future__ import annotations

from fractions import Fraction

from p42_prizes.mechanism import (
    Credit,
    bond_satisfies_finalization,
    claimable_amount,
    required_counter_bond,
    required_finalization_bond,
    required_min_improvement,
    required_posting_bond,
    settle_pool,
)


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


def test_finalization_bond_closes_after_funding_leverage() -> None:
    posted = required_posting_bond(pool_at_submission_wei=0, alpha_bps=2_500, min_bond_wei=1_000)
    assert posted == 1_000
    assert required_finalization_bond(current_entitlement_wei=100_000, alpha_bps=2_500) == 25_000
    assert not bond_satisfies_finalization(
        posted_bond_wei=posted,
        current_entitlement_wei=100_000,
        alpha_bps=2_500,
    )
    assert bond_satisfies_finalization(
        posted_bond_wei=25_000,
        current_entitlement_wei=100_000,
        alpha_bps=2_500,
    )


def test_counter_bond_covers_delay_value_and_rerun_cost() -> None:
    assert required_counter_bond(
        finalizing_entitlement_wei=100_000,
        beta_bps=500,
        rerun_cost_wei=1_000,
        cost_multiplier=3,
        min_bond_wei=500,
    ) == 5_000
    assert required_counter_bond(
        finalizing_entitlement_wei=10_000,
        beta_bps=100,
        rerun_cost_wei=2_000,
        cost_multiplier=4,
        min_bond_wei=500,
    ) == 8_000


def test_min_improvement_uses_current_remaining_gap() -> None:
    assert required_min_improvement(
        current_best=Fraction(99, 1),
        optimum=Fraction(100, 1),
        tau_bps=100,
        min_quantum=Fraction(0, 1),
    ) == Fraction(1, 100)
    assert required_min_improvement(
        current_best="101/100",
        optimum="1/1",
        tau_bps=100,
        min_quantum="1/1000",
        direction="minimize",
    ) == Fraction(1, 1000)
