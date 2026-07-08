from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Iterable

from p42_prizes.verdict import parse_rational, rational_to_string


MAX_FEE_BPS = 250
MAX_BOND_BPS = 10_000
# The on-chain settlement target is Solidity uint256. Improvements whose reduced
# common denominator exceeds this cannot be represented exactly on-chain, so the
# reference model refuses them rather than settling a case the contract can't.
# Production must additionally pin a fixed per-problem denominator (BUILD.md §3).
MAX_SETTLEMENT_DENOMINATOR = 2**256 - 1


@dataclass(frozen=True)
class Credit:
    solver: str
    improvement: Fraction

    def __post_init__(self) -> None:
        # Enforced for every construction path, not just Credit.parse: the spec
        # defines improvement as Delta = max(0, ...) > 0, and a negative credit
        # would let another payout row exceed the pool (conservation break).
        if not self.solver:
            raise ValueError("solver cannot be empty")
        if not isinstance(self.improvement, Fraction):
            raise TypeError("improvement must be a Fraction")
        if self.improvement <= 0:
            raise ValueError("improvement must be positive")

    @classmethod
    def parse(cls, value: str) -> "Credit":
        if "=" not in value:
            raise ValueError("credit must have form solver=num/den")
        solver, raw_improvement = value.split("=", 1)
        solver = solver.strip()
        improvement = parse_rational(raw_improvement)
        return cls(solver=solver, improvement=improvement)


def _floor_fraction(value: Fraction) -> int:
    return value.numerator // value.denominator


def required_posting_bond(
    pool_at_submission_wei: int,
    alpha_bps: int,
    min_bond_wei: int = 0,
) -> int:
    """Bond is fixed from the pool balance observed at commit time."""

    if pool_at_submission_wei < 0:
        raise ValueError("pool_at_submission_wei must be non-negative")
    if min_bond_wei < 0:
        raise ValueError("min_bond_wei must be non-negative")
    if alpha_bps < 0 or alpha_bps > MAX_BOND_BPS:
        raise ValueError(f"alpha_bps must be between 0 and {MAX_BOND_BPS}")
    scaled = pool_at_submission_wei * alpha_bps // 10_000
    return max(min_bond_wei, scaled)


def claimable_amount(vested_wei: int, final_entitlement_wei: int) -> int:
    """Escrow release is capped by the final entitlement after dilution settles."""

    if vested_wei < 0 or final_entitlement_wei < 0:
        raise ValueError("amounts must be non-negative")
    return min(vested_wei, final_entitlement_wei)


def settle_pool(
    pool_wei: int,
    credits: Iterable[Credit],
    fee_bps: int = 250,
    max_denominator: int = MAX_SETTLEMENT_DENOMINATOR,
) -> dict[str, Any]:
    if pool_wei < 0:
        raise ValueError("pool_wei must be non-negative")
    if fee_bps < 0 or fee_bps > MAX_FEE_BPS:
        raise ValueError(f"fee_bps must be between 0 and {MAX_FEE_BPS}")

    credit_list = list(credits)
    total_improvement = sum((credit.improvement for credit in credit_list), Fraction(0, 1))

    if total_improvement.denominator > max_denominator:
        raise ValueError(
            "combined improvement denominator "
            f"{total_improvement.denominator} exceeds the settlement bound "
            f"{max_denominator}; pin a fixed per-problem denominator"
        )

    if total_improvement == 0:
        # No accepted improvement means no payout occurred, so the protocol fee
        # (a skim on payouts, not on funding) is zero and the whole pool is
        # refundable to funders (BUILD.md §3, CLOSE refund rules).
        return {
            "pool_wei": pool_wei,
            "fee_bps": fee_bps,
            "fee_wei": 0,
            "available_wei": pool_wei,
            "total_improvement": "0/1",
            "payouts": [],
            "dust_wei": pool_wei,
        }

    fee_wei = pool_wei * fee_bps // 10_000
    available_wei = pool_wei - fee_wei

    payouts: list[dict[str, Any]] = []
    paid = 0
    for credit in credit_list:
        amount = _floor_fraction(available_wei * credit.improvement / total_improvement)
        paid += amount
        payouts.append(
            {
                "solver": credit.solver,
                "improvement": rational_to_string(credit.improvement),
                "amount_wei": amount,
            }
        )

    return {
        "pool_wei": pool_wei,
        "fee_bps": fee_bps,
        "fee_wei": fee_wei,
        "available_wei": available_wei,
        "total_improvement": rational_to_string(total_improvement),
        "payouts": payouts,
        "dust_wei": available_wei - paid,
    }
