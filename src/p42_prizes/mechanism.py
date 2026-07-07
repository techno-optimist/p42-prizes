from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Iterable

from p42_prizes.verdict import parse_rational, rational_to_string


MAX_FEE_BPS = 500
MAX_BOND_BPS = 10_000
MAX_THRESHOLD_BPS = 10_000


@dataclass(frozen=True)
class Credit:
    solver: str
    improvement: Fraction

    @classmethod
    def parse(cls, value: str) -> "Credit":
        if "=" not in value:
            raise ValueError("credit must have form solver=num/den")
        solver, raw_improvement = value.split("=", 1)
        solver = solver.strip()
        if not solver:
            raise ValueError("solver cannot be empty")
        improvement = parse_rational(raw_improvement)
        if improvement <= 0:
            raise ValueError("improvement must be positive")
        return cls(solver=solver, improvement=improvement)


def _floor_fraction(value: Fraction) -> int:
    return value.numerator // value.denominator


def _as_fraction(value: Fraction | str) -> Fraction:
    if isinstance(value, Fraction):
        return value
    return parse_rational(value)


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


def required_finalization_bond(
    current_entitlement_wei: int,
    alpha_bps: int,
    min_bond_wei: int = 0,
) -> int:
    """Finalize only if the posted bond still covers current entitlement."""

    if current_entitlement_wei < 0:
        raise ValueError("current_entitlement_wei must be non-negative")
    return required_posting_bond(
        pool_at_submission_wei=current_entitlement_wei,
        alpha_bps=alpha_bps,
        min_bond_wei=min_bond_wei,
    )


def bond_satisfies_finalization(
    posted_bond_wei: int,
    current_entitlement_wei: int,
    alpha_bps: int,
    min_bond_wei: int = 0,
) -> bool:
    if posted_bond_wei < 0:
        raise ValueError("posted_bond_wei must be non-negative")
    return posted_bond_wei >= required_finalization_bond(
        current_entitlement_wei=current_entitlement_wei,
        alpha_bps=alpha_bps,
        min_bond_wei=min_bond_wei,
    )


def required_counter_bond(
    finalizing_entitlement_wei: int,
    beta_bps: int,
    rerun_cost_wei: int,
    cost_multiplier: int = 3,
    min_bond_wei: int = 0,
) -> int:
    """Counter-bond covers both delay value and deterministic rerun cost."""

    if finalizing_entitlement_wei < 0:
        raise ValueError("finalizing_entitlement_wei must be non-negative")
    if beta_bps < 0 or beta_bps > MAX_BOND_BPS:
        raise ValueError(f"beta_bps must be between 0 and {MAX_BOND_BPS}")
    if rerun_cost_wei < 0:
        raise ValueError("rerun_cost_wei must be non-negative")
    if cost_multiplier < 0:
        raise ValueError("cost_multiplier must be non-negative")
    if min_bond_wei < 0:
        raise ValueError("min_bond_wei must be non-negative")

    delayed_value = finalizing_entitlement_wei * beta_bps // 10_000
    rerun_value = rerun_cost_wei * cost_multiplier
    return max(min_bond_wei, delayed_value, rerun_value)


def required_min_improvement(
    current_best: Fraction | str,
    optimum: Fraction | str,
    tau_bps: int,
    min_quantum: Fraction | str = Fraction(0, 1),
    direction: str = "maximize",
) -> Fraction:
    """Threshold is based on the current remaining gap, not the initial gap."""

    if tau_bps < 0 or tau_bps > MAX_THRESHOLD_BPS:
        raise ValueError(f"tau_bps must be between 0 and {MAX_THRESHOLD_BPS}")
    current = _as_fraction(current_best)
    target = _as_fraction(optimum)
    quantum = _as_fraction(min_quantum)
    if quantum < 0:
        raise ValueError("min_quantum must be non-negative")
    if direction == "maximize":
        remaining = target - current
    elif direction == "minimize":
        remaining = current - target
    else:
        raise ValueError("direction must be 'maximize' or 'minimize'")
    if remaining < 0:
        remaining = Fraction(0, 1)
    threshold = remaining * tau_bps / 10_000
    return max(quantum, threshold)


def claimable_amount(vested_wei: int, final_entitlement_wei: int) -> int:
    """Escrow release is capped by the final entitlement after dilution settles."""

    if vested_wei < 0 or final_entitlement_wei < 0:
        raise ValueError("amounts must be non-negative")
    return min(vested_wei, final_entitlement_wei)


def settle_pool(
    pool_wei: int,
    credits: Iterable[Credit],
    fee_bps: int = 250,
) -> dict[str, Any]:
    if pool_wei < 0:
        raise ValueError("pool_wei must be non-negative")
    if fee_bps < 0 or fee_bps > MAX_FEE_BPS:
        raise ValueError(f"fee_bps must be between 0 and {MAX_FEE_BPS}")

    credit_list = list(credits)
    total_improvement = sum((credit.improvement for credit in credit_list), Fraction(0, 1))
    fee_wei = pool_wei * fee_bps // 10_000
    available_wei = pool_wei - fee_wei

    if total_improvement == 0:
        return {
            "pool_wei": pool_wei,
            "fee_bps": fee_bps,
            "fee_wei": fee_wei,
            "available_wei": available_wei,
            "total_improvement": "0/1",
            "payouts": [],
            "dust_wei": available_wei,
        }

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
