"""Cross-language conformance for the canonical rational grammar.

The verifier (Python, ``src/p42_prizes/verdict.py``) and the portal
(TypeScript, ``web/src/lib/exact.ts``) both claim to accept *exactly* the same
rational literals — any divergence is a consensus-split hazard. This test pins
the shared corpus on the Python side; the identical corpus is asserted on the JS
side in ``web/src/lib/exact.test.ts``.

Regression guard for the audit finding that Python's ``re.match`` accepted a
trailing newline (``"1/2\\n"``) that the JS ``$`` anchor rejects.
"""

from __future__ import annotations

from fractions import Fraction

import pytest

from p42_prizes.verdict import parse_rational


# Strings both engines MUST accept, with the Fraction they must produce.
ACCEPTED = {
    "0": Fraction(0, 1),
    "1": Fraction(1, 1),
    "-3": Fraction(-3, 1),
    "+7": Fraction(7, 1),
    "6/12": Fraction(1, 2),
    "1/6": Fraction(1, 6),
    "-1/2": Fraction(-1, 2),
    "10/2": Fraction(5, 1),
}

# Strings both engines MUST reject. The trailing/leading-whitespace cases are
# the regression corpus for the re.match-vs-re.fullmatch fix.
REJECTED = [
    "",
    "/2",
    "1/2/3",
    "0x10",
    "0b101",
    "1_0/2",
    "١/٢",  # unicode digits
    "5/0",  # zero denominator
    " 1/2",
    "1/2 ",
    "1/2\n",
    "12\n",
    "-3\n",
    "\n1/2",
    "1 ",
    " 1",
    "\t1/2",
]


@pytest.mark.parametrize("literal,expected", sorted(ACCEPTED.items()))
def test_accepted_literals_parse_to_expected_fraction(literal: str, expected: Fraction) -> None:
    assert parse_rational(literal) == expected


@pytest.mark.parametrize("literal", REJECTED)
def test_rejected_literals_raise(literal: str) -> None:
    with pytest.raises(ValueError):
        parse_rational(literal)
