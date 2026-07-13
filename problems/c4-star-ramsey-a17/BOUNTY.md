# Bounty

Submit a simple red graph on `m` vertices with no `C4` and minimum red degree
at least `m-17`. The verifier scores `m`; only a certified `m = 22` improves
the bundled exact `m = 21` frontier.

The package proves `m <= 22`. A winning witness would meet Parsons' general
upper bound and establish `R(C4,K1,17) = 23`. The bundled seed already proves
the lower bound `R(C4,K1,17) >= 22`; it is repository-certified and pending
external table review.

Before funding, run the open-witness ceremony and replace the effective
frontier with the strongest publicly posted executable witness. Settlement
uses raw integer improvement `m - frontier`, never a claimed score.
