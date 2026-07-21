# Provenance, License, and Attribution

## Imported source

This package converts the `minimum-autocorrelation-bound` source repository at
commit `b23f2d386eda9963e33c7531eeeb35c8f54cba37` (`Embed Zenodo DOIs`,
2026-07-06) into the P42 problem format. The bundled
seed is a lossless rescaling of `certs/certificate_n480.json`: each original
height was multiplied by the common denominator 120. Its grid width remains
`13/4800`, and the verifier independently recomputes score
`2378625/5958277`.

- Concept DOI: `10.5281/zenodo.21227361`
- Version DOI: `10.5281/zenodo.21227362`
- Development repository: `github.com/techno-optimist/minimum-autocorrelation-bound`

No optimizer `.npz`, generated PDF, or source verifier was copied into the
certified path. The P42 verifier is independently adapted to accept arbitrary
bounded submissions rather than checking equality to one pinned certificate.

## Mathematical attribution

The constant, the published lower/upper sides, and the modified-arcsine
construction are due to R. C. Barnard and S. Steinerberger, *Three convolution
inequalities on the real line with connections to additive combinatorics*,
J. Number Theory 207 (2020), arXiv:1903.08731.

The Problem 6.6 framing and proposed bounded-step-function search are from
B. Georgiev, J. Gomez-Serrano, T. Tao, and A. Z. Wagner, *Mathematical
exploration and discovery at scale*, arXiv:2511.02864.

The strict upper-side result is due to J. Madrid and A. Ramos, *On optimal
autocorrelation inequalities on the real line*, CPAA 19 (2020),
arXiv:2003.06962.

The exact seed certificate and source note are by Kevin Russell with CHRONOS / 
ProjectForty2 assistance.

## License boundary

The source repository releases code and certificate data under the MIT License.
This package's verifier, tests, metadata, and converted seed are distributed
under that license; see `LICENSE`. The CC BY 4.0 paper text and PDF are not
redistributed here. Bibliographic facts and short mathematical definitions in
this package are package documentation, not a copy of the paper.
