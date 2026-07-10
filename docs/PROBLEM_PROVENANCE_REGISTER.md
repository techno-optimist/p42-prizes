# P42 Problem Provenance And IP Evidence Register

Status date: 2026-07-10. Evidence snapshot only; not legal advice.

This register audits the ten packages at repository commit
`52ddf44e2d06a1a9467b2cd5179536e53b12a833`. A package tree hash is the Git
SHA-1 tree object returned by `git rev-parse <commit>:problems/<slug>`; witness
hashes are SHA-256 over the raw bundled file bytes. The machine-readable source
of the fields below is
[`docs/provenance/problem-provenance-register.json`](provenance/problem-provenance-register.json).

## Decision

**Real-ETH funding: NO-GO for every board and for the slate as a whole.** The
repository has no root or package license, none of the ten packages has a
cleared redistribution record, immutable verifier images and N-host admission
are absent, and several boards have board-specific source or semantic blockers.
The two highest-signal blockers are:

1. **Signed C3 semantic mismatch.** DOI `10.5281/zenodo.21194863` defines the
   signed constant using `abs(max_t(f*f)(t))`, which is the positive signed
   maximum here and gives the published OrganonAgent value near `1.45230433`.
   The current package computes `max_t abs((f*f)(t))`, the distinct L-infinity
   cousin. Its same negative-dominant witness scores about `4.98749832`. The
   DOI and portal discovery therefore do not support the verifier functional.
2. **Superseded Erdos frontier.** The package accepts only the old `n=2400`
   Hyra witness from upstream `v1.0` and displays
   `Q_old < 0.3808669097979875909124431`. The portal cites DOI
   `10.5281/zenodo.21246903`, which is upstream `v1.1`; that release expressly
   calls the `n=2400` value superseded and proves the tighter `n=512` bound
   `mu < 0.3808622032020279475140496`. The package cannot accept the current
   published witness.

## Root Licensing Boundary

No `LICENSE`, `COPYING`, `NOTICE`, SPDX package field, or per-package license
exists in this repository. The example string `license: "CC0 / MIT verifier"`
in `docs/BUILD.md` is template prose, not a license grant. This audit does not
choose or add a root license. That is an explicit operator/legal decision that
must account for original P42 code, transformed upstream certificate data,
third-party notices, publication text, and user-submitted artifacts.

Where an upstream repository says MIT for code/certificate data and CC BY 4.0
for note text/figures, this register records that upstream permission but does
not treat it as a package-level grant. The current packages omit the upstream
MIT notice and do not document which local files are copies, transformations,
or new works. Their redistribution status is therefore **not cleared** pending
notice inclusion, scope mapping, attribution, and operator/legal approval.

## Evidence Matrix

| Board | Package tree | Bundled witness and SHA-256 | Primary source / immutable ref | License and redistribution | Portal vs verifier | Real ETH |
| --- | --- | --- | --- | --- | --- | --- |
| `hadamard-mini` | `410bb673253334e2f4eceb7bf5db3cc8e14cfd15` | `valid-4.json` `4771e6e4e18ebecb9f4f74f9849f69b784319256d8bd4d04c9f62164a9cdb1b7` | None stated | No SPDX; not cleared | Match | No-go, demo fixture |
| `erdos-min-overlap` | `a09f6e5b93a1fd17de8064f90e004378468464c0` | `hyra-upper.json` `f37c8f97ae3f3b8a50344d7b9e9ffb3be506457a26a8d55622004b83f5ae64d1` | `v1.0` `8fa0854d0099e0c6e8e211f5d6b108c7015f1256`; current `v1.1` `e0ddacb424a2701689a65419582293b0974f7edf` | Upstream MIT data / CC-BY-4.0 note; package notice absent | Partial; package frontier superseded | No-go |
| `edges-vs-triangles` | `24fec7eb3fa3b97bf3e5ad5d9fcc18c8fce63402` | `rational-curve-sample.json` `a662d18c930fbb2c351ca5987e78113be30657a04615cbff87e4781745969214` | None; historical Arena artifact missing | No SPDX; not cleared | Match to disclosed local model only | No-go / hold |
| `arithmetic-kakeya` | `dcf2cb0064fbfedb0726acd5628e85eaacab71eb` | `kt-2x2-forcing.json` `031865755a17795bf2a4c65a24986589b6a8d10085d6a062fae5293c38a7f118` | Mutable Epoch PDF only; local named note absent | No package SPDX; local artifact not cleared | Partial; 2x2 warm-up only | No-go / hold |
| `autoconvolution-c1-upper` | `ea1586e043fb068475032474ea268e43effc8b9f` | `hyra-upper.json` `0dc121b9404193d8a423400b946645e14ed1403c2d7bcb6c3b23ffc07675ad0e` | `v1.0` `1827a116b1d704a7237c9064507a490045a039d6` | Upstream MIT data / CC-BY-4.0 note; package notice absent | Match | No-go |
| `autoconvolution-c2-lower` | `01185e6d67731c71f1e326e4d6c54eafa0485a77` | `hyra-lower.json` `6e785f481b592e0a6d1a77dd367c0379b8a3e55fe3b739c5cd1b352d7a25f064` | `v1.0` `1827a116b1d704a7237c9064507a490045a039d6` | Upstream MIT data / CC-BY-4.0 note; package notice absent | Match | No-go |
| `signed-autoconvolution-c3-upper` | `96de3c662aa00bfe7cc494cf119345845dd9f8e1` | `organon-upper.json` `546aa6f4f08fcf78c7cdf762c405281d423025a1260930f3269813a4138e294e` | `v1.0` `1827a116b1d704a7237c9064507a490045a039d6` | Upstream MIT data / CC-BY-4.0 note; package notice absent | **No; different functional** | **No-go / blocked** |
| `mertens-lp-ceiling-k12000` | `51a00684d558e6dd724b78049c77d873891d7acd` | `certificate-k12000.json` `769a2cc98425695b4024d9c6ef549cc668e31882ae7773992967744540cb2795` | `v1.1` `301043cc15a0d08d804bfde4e095cdfe2340c5c2` | Upstream MIT data / CC-BY-4.0 note; package notice absent | Match finite K=12000 ceiling | No-go |
| `pnt-sparse-mertens-construction` | `f6a1a0d67bda0642a7e60061a3dc91c3fb77a2d3` | `chronos-96000.json` `a60e6687ed1731009b3e3383fba1429bfac2bff694ee8e4fe256eef1fa42fb05` | Private `/private/tmp` path and Arena receipt only; neither retained | No SPDX; not cleared | Local copy matches; linked DOI does not | No-go |
| `hadamard-668-defect` | `ee911e581b9c0b7e15b280583310b66241beda72` | `sylvester-prefix.json` `4021e45669d91b63179c730309eb26613e4584aa63ee7ec928b32cd4b1ed2bc6` | None stated; locally generated classical construction | No SPDX; not cleared | Match defect ladder | No-go |

## Board Records

### `hadamard-mini`

- **Witness:** 58-byte `examples/valid-4.json`, score `0/1`; raw hash is in the matrix.
- **Source / publication / attribution:** no source URL, repository, publication,
  DOI, or artifact author is stated. It is recognizable as the standard order-4
  Sylvester matrix, but that observation is not substituted for evidence.
- **Functional:** portal and verifier both minimize the six nonorthogonal row
  pairs of a 4 by 4 sign matrix. Claim match: **yes**.
- **Missing evidence:** artifact authorship and license declaration; root/package
  redistribution policy; immutable verifier image; four-host deterministic run.

### `erdos-min-overlap`

- **Witness:** 59,086-byte `examples/hyra-upper.json`, exact score
  `1424992289798782609633201801352767458976314440679252577/3741444197802851304404516484910431627947663875649308401`.
- **Declared source:** `arena/erdos_note/certs/erdos_hyra_current.json converted
  from exact Python float bit patterns`.
- **Immutable source:** upstream [`v1.0`](https://github.com/techno-optimist/erdos-minimum-overlap-bound/tree/v1.0),
  commit `8fa0854d0099e0c6e8e211f5d6b108c7015f1256`, source blob
  `9ab03527b57314d666c235d3d5893b1ab1d051f1`, source SHA-256
  `5fd088018f1b648b73a4f0086eceb64f9cf50a7390cc8ddf3cf7b60352f824ba`.
  Conversion of all 2,400 Python float bit patterns to denominator `2^82` was
  reproduced exactly.
- **Publication / attribution:** Hyra witness; Kevin Russell / ProjectForty2.
  Witness version DOI [`10.5281/zenodo.21194861`](https://doi.org/10.5281/zenodo.21194861).
  The portal instead cites current v1.1 DOI
  [`10.5281/zenodo.21246903`](https://doi.org/10.5281/zenodo.21246903),
  tag `v1.1`, commit `e0ddacb424a2701689a65419582293b0974f7edf`.
- **Functional:** the packaged old witness is evaluated consistently, but the
  cited current publication's `n=512` artifact cannot pass the verifier's fixed
  `n=2400` schema. Claim match: **partial and superseded**.
- **Missing evidence:** package MIT notice; decision to update to v1.1 or freeze
  v1.0 honestly; continuum-reduction review; artifact-floor search; immutable
  image and N-host evidence.

### `edges-vs-triangles`

- **Witness:** 24,241-byte `examples/rational-curve-sample.json`, exact score
  `-16684282317138839/23437500000000000`.
- **Source / publication / attribution:** the source field says it is a local
  fixed-row-sum sample and expressly not the missing historical Arena incumbent.
  No URL, immutable receipt, publication, DOI, named author, or license exists.
- **Functional:** the portal accurately describes this local slope-3
  area-plus-gap score and includes the historical-artifact caveat. Claim match:
  **yes to the local model, not to any historical Arena frontier**.
- **Missing evidence:** historical receipt/incumbent; named artifact provenance;
  license; external review that this is a meaningful open frontier; immutable
  image and N-host evidence. Keep on hold or respec before funding.

### `arithmetic-kakeya`

- **Witness:** 345-byte `examples/kt-2x2-forcing.json`, score `7/4`.
- **Declared source:** `arithmetic_kakeya_forcing_certificate_2026_06.md section
  3`; that file is not in the repository and no URL, author, hash, license, or
  immutable commit is supplied.
- **Primary context located:** Epoch AI's
  [New bounds for arithmetic Kakeya](https://epoch.ai/files/open-problems/arithmetic-kakeya.pdf).
  The currently served 512,893-byte PDF had SHA-256
  `496de63b6831db0d69fdeb2a5fad78d40d8b2bbde549bf4b3d9a29395f37223b`
  on 2026-07-10, but its URL is mutable and it is not the named local source.
- **Publication / attribution:** Epoch AI for the public write-up; Katz and Tao
  for the 7/4 warm-up lineage. No DOI is stated. Epoch's site gives a general
  Creative Commons Attribution statement without a versioned SPDX declaration;
  the local certificate remains unlicensed.
- **Functional:** the board page carefully says scoped 2x2 warm-up, while wider
  portal copy calls it the FrontierMath open problem. The verifier does not
  verify general AK progress or establish a finite paid certificate language.
  Claim match: **partial**.
- **Missing evidence:** local note; immutable primary version; derivation from
  accepted certificate to advertised progress; bounded/economic search-space
  argument; license; external scope review; immutable image and N-host evidence.

### `autoconvolution-c1-upper`

- **Witness:** 2,564,099-byte `examples/hyra-upper.json`, exact score recorded in
  the JSON ledger.
- **Immutable source:** [`vectors/ac_board2_leader.json`](https://github.com/techno-optimist/autoconvolution-inequality-certificates/blob/1827a116b1d704a7237c9064507a490045a039d6/vectors/ac_board2_leader.json),
  tag `v1.0`, commit `1827a116b1d704a7237c9064507a490045a039d6`,
  blob `22f953fb5a8578d8ce0c4a68435762852685c758`, SHA-256
  `84b6eed3781a94067e79d17381594fba23d89b84c3758688661da69b2394099b`.
  Scaling every exact JSON decimal token by `10^35` reproduced all 90,000 local
  integers.
- **Publication / attribution:** Hyra witness; Kevin Russell / ProjectForty2;
  concept DOI [`10.5281/zenodo.21194862`](https://doi.org/10.5281/zenodo.21194862),
  immutable v1.0 DOI [`10.5281/zenodo.21194863`](https://doi.org/10.5281/zenodo.21194863).
- **License / redistribution:** upstream README says MIT for code/certificate
  data and CC-BY-4.0 for note text/figures. Its LICENSE scope footer contains
  stale Erdos filenames. Package notice and scope mapping are absent; not cleared.
- **Functional:** publication, portal, and verifier use the same nonnegative C1
  functional. Claim match: **yes**.
- **Missing evidence:** package notice and corrected scope; committed conversion
  transcript; current-literature/independent review; immutable image and N-host
  timing/memory evidence.

### `autoconvolution-c2-lower`

- **Witness:** 1,949,278-byte `examples/hyra-lower.json`, exact score
  `140651861665566489683881393353250795846281833/146070932420211259869783468438333325818535926`.
- **Immutable source:** [`vectors/ac_board3_leader.json`](https://github.com/techno-optimist/autoconvolution-inequality-certificates/blob/1827a116b1d704a7237c9064507a490045a039d6/vectors/ac_board3_leader.json),
  same `v1.0` commit, blob `d19c22f4362a31ec6fa08d138f2e4a92eb753a23`,
  SHA-256 `a78b8e4cff437cbd6bf260e6a80d98a10800f9a8649818fb5b401c8870d00e6c`.
  All 524,288 integers match upstream exactly.
- **Publication / attribution / license:** same v1.0 DOI and licensing evidence as
  C1; Hyra witness, Kevin Russell / ProjectForty2 publication. The publication
  describes this as exact recertification of an existing construction, not a new
  leaderboard win.
- **Functional:** publication, portal, and verifier match. Claim match: **yes**.
- **Missing evidence:** package notice and corrected scope; independent
  current-frontier review; immutable image and N-host timing/memory evidence.

### `signed-autoconvolution-c3-upper`

- **Witness:** 2,285,094-byte `examples/organon-upper.json`, corrected local score
  `40362551506526560656553725091979410551071047680000000/8092744874989952471246071559466128309374865340943729`
  (about `4.98749832`).
- **Immutable source:** [`vectors/ac_board4_leader.json`](https://github.com/techno-optimist/autoconvolution-inequality-certificates/blob/1827a116b1d704a7237c9064507a490045a039d6/vectors/ac_board4_leader.json),
  same `v1.0` commit, blob `8d8e2d625b2435fa5b3c8980c7209c90d5850657`,
  SHA-256 `b4f6a1acd6c625cca66d7a44cf13ed56546e461ef44dfd6483f00c4c2e820c62`.
  Conversion of all 100,000 Python float bit patterns to denominator `2^68`
  reproduced the local integers.
- **Publication / attribution / license:** OrganonAgent witness; Kevin Russell /
  ProjectForty2; same autoconvolution concept and v1.0 DOIs and conditional
  upstream licensing evidence as C1/C2.
- **Functional:** **does not match**. The publication repeatedly distinguishes
  signed maximum `abs(max(f*f))` from L-infinity `max(abs(f*f))`. The portal
  discovery advertises the former at `1.45230433`; the verifier enforces the
  latter, for which this witness is worse than the `3/2` local seed. The package
  correctly fixed an implementation bug only by changing which mathematical
  object the board scores; it did not acquire publication support for that new
  object.
- **Missing evidence:** select one functional through governance; align portal,
  spec, verifier, and seed; provide a valid frontier witness/publication for that
  functional; replace stale image evidence; add notices and external review.

### `mertens-lp-ceiling-k12000`

- **Witness:** 171,839-byte `examples/certificate-k12000.json`; exact score
  `249371902576813203926437/250000000000000000000000`; embedded dual hash
  `2089d81dde22f590ef27e4aeaa4ead55932a8138250d3d05d2299d12647baffd`.
- **Immutable source:** upstream [`v1.1`](https://github.com/techno-optimist/pnt-ceiling-certificates/tree/v1.1),
  commit `301043cc15a0d08d804bfde4e095cdfe2340c5c2`. The NPZ blob
  `5cb29364d9a96cb069462fe6626be204555a48b4` has SHA-256
  `5f87de72c15f863e48647aeb9ee227cec9863abe59f64961de5222bc58a0d36b`;
  `certs/certificate_K12000.json` blob
  `fa3540434c9d5b1e87616b76b2eca05103ea72fc` has SHA-256
  `f7eb7c23f88044aaad1649d42aed5bd99f8847406afef5df76c7c32b6f9c2b51`.
  The local `m` and `Y` arrays match the NPZ exactly.
- **Publication / attribution:** Kevin Russell / ProjectForty2/CHRONOS; concept
  DOI [`10.5281/zenodo.21221207`](https://doi.org/10.5281/zenodo.21221207),
  immutable v1.1 DOI
  [`10.5281/zenodo.21221833`](https://doi.org/10.5281/zenodo.21221833).
- **License / redistribution:** upstream MIT for code/certs/duals and CC-BY-4.0
  for note/figures; package notice absent; not cleared.
- **Functional:** finite K=12000 proof-side ceiling matches publication and
  portal. Claim match: **yes**, with the existing no-monotonicity caveat.
- **Missing evidence:** package notice; committed extraction transcript; portal
  version-DOI pin; independent proof review and in-house solve to determine
  whether the track is effectively closed; immutable image and N-host evidence.

### `pnt-sparse-mertens-construction`

- **Witness:** 98,097-byte `examples/chronos-96000.json`, score
  `9974252022196793/10000000000000000`.
- **Declared source:** `CHRONOS accepted Arena solution 2386, converted from
  /private/tmp/pnt_candidate_96000_safe_scaled.json decimal literals`. The raw
  file and receipt are not retained; no URL, immutable commit, timestamp,
  submitter identity, source hash, license, or publication is available.
- **Publication association:** the portal maps this board to concept DOI
  `10.5281/zenodo.21221207`, but that publication certifies K=4800/K=12000
  proof-side ceilings. It does not publish the reach-96000 construction.
- **Functional:** local portal copy matches the local exhaustive reach-96000
  verifier. The linked publication does not support the artifact or functional.
  Claim match: **partial**.
- **Missing evidence:** Arena receipt; raw source; durable identity and hash;
  public archive; license; conversion transcript; independent interval review;
  immutable image and N-host evidence.

### `hadamard-668-defect`

- **Witness:** 113,745-byte `examples/sylvester-prefix.json`, score `55444/1`.
- **Declared source:** first 668 rows and columns of the classical Sylvester
  order-1024 matrix. No generation transcript, URL, immutable source, named
  artifact author, license, publication, or DOI is supplied.
- **Functional:** portal and verifier both minimize nonorthogonal row-pair
  defect and do not claim the bundled baseline solves order 668. Claim match:
  **yes**. The time-sensitive portal statement that 668 is the smallest unknown
  order has no cited primary current-literature source in the package.
- **Missing evidence:** deterministic generation record; artifact authorship and
  license; primary current-literature citation; compute-indexed baseline and
  public seed challenge; immutable image, N-host timing, and external review.

## URL And Hash Validation

The following primary resources returned HTTP 200 on 2026-07-10 and their refs
were checked with `git ls-remote` or the Zenodo record API:

| Resource | Validated immutable identity |
| --- | --- |
| Erdos upstream | `v1.0^{}` = `8fa0854d0099e0c6e8e211f5d6b108c7015f1256`; `v1.1` = `e0ddacb424a2701689a65419582293b0974f7edf` |
| Autoconvolution upstream | `v1.0^{}` = `1827a116b1d704a7237c9064507a490045a039d6`; current HEAD `73bbac3dd971255832bf97cf761eba1c52ae6048` changes README only |
| PNT ceiling upstream | `v1.1^{}` = `301043cc15a0d08d804bfde4e095cdfe2340c5c2` |
| Erdos Zenodo | v1.0 record `10.5281/zenodo.21194861`; v1.1 record `10.5281/zenodo.21246903`; concept `10.5281/zenodo.21194860` |
| Autoconvolution Zenodo | v1.0 record `10.5281/zenodo.21194863`; concept `10.5281/zenodo.21194862` |
| PNT ceiling Zenodo | v1.1 record `10.5281/zenodo.21221833`; concept `10.5281/zenodo.21221207` |
| Epoch Arithmetic Kakeya PDF | Mutable URL; retrieval SHA-256 `496de63b6831db0d69fdeb2a5fad78d40d8b2bbde549bf4b3d9a29395f37223b` only |

Zenodo metadata identifies Kevin Russell, affiliation ProjectForty2, and
`cc-by-4.0` for the deposited publications. Repository LICENSE/README files,
not Zenodo's publication license, are the evidence used above for certificate
data redistribution.

## Validation Replay

Run from repository commit `52ddf44e2d06a1a9467b2cd5179536e53b12a833`:

```bash
PYTHONDONTWRITEBYTECODE=1 make validate
PYTHONDONTWRITEBYTECODE=1 make lint
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m pytest -q problems -p no:cacheprovider
```

Results: 10/10 manifests valid, 10/10 verifier trees lint-clean, and 40 package
tests passed in 130.17 seconds. These are local source tests, not immutable-image
or N-host admission evidence.

## Machine Checklist

The JSON ledger has exactly ten boards and makes every missing item explicit.
The following commands verify its shape, package tree IDs, and witness hashes:

```bash
jq -e '
  .schema_version == "p42-provenance-register/v1" and
  .global_real_eth_funding_decision == "NO_GO" and
  (.boards | length == 10) and
  all(.boards[]; .checklist.real_eth_fundable == false) and
  all(.boards[]; (.missing_evidence | length) > 0)
' docs/provenance/problem-provenance-register.json

jq -r '.boards[] | [.slug, .package_tree, .witness.path, .witness.sha256] | @tsv' \
  docs/provenance/problem-provenance-register.json |
while IFS=$'\t' read -r slug tree witness expected; do
  test "$(git rev-parse "52ddf44e2d06a1a9467b2cd5179536e53b12a833:problems/$slug")" = "$tree"
  test "$(shasum -a 256 "$witness" | awk '{print $1}')" = "$expected"
done
```

Passing these checks proves register integrity against the audited snapshot. It
does not close IP ownership, mathematical scope, verifier admission, audit,
legal, governance, custody, or mainnet gates.
