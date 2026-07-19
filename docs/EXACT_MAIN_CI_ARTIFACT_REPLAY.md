# Exact-main CI artifact replay

## Current successful `main` runs (v3)

`scripts/replay_current_main_ci_artifacts.py` is the bounded current-run path.
It does not modify or regenerate the historical v1 generator or receipt. The
operator supplies an explicit GitHub `owner/name`, merged pull request number,
successful push run ID, exact lowercase 40-hex `main` SHA, retained artifact ZIP
root, local source Git checkout containing that SHA, and an offline GitHub REST
capture.

The capture is a JSON object with exactly `capturedAt`, `mainRef`,
`pullRequest`, `run`, `jobs`, and `artifacts`. `mainRef`, `pullRequest`, and
`run` are captured REST objects. `jobs` and `artifacts` are the fully
paginated REST response objects, including their `total_count` fields. Capture
can be performed separately with authenticated tooling, but
the replay CLI itself makes no network calls and tests use fixtures only. The
run must use pinned workflow ID `310385148`, and the jobs page must contain
exactly the four application gates, two SP1 producers, and the reproducibility
comparator, all successful.

Capture the merged PR, current `main` ref, run, and both fully paginated REST
records before downloading artifacts:

```bash
RUN_ID=30000000001
PR=178
CAPTURE_DIR=/secure/capture
install -d -m 700 "$CAPTURE_DIR" "$CAPTURE_DIR/archives"
gh api "repos/techno-optimist/p42-prizes/git/ref/heads/main" > "$CAPTURE_DIR/main-ref.json"
gh api "repos/techno-optimist/p42-prizes/pulls/$PR" > "$CAPTURE_DIR/pull-request.json"
gh api "repos/techno-optimist/p42-prizes/actions/runs/$RUN_ID" > "$CAPTURE_DIR/run.json"
gh api --paginate "repos/techno-optimist/p42-prizes/actions/runs/$RUN_ID/jobs?per_page=100" > "$CAPTURE_DIR/jobs-pages.json"
gh api --paginate "repos/techno-optimist/p42-prizes/actions/runs/$RUN_ID/artifacts?per_page=100" > "$CAPTURE_DIR/artifact-pages.json"
jq -n \
  --arg capturedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --slurpfile mainRef "$CAPTURE_DIR/main-ref.json" \
  --slurpfile pullRequest "$CAPTURE_DIR/pull-request.json" \
  --slurpfile run "$CAPTURE_DIR/run.json" \
  --slurpfile jobPages "$CAPTURE_DIR/jobs-pages.json" \
  --slurpfile artifactPages "$CAPTURE_DIR/artifact-pages.json" \
  '{capturedAt:$capturedAt,mainRef:$mainRef[0],pullRequest:$pullRequest[0],run:$run[0],jobs:{total_count:($jobPages|map(.total_count)|max),jobs:($jobPages|map(.jobs)|add)},artifacts:{total_count:($artifactPages|map(.total_count)|max),artifacts:($artifactPages|map(.artifacts)|add)}}' \
  > "$CAPTURE_DIR/github-api.json"
chmod 600 "$CAPTURE_DIR"/*.json
jq -r '.artifacts[] | [.id,.name] | @tsv' "$CAPTURE_DIR/github-api.json" |
  while IFS=$'\t' read -r artifact_id artifact_name; do
    gh api "repos/techno-optimist/p42-prizes/actions/artifacts/$artifact_id/zip" \
      > "$CAPTURE_DIR/archives/$artifact_name.zip"
  done
chmod 600 "$CAPTURE_DIR/archives"/*.zip
```

The tool rejects a PR merge commit or captured `refs/heads/main` that differs
from the requested SHA, pull-request and non-`main` CI runs, foreign/fork heads,
SHA or run-ID drift, non-successful or incomplete runs, partial jobs/artifact
pages, unfinished or failed jobs, expired artifacts, duplicate IDs, and
artifact records attributed to another run. It derives expected names from the
five published validated artifact prefixes, the two fixed Ubuntu runner images,
and the requested run ID. Caller-supplied artifact names and IDs become receipt
data only after that derivation and API-record cross-check. The archive root
must contain exactly those ten `<artifact-name>.zip` files. Each downloaded ZIP
must match GitHub's recorded byte size and SHA-256 before bounded extraction,
and each archive must contain its exact flat file inventory. The replay caps one
archive at 512 MiB, all retained archives at 1 GiB, one member at 256 MiB, one
extracted archive at 512 MiB, and aggregate extracted bytes at 1 GiB.

Replay uses the historical tool's hostile no-follow snapshots, stable reads,
pairwise byte comparison, semantic verifier launcher, and non-overwriting
publication helper. Verifier and candidate-source bytes are materialized from
the exact requested commit with `git show`. The output validates against the
closed v3 schema and `receiptHash` covers canonical JSON with that field
removed.

```bash
python3 scripts/replay_current_main_ci_artifacts.py \
  --repository techno-optimist/p42-prizes \
  --run-id 30000000001 \
  --main-sha 0123456789abcdef0123456789abcdef01234567 \
  --pull-request-number 178 \
  --archive-root /secure/capture/archives \
  --github-capture /secure/capture/github-api.json \
  --source-repo /path/to/p42-prizes \
  --output /secure/receipts/exact-main-ci-artifact-replay-30000000001-v3.json
```

V3 retains and hashes each downloaded ZIP, requires equality with the digest
and size in the captured API record, securely extracts the verified bytes into
a private temporary root, and independently hashes every extracted file and
directory. The self-hash binds the caller-supplied capture; it does not
authenticate that capture as a GitHub statement. Online API capture,
release-authority signatures, and independent review remain separate gates. The
receipt also does not claim transparency-log inclusion, non-x86 execution,
candidate promotion, or any protocol/gate mutation.

## Historical fixed run (v1)

`scripts/replay_exact_main_ci_artifacts.py` productizes the offline replay of the
ten validated SP1 artifact directories downloaded from GitHub Actions run
[`29645758684`](https://github.com/techno-optimist/p42-prizes/actions/runs/29645758684).
That successful `CI` push run is fixed to repository `techno-optimist/p42-prizes`,
`main` commit `1b65b84b13dbe350339bcd985b44b5224e6c6df7`, workflow
`.github/workflows/ci.yml`, run attempt 1, and run number 798.

The checked receipt is
`docs/evidence/exact-main-ci-artifact-replay-29645758684.json`. Its closed schema
is `docs/operations/schemas/exact-main-ci-artifact-replay.schema.json`.

## What the replay proves

The tool requires exactly these extracted directories, with no other root
entries:

- `p42-validated-distinct-subset-sums-a11-x86-elf-ubuntu-22.04-29645758684`
- `p42-validated-distinct-subset-sums-a11-x86-elf-ubuntu-24.04-29645758684`
- `p42-validated-hadamard-668-x86-elf-ubuntu-22.04-29645758684`
- `p42-validated-hadamard-668-x86-elf-ubuntu-24.04-29645758684`
- `p42-validated-q6-candidate-ubuntu-22.04-29645758684`
- `p42-validated-q6-candidate-ubuntu-24.04-29645758684`
- `p42-validated-edges-candidate-ubuntu-22.04-29645758684`
- `p42-validated-edges-candidate-ubuntu-24.04-29645758684`
- `p42-validated-sp1-build-provenance-ubuntu-22.04-29645758684`
- `p42-validated-sp1-build-provenance-ubuntu-24.04-29645758684`

Each root entry must be a real directory. Every artifact entry must be a direct,
no-follow regular file; symlinks, subdirectories, devices, sockets, and extra
files fail closed. The replay then:

1. Runs the existing `scripts/verify-sp1-objective-reproduction.py` against all
   eight program artifacts.
2. Requires that verifier to equal both the Git blob and SHA-256 fixed at the
   run's source commit.
3. Requires exact file-set and byte equality between Ubuntu 22.04 and 24.04 for
   each program and for SP1 build provenance.
4. Requires the frozen A11 and Hadamard identities and the observed untrusted
   Q6 and Edges candidate identities to equal the fixed run observations.
5. Requires the two provenance files to be identical and to retain
   `trust=candidate-build-inputs-only`, x86_64 Linux, SP1 `6.1.0`, and the fixed
   SP1/toolchain identities.
6. Records every file's byte size and SHA-256. A directory digest is the SHA-256
   of UTF-8, minified, key-sorted JSON for the file records sorted by filename.
7. Retains canonical GitHub run, workflow, and per-artifact API observations,
   each with its own canonical-record SHA-256. Every artifact record includes
   GitHub's archive digest and the independently computed SHA-256 of the
   downloaded ZIP; the receipt requires them to agree.
8. Binds the exact generator and schema byte size and SHA-256. These hashes are
   computed from the external files and covered by the receipt self-hash; the
   generator and schema do not embed their own expected digest.

Artifact capture is snapshot-based. The tool opens the root and all ten
directories with retained directory descriptors and `O_NOFOLLOW`, opens every
artifact file once relative to its directory descriptor, requires one-link
regular files, and checks device, inode, size, mtime, and ctime before and after
the single byte read. Manifests, identity checks, pairwise comparison, and
semantic replay all consume those retained bytes. Semantic replay materializes
a private temporary copy rather than rereading artifact paths. The Q6 and Edges
source closures are extracted as Git blobs from commit `1b65b84`, recorded by
path, blob SHA-1, byte SHA-256, and size, and materialized beside that temporary
copy; the verifier never consults the mutable checkout for those semantics.
Before accepting the replay, the tool revalidates every open descriptor,
pathname binding, metadata tuple, and directory inventory.

The phrase "independent exact-main artifact replay" means that the downloaded
bytes were replayed by this separate offline operation. It is explicitly not
independent-operator evidence: both CI matrix jobs were GitHub-hosted under the
same repository operator. It is x86_64-only, not cross-architecture or non-x86
evidence. It does not convert the CI mock execution into a non-mock proof. It
does not promote Q6, Edges, or build provenance from candidate status. It does
not change gate status or mutate a frozen artifact.

The retained GitHub API records and archive digests preserve exactly what was
observed while the Actions artifacts were available. They do not retain the ZIP
archives themselves, make an expired artifact downloadable, or constitute a
GitHub signature or transparency-log attestation. After Actions expiry, a
reviewer can verify the retained records, archive digests, extracted-file
manifests, replay, and receipt bindings, but cannot redownload from this packet.

## Generate once

Use a clean checkout that contains source commit `1b65b84` and the exact
downloaded directory tree. The output parent must already exist.

```bash
python3 scripts/replay_exact_main_ci_artifacts.py \
  --artifacts /private/tmp/p42-main-29645758684-validated-replay \
  --output docs/evidence/exact-main-ci-artifact-replay-29645758684.json
```

The output is deterministic canonical JSON with one trailing LF. `receiptHash`
is SHA-256 over the canonical receipt after removing `receiptHash`. Creation
retains a no-follow parent descriptor, writes and fsyncs an exclusive private
temporary file, atomically publishes it without replacement by same-directory
hard link, revalidates parent and output identity, removes the temporary link,
and fsyncs the directory. Existing output paths are never overwritten.
The receipt contains no GitHub token, authorization header, environment dump,
operator home path, or artifact download URL.

## Verify

Verification performs the complete snapshot-stable semantic and byte replay
again, validates every retained GitHub record hash and archive-digest equality,
requires the current generator and schema bytes to match the receipt, validates
the checked receipt against the closed schema, checks canonical bytes and the
self-hash, then requires exact equality with the freshly reconstructed receipt.

```bash
python3 scripts/replay_exact_main_ci_artifacts.py \
  --artifacts /private/tmp/p42-main-29645758684-validated-replay \
  --verify-receipt docs/evidence/exact-main-ci-artifact-replay-29645758684.json
```

Run the focused hostile suite with:

```bash
pytest -q tests/test_exact_main_ci_artifact_replay.py
```

Do not regenerate over the checked receipt. To reproduce it, target a new path,
compare exact bytes, and remove only that disposable output after review.
