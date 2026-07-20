# DGX host-global executor source rehearsal

Status: passed ARM source-level rehearsal; unsigned and non-authorizing.

Source commit: `caa50021ca34b4e5f187a5d85f9f9fe5115f2748`.

Host: `spark-38e3` (`aarch64`, Ubuntu 24.04.4 LTS).

## Exact replay

The source commit was exported with `git archive`, transferred to a disposable
directory on the DGX, and exercised from that archive. The replay observed:

| Path | SHA-256 |
| --- | --- |
| `agent/verifier-executor.py` | `b33f4aceceae0db138cc28d1e0e657dd7891daef02bcbdd62c452c78ed7e7606` |
| `scripts/verify-runtime-systemd.sh` | `8bddc9b5edbe59b4cc19a649fe130e4de1eae114ec1fefbaf520e3d01dbe1b46` |

Results:

- `84 passed in 10.68s`
- `runtime ExecStart CLI contracts verified`
- `runtime systemd templates verified`

The first ARM attempt exposed a process-cleanup race: a killed authorization
fence child could remain unreaped beyond the protocol deadline. Commit
`caa50021ca34b4e5f187a5d85f9f9fe5115f2748` gives mandatory child cleanup a
separate one-second reap grace. The exact archived commit then passed the replay
reported above.

## Authority boundary

Rootful `docker.service` and its socket remained active, and an idle BuildKit
container remained untouched because the host was shared with other work. No
P42 unit, service account, or runtime configuration was installed. The rehearsal
did not exercise a Docker socket, verifier image, production queue, live IPC,
signer, RPC, transcript publication, or on-chain action.

This receipt closes only ARM source and test feasibility for the host-global
executor and systemd templates. It does not close the production target-host
gate for the rootless runtime, immutable verifier images, independent operators,
production credentials, or funding authorization. The report commit is an
evidence-publication descendant of the tested source commit.
