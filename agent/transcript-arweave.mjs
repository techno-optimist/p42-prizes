import {
  cidOf,
  confirmArweaveTransaction,
  fetchFromArweave,
  findTxidsByCid,
  uploadToArweave,
} from "./da-arweave.mjs";

const CID_PATTERN = /^sha256:[0-9a-f]{64}$/;
const TXID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function validateArtifact(bytes, metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new Error("transcript publication metadata is required");
  }
  if (!CID_PATTERN.test(metadata.artifact_sha256)) {
    throw new Error("transcript artifact_sha256 must be a canonical SHA-256 digest");
  }
  if (!Number.isSafeInteger(metadata.length) || metadata.length < 0) {
    throw new Error("transcript length must be a non-negative safe integer");
  }

  const payload = Buffer.from(bytes);
  if (payload.length !== metadata.length) throw new Error("transcript length metadata mismatch");
  const cid = cidOf(payload);
  if (cid !== metadata.artifact_sha256) throw new Error("transcript artifact_sha256 metadata mismatch");
  return { payload, cid };
}

function validateTxid(value, label) {
  if (typeof value !== "string" || !TXID_PATTERN.test(value)) {
    throw new Error(`${label} returned an invalid Arweave transaction id`);
  }
  return value;
}

export function arweaveTranscriptPublisher({
  findTxidsByCidImpl = findTxidsByCid,
  fetchFromArweaveImpl = fetchFromArweave,
  confirmArweaveTransactionImpl = confirmArweaveTransaction,
  uploadToArweaveImpl = uploadToArweave,
  ...options
} = {}) {
  if (typeof findTxidsByCidImpl !== "function") throw new Error("Arweave CID lookup must be a function");
  if (typeof fetchFromArweaveImpl !== "function") throw new Error("Arweave retrieval must be a function");
  if (typeof confirmArweaveTransactionImpl !== "function") throw new Error("Arweave confirmation must be a function");
  if (typeof uploadToArweaveImpl !== "function") throw new Error("Arweave upload must be a function");
  if (typeof options.owner !== "string" || !TXID_PATTERN.test(options.owner)) {
    throw new Error("Arweave transcript publisher requires the 43-character funded wallet owner address");
  }

  const publisher = {
    async publishTranscript(bytes, metadata) {
      const { payload, cid } = validateArtifact(bytes, metadata);
      let txid;
      const performUpload = async () => {
        const uploaded = await uploadToArweaveImpl(payload, {
          ...options,
          expectedOwner: options.owner,
          preparedTransaction: metadata.preparedTransaction,
          onPrepared: metadata.onPrepared,
          onPosted: metadata.onReceipt
            ? async ({ txid: acceptedTxid }) => metadata.onReceipt({
              uri: `ar://${validateTxid(acceptedTxid, "Arweave post")}`,
              artifact_sha256: cid,
              length: payload.length,
            })
            : undefined,
        });
        if (!uploaded || typeof uploaded !== "object" || Array.isArray(uploaded)) {
          throw new Error("Arweave upload returned a malformed result");
        }
        if (uploaded.cid !== cid) throw new Error("Arweave upload returned a mismatched CID");
        return validateTxid(uploaded.txid, "Arweave upload");
      };
      if (metadata.preparedTransaction !== undefined) {
        txid = await performUpload();
      } else {
        const found = await findTxidsByCidImpl(cid, { ...options, limit: options.limit ?? 10 });
        if (!Array.isArray(found)) throw new Error("Arweave CID lookup returned a malformed candidate list");
        let unavailable = 0;
        for (const value of found) {
          const candidate = validateTxid(value, "Arweave CID lookup");
          try {
            const existing = Buffer.from(await fetchFromArweaveImpl(candidate, {
              ...options,
              attemptsPerGateway: 1,
              pollMs: 0,
              networkTimeoutMs: options.candidateRetrievalTimeoutMs ?? 3_000,
            }));
            if (cidOf(existing) === cid) {
              txid = candidate;
              break;
            }
          } catch {
            unavailable += 1;
          }
        }
        if (txid === undefined) {
          if (unavailable > 0) {
            throw new Error("Arweave CID candidates are not yet retrievable; refusing a duplicate upload");
          }
          txid = await performUpload();
        }
      }

      return {
        uri: `ar://${txid}`,
        artifact_sha256: cid,
        length: payload.length,
      };
    },
    async confirmReceipt(bytes, receipt) {
      const { payload, cid } = validateArtifact(bytes, {
        artifact_sha256: receipt?.artifact_sha256,
        length: receipt?.length,
      });
      const txid = validateTxid(String(receipt?.uri ?? "").replace(/^ar:\/\//, ""), "Arweave receipt");
      const confirmed = await confirmArweaveTransactionImpl(payload, txid, options);
      if (confirmed?.cid !== cid || confirmed?.txid !== txid) {
        throw new Error("Arweave confirmation returned mismatched transcript identity");
      }
      return confirmed;
    },
  };
  return publisher;
}

export const createArweaveTranscriptPublisher = arweaveTranscriptPublisher;
