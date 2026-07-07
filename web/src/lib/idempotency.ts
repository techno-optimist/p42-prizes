import { createHash } from "node:crypto";
import { ApiError, json } from "@/lib/api";
import { appendPortalEvent, readPortalState, updatePortalState } from "@/lib/portal-store";

const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,128}$/;

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

export function idempotencyKey(req: Request): string | undefined {
  const key = req.headers.get("Idempotency-Key")?.trim();
  if (!key) return undefined;
  if (!IDEMPOTENCY_KEY.test(key)) {
    throw new ApiError("Idempotency-Key must be 8-128 chars of letters, numbers, dot, underscore, colon, or dash", 400);
  }
  return key;
}

export function requestHash(payload: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex")}`;
}

export function replayIdempotentResponse(req: Request, route: string, payload: unknown): Response | undefined {
  const key = idempotencyKey(req);
  if (!key) return undefined;

  const hash = requestHash(payload);
  const record = readPortalState().idempotency.find((entry) => entry.route === route && entry.key === key);
  if (!record) return undefined;
  if (record.requestHash !== hash) {
    updatePortalState((state) => {
      appendPortalEvent(state, {
        type: "idempotency.conflict",
        subjectId: key,
        payload: {
          route,
          key,
          requestHash: hash,
          originalRequestHash: record.requestHash,
        },
      });
    });
    throw new ApiError("Idempotency-Key was already used for a different request body", 409);
  }

  updatePortalState((state) => {
    appendPortalEvent(state, {
      type: "idempotency.replayed",
      subjectId: key,
      payload: {
        route,
        key,
        requestHash: hash,
        status: record.status,
      },
    });
  });

  return json(record.response, {
    status: record.status,
    headers: {
      "Idempotency-Status": "replayed",
      "Idempotency-Key": key,
    },
  });
}

export function rememberIdempotentResponse(
  req: Request,
  route: string,
  payload: unknown,
  response: unknown,
  status: number,
): HeadersInit {
  const key = idempotencyKey(req);
  if (!key) return {};

  const hash = requestHash(payload);
  updatePortalState((state) => {
    const existing = state.idempotency.find((entry) => entry.route === route && entry.key === key);
    if (existing) {
      if (existing.requestHash !== hash) {
        appendPortalEvent(state, {
          type: "idempotency.conflict",
          subjectId: key,
          payload: {
            route,
            key,
            requestHash: hash,
            originalRequestHash: existing.requestHash,
          },
        });
        throw new ApiError("Idempotency-Key was already used for a different request body", 409);
      }
      existing.response = response;
      existing.status = status;
      return;
    }
    state.idempotency.push({
      key,
      route,
      requestHash: hash,
      response,
      status,
      createdAt: new Date().toISOString(),
    });
    appendPortalEvent(state, {
      type: "idempotency.stored",
      subjectId: key,
      payload: {
        route,
        key,
        requestHash: hash,
        status,
      },
    });
  });

  return {
    "Idempotency-Status": "stored",
    "Idempotency-Key": key,
  };
}
