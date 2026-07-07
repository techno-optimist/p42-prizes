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
  if (record.state === "cancelled") return undefined;
  if ((record.state ?? "completed") === "pending") {
    throw new ApiError("Idempotency-Key request is already in progress", 409);
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

export function reserveIdempotentRequest(req: Request, route: string, payload: unknown): Response | undefined {
  const key = idempotencyKey(req);
  if (!key) return undefined;

  const hash = requestHash(payload);
  let replayRecord: { response: unknown; status: number } | undefined;
  let error: ApiError | undefined;
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
        error = new ApiError("Idempotency-Key was already used for a different request body", 409);
        return;
      }
      if ((existing.state ?? "completed") === "pending") {
        error = new ApiError("Idempotency-Key request is already in progress", 409);
        return;
      }
      if (existing.state === "cancelled") {
        existing.state = "pending";
        existing.response = null;
        existing.status = 0;
        delete existing.completedAt;
        delete existing.cancelledAt;
        appendPortalEvent(state, {
          type: "idempotency.reserved",
          subjectId: key,
          payload: {
            route,
            key,
            requestHash: hash,
          },
        });
        return;
      }
      replayRecord = { response: existing.response, status: existing.status };
      appendPortalEvent(state, {
        type: "idempotency.replayed",
        subjectId: key,
        payload: {
          route,
          key,
          requestHash: hash,
          status: existing.status,
        },
      });
      return;
    }

    state.idempotency.push({
      key,
      route,
      requestHash: hash,
      state: "pending",
      response: null,
      status: 0,
      createdAt: new Date().toISOString(),
    });
    appendPortalEvent(state, {
      type: "idempotency.reserved",
      subjectId: key,
      payload: {
        route,
        key,
        requestHash: hash,
      },
    });
  });

  if (error) throw error;
  if (!replayRecord) return undefined;
  return json(replayRecord.response, {
    status: replayRecord.status,
    headers: {
      "Idempotency-Status": "replayed",
      "Idempotency-Key": key,
    },
  });
}

export function cancelIdempotentReservation(req: Request, route: string, payload: unknown, reason: string): void {
  const key = idempotencyKey(req);
  if (!key) return;

  const hash = requestHash(payload);
  updatePortalState((state) => {
    const existing = state.idempotency.find((entry) => entry.route === route && entry.key === key);
    if (!existing || existing.requestHash !== hash || existing.state !== "pending") return;

    existing.state = "cancelled";
    existing.status = 0;
    existing.response = null;
    existing.cancelledAt = new Date().toISOString();
    appendPortalEvent(state, {
      type: "idempotency.cancelled",
      subjectId: key,
      payload: {
        route,
        key,
        requestHash: hash,
        reason,
      },
    });
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
  let error: ApiError | undefined;
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
        error = new ApiError("Idempotency-Key was already used for a different request body", 409);
        return;
      }
      existing.response = response;
      existing.status = status;
      existing.state = "completed";
      existing.completedAt = new Date().toISOString();
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
      return;
    }
    state.idempotency.push({
      key,
      route,
      requestHash: hash,
      state: "completed",
      response,
      status,
      createdAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
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

  if (error) throw error;
  return {
    "Idempotency-Status": "stored",
    "Idempotency-Key": key,
  };
}
