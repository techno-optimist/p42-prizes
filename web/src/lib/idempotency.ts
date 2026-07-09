import { createHash, randomUUID } from "node:crypto";
import { ApiError, json } from "@/lib/api";
import {
  appendPortalEvent,
  assertPortalCapacity,
  portalLifecyclePolicy,
  updatePortalState,
  type PortalStateSnapshot,
} from "@/lib/portal-store";

const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,128}$/;

export interface IdempotencyReservation {
  key: string;
  route: string;
  requestHash: string;
  reservationId: string;
}

export interface IdempotencyAttempt {
  reservation?: IdempotencyReservation;
  replay?: Response;
}

type ReservationOutcome =
  | { kind: "reserved" }
  | { kind: "replay"; response: unknown; status: number }
  | { kind: "conflict"; originalRequestHash: string }
  | { kind: "pending"; retryAfterSeconds: number };

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

export function beginIdempotentRequest(req: Request, route: string, payload: unknown): IdempotencyAttempt {
  const key = idempotencyKey(req);
  if (!key) return {};

  const hash = requestHash(payload);
  const reservationId = randomUUID();
  const now = Date.now();
  const leaseExpiresAt = new Date(now + portalLifecyclePolicy().idempotencyLeaseMs).toISOString();
  const outcome: { current: ReservationOutcome } = { current: { kind: "reserved" } };

  updatePortalState((state) => {
    const existing = state.idempotency.find((entry) => entry.route === route && entry.key === key);
    if (!existing) {
      assertPortalCapacity(state, "idempotency");
      state.idempotency.push({
        key,
        route,
        requestHash: hash,
        state: "pending",
        createdAt: new Date(now).toISOString(),
        reservationId,
        leaseExpiresAt,
      });
      return;
    }

    if (existing.requestHash !== hash) {
      outcome.current = { kind: "conflict", originalRequestHash: existing.requestHash };
      appendPortalEvent(state, {
        type: "idempotency.conflict",
        subjectId: key,
        payload: { route, key, requestHash: hash, originalRequestHash: existing.requestHash },
      });
      return;
    }

    if (existing.state === "completed") {
      if (existing.status === undefined) throw new Error("completed idempotency record is missing its status");
      outcome.current = { kind: "replay", response: existing.response, status: existing.status };
      appendPortalEvent(state, {
        type: "idempotency.replayed",
        subjectId: key,
        payload: { route, key, requestHash: hash, status: existing.status },
      });
      return;
    }

    const currentLease = existing.leaseExpiresAt ? Date.parse(existing.leaseExpiresAt) : Number.NaN;
    if (Number.isFinite(currentLease) && currentLease > now) {
      outcome.current = { kind: "pending", retryAfterSeconds: Math.max(1, Math.ceil((currentLease - now) / 1000)) };
      return;
    }

    existing.reservationId = reservationId;
    existing.leaseExpiresAt = leaseExpiresAt;
    existing.createdAt = new Date(now).toISOString();
  });

  const resolved = outcome.current;
  if (resolved.kind === "conflict") {
    throw new ApiError("Idempotency-Key was already used for a different request body", 409);
  }
  if (resolved.kind === "pending") {
    throw new ApiError("an idempotent request with this key is already in progress", 409, {
      "Retry-After": String(resolved.retryAfterSeconds),
      "Idempotency-Status": "pending",
    });
  }
  if (resolved.kind === "replay") {
    return {
      replay: json(resolved.response, {
        status: resolved.status,
        headers: { "Idempotency-Status": "replayed", "Idempotency-Key": key },
      }),
    };
  }
  return { reservation: { key, route, requestHash: hash, reservationId } };
}

export function completeIdempotentOperation<T>(
  reservation: IdempotencyReservation | undefined,
  status: number | ((response: T) => number),
  operation: (state: PortalStateSnapshot) => T,
): { response: T; status: number; headers: HeadersInit } {
  let response!: T;
  let responseStatus!: number;
  updatePortalState((state) => {
    if (!reservation) {
      response = operation(state);
      responseStatus = typeof status === "function" ? status(response) : status;
      return;
    }

    const existing = state.idempotency.find(
      (entry) => entry.route === reservation.route && entry.key === reservation.key,
    );
    if (
      !existing
      || existing.state !== "pending"
      || existing.requestHash !== reservation.requestHash
      || existing.reservationId !== reservation.reservationId
    ) {
      throw new ApiError("idempotency reservation was lost; retry the request", 409);
    }

    response = operation(state);
    responseStatus = typeof status === "function" ? status(response) : status;
    existing.state = "completed";
    existing.status = responseStatus;
    existing.response = response;
    delete existing.reservationId;
    delete existing.leaseExpiresAt;
    appendPortalEvent(state, {
      type: "idempotency.stored",
      subjectId: reservation.key,
      payload: {
        route: reservation.route,
        key: reservation.key,
        requestHash: reservation.requestHash,
        status: responseStatus,
      },
    });
  });

  return {
    response,
    status: responseStatus,
    headers: reservation
      ? { "Idempotency-Status": "stored", "Idempotency-Key": reservation.key }
      : {},
  };
}

export function releaseIdempotencyReservation(reservation: IdempotencyReservation | undefined): void {
  if (!reservation) return;
  updatePortalState((state) => {
    const index = state.idempotency.findIndex(
      (entry) => entry.route === reservation.route
        && entry.key === reservation.key
        && entry.state === "pending"
        && entry.reservationId === reservation.reservationId,
    );
    if (index >= 0) state.idempotency.splice(index, 1);
  });
}
