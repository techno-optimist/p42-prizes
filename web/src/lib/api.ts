import { NextResponse } from "next/server";
import { ZodError, type ZodType } from "zod";

const MAX_JSON_BYTES = 1_000_000;
const MUTABLE_HEADERS = {
  "Cache-Control": "no-store, max-age=0",
  "X-Content-Type-Options": "nosniff",
};
const DECODER = new TextDecoder();

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status = 400,
    readonly headers: HeadersInit = {},
    readonly body: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

export async function readJson<T>(req: Request, schema: ZodType<T>): Promise<T> {
  const contentLengthHeader = req.headers.get("content-length");
  const contentLength = contentLengthHeader === null ? undefined : Number(contentLengthHeader);
  if (contentLength !== undefined && Number.isFinite(contentLength) && contentLength > MAX_JSON_BYTES) {
    throw new ApiError("request body is too large", 413);
  }

  let body: unknown;
  try {
    const raw = await readBoundedBody(req);
    body = JSON.parse(raw);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError("malformed JSON body", 400);
  }

  try {
    return schema.parse(body);
  } catch (error) {
    if (error instanceof ZodError) {
      const first = error.issues[0];
      const path = first.path.length ? `${first.path.join(".")}: ` : "";
      throw new ApiError(`${path}${first.message}`, 400);
    }
    throw error;
  }
}

// The content-length header is advisory and attacker-controlled (omit it or lie
// low): stream the body and enforce the cap on bytes actually read so an
// unbounded payload can't be buffered before Zod's field-level limit applies.
async function readBoundedBody(req: Request): Promise<string> {
  if (!req.body) return "";

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_JSON_BYTES) {
      throw new ApiError("request body is too large", 413);
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return DECODER.decode(bytes);
}

export function json(data: unknown, init: ResponseInit = {}) {
  return NextResponse.json(data, {
    ...init,
    headers: {
      ...MUTABLE_HEADERS,
      ...(init.headers ?? {}),
    },
  });
}

export function apiError(error: unknown) {
  if (error instanceof ApiError) {
    return json({ error: error.message, ...error.body }, { status: error.status, headers: error.headers });
  }
  // Errors carrying an explicit public contract (e.g. VerifierInfraError) map to
  // their declared status; everything else is an unexpected server fault and
  // must not leak its raw message or masquerade as a client (4xx) error.
  const publicError = error as {
    publicStatus?: unknown;
    publicMessage?: unknown;
    publicCode?: unknown;
  };
  if (typeof publicError.publicStatus === "number") {
    return json(
      {
        error: typeof publicError.publicMessage === "string" ? publicError.publicMessage : "request failed",
        ...(typeof publicError.publicCode === "string" ? { code: publicError.publicCode } : {}),
      },
      { status: publicError.publicStatus },
    );
  }
  return json({ error: "request failed" }, { status: 500 });
}
