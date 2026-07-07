import { NextResponse } from "next/server";
import { ZodError, type ZodType } from "zod";

const MAX_JSON_BYTES = 1_000_000;
const MUTABLE_HEADERS = {
  "Cache-Control": "no-store, max-age=0",
  "X-Content-Type-Options": "nosniff",
};

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
  const contentLength = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_JSON_BYTES) {
    throw new ApiError("request body is too large", 413);
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
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
