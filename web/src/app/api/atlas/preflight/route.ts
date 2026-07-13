import {
  ATLAS_PREFLIGHT_MAX_BODY_BYTES,
  AtlasPreflightInputError,
  assertNoDuplicateJsonKeys,
  computeAtlasPreflight,
  parseAtlasPreflightRequest,
} from "@/lib/atlas-preflight";
import { json } from "@/lib/api";

const DECODER = new TextDecoder("utf-8", { fatal: true });

async function readBoundedBody(request: Request): Promise<string> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const parsed = Number(declaredLength);
    if (Number.isFinite(parsed) && parsed > ATLAS_PREFLIGHT_MAX_BODY_BYTES) {
      throw new AtlasPreflightInputError("request body is too large", 413);
    }
  }
  if (!request.body) throw new AtlasPreflightInputError("request body is required");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > ATLAS_PREFLIGHT_MAX_BODY_BYTES) {
      await reader.cancel();
      throw new AtlasPreflightInputError("request body is too large", 413);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return DECODER.decode(bytes);
  } catch {
    throw new AtlasPreflightInputError("request body must be valid UTF-8");
  }
}

export async function POST(request: Request) {
  try {
    const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== "application/json") {
      throw new AtlasPreflightInputError("content-type must be application/json", 415);
    }
    const raw = await readBoundedBody(request);
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
      assertNoDuplicateJsonKeys(raw);
    } catch (error) {
      if (error instanceof AtlasPreflightInputError) throw error;
      throw new AtlasPreflightInputError("malformed JSON body");
    }
    return json(computeAtlasPreflight(parseAtlasPreflightRequest(parsed)));
  } catch (error) {
    if (error instanceof AtlasPreflightInputError) {
      return json({ error: error.message, code: "INVALID_REQUEST" }, { status: error.status });
    }
    throw error;
  }
}
