import { z } from "zod";
import { describe, expect, it } from "vitest";
import { readJson } from "@/lib/api";

function jsonRequest(body: string, headers: Record<string, string> = {}) {
  return new Request("http://localhost/api/test", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
}

describe("readJson", () => {
  it("parses valid JSON through the supplied schema", async () => {
    await expect(
      readJson(jsonRequest('{"name":"CHRONOS"}'), z.object({ name: z.string() })),
    ).resolves.toEqual({ name: "CHRONOS" });
  });

  it("enforces the byte cap when content-length is absent", async () => {
    const body = JSON.stringify({ solution_raw: "x".repeat(1_200_000) });
    await expect(readJson(jsonRequest(body), z.object({ solution_raw: z.string() }))).rejects.toMatchObject({
      message: "request body is too large",
      status: 413,
    });
  });

  it("enforces the byte cap when content-length is spoofed low", async () => {
    const body = JSON.stringify({ solution_raw: "x".repeat(1_200_000) });
    await expect(
      readJson(jsonRequest(body, { "content-length": "10" }), z.object({ solution_raw: z.string() })),
    ).rejects.toMatchObject({
      message: "request body is too large",
      status: 413,
    });
  });
});
