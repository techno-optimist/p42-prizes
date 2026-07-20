// @vitest-environment jsdom

import { act, cleanup, render, screen } from "@testing-library/react";
import { renderToString } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  FundingPanel,
  sameCheckpointObservation,
  type FundingPanelProps,
} from "@/components/FundingPanel";

const SLUG = "test-board";
const ADDRESS = `0x${"7".repeat(40)}`;
const CHECKPOINT_DIGEST = `sha256:${"6".repeat(64)}`;
const FINALIZED = "2026-01-04T00:00:00.000Z";

function props(overrides: Partial<FundingPanelProps> = {}): FundingPanelProps {
  return {
    slug: SLUG,
    fundingTargetDeployed: true,
    authorizationExpiresAt: "2026-12-01T00:00:00.000Z",
    finalizedObservedAt: FINALIZED,
    fundingDeadline: "2026-06-01T00:00:00.000Z",
    remainingCapWei: "1000000000000000000",
    serverObservedAt: FINALIZED,
    fundingAuthorizationDigest: `sha256:${"4".repeat(64)}`,
    activationCompletionDigest: `sha256:${"5".repeat(64)}`,
    checkpointBlock: 100,
    checkpointDigest: CHECKPOINT_DIGEST,
    activationFinalizedBlock: 99,
    label: "Test pool",
    ...overrides,
  };
}

function phase0Response(overrides: Record<string, unknown> = {}) {
  return {
    schema: "p42-prizes/funding-target/v3",
    slug: SLUG,
    authorizationExpiresAt: "2026-12-01T00:00:00.000Z",
    finalizedObservedAt: FINALIZED,
    fundingDeadline: "2026-06-01T00:00:00.000Z",
    remainingCapWei: "1000000000000000000",
    serverObservedAt: FINALIZED,
    fundingAuthorizationDigest: `sha256:${"4".repeat(64)}`,
    activationCompletionDigest: `sha256:${"5".repeat(64)}`,
    checkpointBlock: 100,
    checkpointDigest: CHECKPOINT_DIGEST,
    activationFinalizedBlock: 99,
    target: null,
    ...overrides,
  };
}

function activeV4Response() {
  const { fundingAuthorizationDigest: _v3Digest, ...base } = phase0Response();
  return {
    ...base,
    schema: "p42-prizes/funding-target/v4",
    authorizationBinding: {
      schema: "p42-production-launch-authorization/v2",
      authorizationDigest: `sha256:${"4".repeat(64)}`,
      authorizationBytesDigest: `sha256:${"9".repeat(64)}`,
      legalArtifactsDigest: `sha256:${"a".repeat(64)}`,
    },
    target: {
      address: ADDRESS,
      asset: "ETH",
      chain: "Base Sepolia",
      chainId: 84532,
      explorerUrl: `https://sepolia.basescan.org/address/${ADDRESS}`,
      walletUri: `ethereum:${ADDRESS}@84532`,
      releaseArtifacts: {
        terms: { uri: "https://legal.example/terms", sha256: `sha256:${"b".repeat(64)}` },
        privacy: { uri: "https://legal.example/privacy", sha256: `sha256:${"c".repeat(64)}` },
        risk: { uri: "https://legal.example/risk", sha256: `sha256:${"d".repeat(64)}` },
        eligibility: { uri: "https://legal.example/eligibility", sha256: `sha256:${"e".repeat(64)}` },
      },
    },
  };
}

function response(body: unknown): Response {
  return { ok: true, json: async () => body } as Response;
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

function expectNoActionableMaterial() {
  expect(document.body.textContent).not.toContain(ADDRESS);
  expect(document.body.innerHTML).not.toContain("ethereum:");
  expect(document.body.innerHTML.toLowerCase()).not.toContain("basescan");
  expect(screen.queryByRole("checkbox")).toBeNull();
  expect(screen.queryByRole("link", { name: /fund|wallet|basescan/i })).toBeNull();
}

describe("FundingPanel dormant funding boundary", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(FINALIZED);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(phase0Response())));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("server-renders no destination or action", () => {
    const html = renderToString(<FundingPanel {...props()} />);
    expect(html).toContain("checking funding availability");
    expect(html).not.toContain(ADDRESS);
    expect(html).not.toContain("ethereum:");
    expect(html.toLowerCase()).not.toContain("basescan");
  });

  it("accepts only the exact v3 null envelope and remains unavailable", async () => {
    render(<FundingPanel {...props()} />);
    await flush();
    expect(screen.getByText("funding unavailable")).toBeTruthy();
    expectNoActionableMaterial();
  });

  it("rejects an arbitrary active v4 response even with future-looking binding labels", async () => {
    vi.mocked(fetch).mockResolvedValue(response(activeV4Response()));
    render(<FundingPanel {...props()} />);
    await flush();
    expect(screen.getByText("funding unavailable")).toBeTruthy();
    expectNoActionableMaterial();
  });

  it("rejects an actionable target smuggled into v3", async () => {
    vi.mocked(fetch).mockResolvedValue(response({ ...activeV4Response(), schema: "p42-prizes/funding-target/v3" }));
    render(<FundingPanel {...props()} />);
    await flush();
    expectNoActionableMaterial();
  });

  it("rejects extra actionable keys on the null envelope", async () => {
    vi.mocked(fetch).mockResolvedValue(response({ ...phase0Response(), walletUri: `ethereum:${ADDRESS}@84532` }));
    render(<FundingPanel {...props()} />);
    await flush();
    expectNoActionableMaterial();
  });

  it("does not fetch after the funding deadline", () => {
    vi.setSystemTime("2026-06-01T00:00:00.000Z");
    render(<FundingPanel {...props({ serverObservedAt: "2026-06-01T00:00:00.000Z" })} />);
    expect(fetch).not.toHaveBeenCalled();
    expectNoActionableMaterial();
  });

  it("requires finalizedObservedAt to remain exact for one checkpoint identity", () => {
    const expected = { checkpointBlock: 100, checkpointDigest: CHECKPOINT_DIGEST, finalizedObservedAt: FINALIZED };
    expect(sameCheckpointObservation(expected, expected)).toBe(true);
    expect(sameCheckpointObservation({
      ...expected,
      finalizedObservedAt: "2026-01-04T00:00:01.000Z",
    }, expected)).toBe(false);
    expect(sameCheckpointObservation({
      ...expected,
      finalizedObservedAt: "2026-01-03T23:59:59.000Z",
    }, expected)).toBe(false);
  });
});
