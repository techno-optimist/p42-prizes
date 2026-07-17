// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { hydrateRoot, type Root } from "react-dom/client";
import { renderToString } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FundingPanel, type FundingPanelProps } from "@/components/FundingPanel";

const SLUG = "test-board";
const B_SLUG = "second-board";
const ADDRESS = `0x${"7".repeat(40)}`;
const B_ADDRESS = `0x${"6".repeat(40)}`;
const DEADLINE_MS = 2_000_000;
const OBSERVED_MS = DEADLINE_MS - 1_000;
const AUTHORIZATION_EXPIRY_MS = DEADLINE_MS + 10_000;
const FINALIZED_MS = OBSERVED_MS - 100;
const WALLET_URI = `ethereum:${ADDRESS}@84532`;

function props(overrides: Partial<FundingPanelProps> = {}): FundingPanelProps {
  return {
    slug: SLUG,
    fundingTargetDeployed: true,
    authorizationExpiresAt: new Date(AUTHORIZATION_EXPIRY_MS).toISOString(),
    finalizedObservedAt: new Date(FINALIZED_MS).toISOString(),
    fundingDeadline: new Date(DEADLINE_MS).toISOString(),
    remainingCapWei: "1000000000000000000",
    serverObservedAt: new Date(OBSERVED_MS).toISOString(),
    label: "Test pool",
    ...overrides,
  };
}

function responseBody({
  slug = SLUG,
  address = ADDRESS,
  fundingDeadline = DEADLINE_MS,
  serverObservedAt = OBSERVED_MS,
  remainingCapWei = "1000000000000000000",
  target = true,
}: {
  slug?: string;
  address?: string;
  fundingDeadline?: number;
  serverObservedAt?: number;
  remainingCapWei?: string;
  target?: boolean;
} = {}) {
  return {
    schema: "p42-prizes/funding-target/v2",
    slug,
    authorizationExpiresAt: new Date(AUTHORIZATION_EXPIRY_MS).toISOString(),
    finalizedObservedAt: new Date(FINALIZED_MS).toISOString(),
    fundingDeadline: new Date(fundingDeadline).toISOString(),
    remainingCapWei,
    serverObservedAt: new Date(serverObservedAt).toISOString(),
    target: target ? {
      address,
      asset: "ETH",
      chain: "Base Sepolia",
      chainId: 84532,
      explorerUrl: `https://sepolia.basescan.org/address/${address}`,
      walletUri: `ethereum:${address}@84532`,
    } : null,
  };
}

function okResponse(body: unknown = responseBody()) {
  return { ok: true, json: async () => body } as Response;
}

function deferredResponse() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>((done) => { resolve = done; });
  return { promise, resolve };
}

async function flushResponse() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function renderAndReveal() {
  render(<FundingPanel {...props()} />);
  expect(screen.getByText("checking funding availability")).toBeTruthy();
  expectTargetClearedFromDom();
  await flushResponse();
  expectTargetVisible();
}

function expectTargetVisible(address = ADDRESS) {
  expect(screen.getByText(address)).toBeTruthy();
  expect(document.querySelector(`a[href="ethereum:${address}@84532"]`)).not.toBeNull();
}

function expectTargetClearedFromDom() {
  expect(screen.queryByText(ADDRESS)).toBeNull();
  expect(document.querySelector(`a[href="${WALLET_URI}"]`)).toBeNull();
  expect(document.body.textContent).not.toContain(ADDRESS);
  expect(document.body.innerHTML).not.toContain(WALLET_URI);
}

function expectTargetUnavailable() {
  expectTargetClearedFromDom();
  expect(screen.getByText("funding unavailable")).toBeTruthy();
  expect(screen.getByText(/conservatively stops publishing funding targets/)).toBeTruthy();
}

function serverMarkup() {
  return renderToString(<FundingPanel {...props()} />);
}

function hydrationErrors(spy: ReturnType<typeof vi.spyOn>) {
  return spy.mock.calls.flatMap((call) => call.map(String)).filter((message) => /hydrat/i.test(message));
}

describe("FundingPanel deadline reconciliation", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(OBSERVED_MS);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(okResponse()));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("server-renders only non-address Flight props and a deterministic checking state", () => {
    const html = serverMarkup();
    expect(JSON.stringify(props())).not.toContain(ADDRESS);
    expect(JSON.stringify(props())).not.toContain("84532");
    expect(html).toContain("checking funding availability");
    expect(html).toContain("No transfer target is published");
    expect(html).not.toContain(ADDRESS);
    expect(html).not.toContain(WALLET_URI);
  });

  it("never fetches or reveals a target when hydration is delayed across D", async () => {
    const container = document.createElement("div");
    container.innerHTML = serverMarkup();
    document.body.append(container);
    vi.setSystemTime(DEADLINE_MS);
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    let root: Root | undefined;

    await act(async () => {
      root = hydrateRoot(container, <FundingPanel {...props()} />);
      await Promise.resolve();
    });

    expectTargetUnavailable();
    expect(fetch).not.toHaveBeenCalled();
    expect(hydrationErrors(consoleError)).toEqual([]);
    act(() => root?.unmount());
    container.remove();
  });

  it("reveals only after before-D hydration installs guards and validates the endpoint response", async () => {
    const container = document.createElement("div");
    container.innerHTML = serverMarkup();
    document.body.append(container);
    expect(container.innerHTML).not.toContain(ADDRESS);
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    let root: Root | undefined;

    await act(async () => {
      root = hydrateRoot(container, <FundingPanel {...props()} />);
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(fetch).toHaveBeenCalledWith(`/api/problems/${SLUG}/funding-target`, expect.objectContaining({
      cache: "no-store",
      credentials: "same-origin",
    }));
    expectTargetVisible();
    expect(hydrationErrors(consoleError)).toEqual([]);
    act(() => vi.advanceTimersByTime(1_000));
    expectTargetUnavailable();
    act(() => root?.unmount());
    container.remove();
  });

  it("discards a delayed response that crosses D without ever revealing", async () => {
    let resolveFetch!: (response: Response) => void;
    vi.mocked(fetch).mockReturnValue(new Promise((resolve) => { resolveFetch = resolve; }));
    render(<FundingPanel {...props()} />);
    expectTargetClearedFromDom();

    vi.setSystemTime(DEADLINE_MS);
    resolveFetch(okResponse());
    await flushResponse();

    expectTargetUnavailable();
  });

  it("cannot reveal when Date.now advances between response checks and setup", async () => {
    let resolveFetch!: (response: Response) => void;
    vi.mocked(fetch).mockReturnValue(new Promise((resolve) => { resolveFetch = resolve; }));
    render(<FundingPanel {...props()} />);
    const now = vi.spyOn(Date, "now");
    now.mockReturnValueOnce(OBSERVED_MS).mockReturnValueOnce(OBSERVED_MS)
      .mockReturnValueOnce(OBSERVED_MS).mockReturnValue(DEADLINE_MS);

    resolveFetch(okResponse());
    await flushResponse();

    expectTargetUnavailable();
  });

  it("fails closed on a malformed or over-broad endpoint envelope", async () => {
    vi.mocked(fetch).mockResolvedValue(okResponse({ ...responseBody(), unexpected: ADDRESS }));
    render(<FundingPanel {...props()} />);
    await flushResponse();

    expectTargetClearedFromDom();
    expect(screen.getByText("funding unavailable")).toBeTruthy();
  });

  it("suppresses visible A synchronously while rerendered binding B is pending, then reveals B", async () => {
    const { rerender } = render(<FundingPanel {...props()} />);
    await flushResponse();
    expectTargetVisible();
    const pendingB = deferredResponse();
    vi.mocked(fetch).mockReturnValueOnce(pendingB.promise);

    rerender(<FundingPanel {...props({ slug: B_SLUG })} />);
    expectTargetClearedFromDom();
    expect(screen.getByText("checking funding availability")).toBeTruthy();

    pendingB.resolve(okResponse(responseBody({ slug: B_SLUG, address: B_ADDRESS })));
    await flushResponse();
    expectTargetVisible(B_ADDRESS);
  });

  it("discards a late A response after rerendering to pending B", async () => {
    const pendingA = deferredResponse();
    const pendingB = deferredResponse();
    vi.mocked(fetch).mockReturnValueOnce(pendingA.promise).mockReturnValueOnce(pendingB.promise);
    const { rerender } = render(<FundingPanel {...props()} />);
    rerender(<FundingPanel {...props({ slug: B_SLUG })} />);

    pendingA.resolve(okResponse());
    await flushResponse();
    expectTargetClearedFromDom();

    pendingB.resolve(okResponse(responseBody({ slug: B_SLUG, address: B_ADDRESS })));
    await flushResponse();
    expectTargetVisible(B_ADDRESS);
  });

  it("suppresses a target when the same slug receives a new deadline/observation binding", async () => {
    const { rerender } = render(<FundingPanel {...props()} />);
    await flushResponse();
    expectTargetVisible();
    const newDeadline = DEADLINE_MS + 5_000;
    const newObserved = OBSERVED_MS + 500;
    const pending = deferredResponse();
    vi.mocked(fetch).mockReturnValueOnce(pending.promise);

    rerender(<FundingPanel {...props({
      fundingDeadline: new Date(newDeadline).toISOString(),
      serverObservedAt: new Date(newObserved).toISOString(),
    })} />);
    expectTargetClearedFromDom();

    pending.resolve(okResponse(responseBody({
      address: B_ADDRESS,
      fundingDeadline: newDeadline,
      serverObservedAt: newObserved,
    })));
    await flushResponse();
    expectTargetVisible(B_ADDRESS);
  });

  it("blocks stale A click/copy handlers without aborting pending B", async () => {
    const clipboardWrite = vi.fn();
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: clipboardWrite } });
    const { rerender } = render(<FundingPanel {...props()} />);
    await flushResponse();
    const staleLink = document.querySelector(`a[href="${WALLET_URI}"]`)!;
    const staleCopy = screen.getByRole("button", { name: "Copy sponsor pool address" });
    const linkPropsKey = Object.keys(staleLink).find((key) => key.startsWith("__reactProps$"))!;
    const copyPropsKey = Object.keys(staleCopy).find((key) => key.startsWith("__reactProps$"))!;
    const staleLinkHandler = (staleLink as unknown as Record<string, { onClick: (event: { preventDefault: () => void }) => void }>)[linkPropsKey].onClick;
    const staleCopyHandler = (staleCopy as unknown as Record<string, { onClick: () => Promise<void> }>)[copyPropsKey].onClick;
    const pendingB = deferredResponse();
    vi.mocked(fetch).mockReturnValueOnce(pendingB.promise);

    rerender(<FundingPanel {...props({ slug: B_SLUG })} />);
    const preventDefault = vi.fn();
    staleLinkHandler({ preventDefault });
    await staleCopyHandler();
    expect(preventDefault).toHaveBeenCalledOnce();
    expect(clipboardWrite).not.toHaveBeenCalled();
    expectTargetClearedFromDom();

    pendingB.resolve(okResponse(responseBody({ slug: B_SLUG, address: B_ADDRESS })));
    await flushResponse();
    expectTargetVisible(B_ADDRESS);
  });

  it("ignores a deferred clipboard completion from binding A after B is visible", async () => {
    let resolveClipboard!: () => void;
    const clipboardWrite = vi.fn(() => new Promise<void>((resolve) => { resolveClipboard = resolve; }));
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: clipboardWrite } });
    const { rerender } = render(<FundingPanel {...props()} />);
    await flushResponse();

    fireEvent.click(screen.getByRole("button", { name: "Copy sponsor pool address" }));
    expect(clipboardWrite).toHaveBeenCalledWith(ADDRESS);
    const pendingB = deferredResponse();
    vi.mocked(fetch).mockReturnValueOnce(pendingB.promise);
    rerender(<FundingPanel {...props({ slug: B_SLUG })} />);
    pendingB.resolve(okResponse(responseBody({ slug: B_SLUG, address: B_ADDRESS })));
    await flushResponse();
    expectTargetVisible(B_ADDRESS);

    resolveClipboard();
    await flushResponse();
    expect(screen.getByRole("button", { name: "Copy sponsor pool address" }).textContent).toBe("copy");
    expectTargetVisible(B_ADDRESS);
  });

  it("does not let binding A's reset timer clear binding B's copy feedback", async () => {
    const longDeadline = DEADLINE_MS + 10_000;
    const clipboardWrite = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: clipboardWrite } });
    vi.mocked(fetch).mockResolvedValueOnce(okResponse(responseBody({ fundingDeadline: longDeadline })));
    const longProps = props({ fundingDeadline: new Date(longDeadline).toISOString() });
    const { rerender } = render(<FundingPanel {...longProps} />);
    await flushResponse();

    fireEvent.click(screen.getByRole("button", { name: "Copy sponsor pool address" }));
    await flushResponse();
    expect(screen.getByRole("button", { name: "Copy sponsor pool address" }).textContent).toBe("copied");
    act(() => vi.advanceTimersByTime(800));

    vi.mocked(fetch).mockResolvedValueOnce(okResponse(responseBody({
      slug: B_SLUG,
      address: B_ADDRESS,
      fundingDeadline: longDeadline,
    })));
    rerender(<FundingPanel {...longProps} slug={B_SLUG} />);
    await flushResponse();
    expectTargetVisible(B_ADDRESS);
    fireEvent.click(screen.getByRole("button", { name: "Copy sponsor pool address" }));
    await flushResponse();
    expect(screen.getByRole("button", { name: "Copy sponsor pool address" }).textContent).toBe("copied");

    act(() => vi.advanceTimersByTime(800));
    expect(screen.getByRole("button", { name: "Copy sponsor pool address" }).textContent).toBe("copied");
    act(() => vi.advanceTimersByTime(800));
    expect(screen.getByRole("button", { name: "Copy sponsor pool address" }).textContent).toBe("copy");
  });

  it("clears prior success while a same-binding retry is pending or rejected", async () => {
    let rejectRetry!: (reason?: unknown) => void;
    const retry = new Promise<void>((_resolve, reject) => { rejectRetry = reject; });
    const clipboardWrite = vi.fn()
      .mockResolvedValueOnce(undefined)
      .mockReturnValueOnce(retry);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: clipboardWrite } });
    render(<FundingPanel {...props()} />);
    await flushResponse();

    const copyButton = screen.getByRole("button", { name: "Copy sponsor pool address" });
    fireEvent.click(copyButton);
    await flushResponse();
    expect(copyButton.textContent).toBe("copied");

    fireEvent.click(copyButton);
    expect(copyButton.textContent).toBe("copy");
    rejectRetry(new Error("clipboard denied"));
    await flushResponse();
    expect(copyButton.textContent).toBe("copy");
    expect(clipboardWrite).toHaveBeenCalledTimes(2);
  });

  it("does not report success when the clipboard API is unavailable", async () => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    render(<FundingPanel {...props()} />);
    await flushResponse();

    const copyButton = screen.getByRole("button", { name: "Copy sponsor pool address" });
    fireEvent.click(copyButton);
    await flushResponse();
    expect(copyButton.textContent).toBe("copy");
  });

  it("clears at D using the server-derived monotonic budget with a skewed client wall clock", async () => {
    vi.setSystemTime(OBSERVED_MS - 10_000);
    await renderAndReveal();
    act(() => vi.advanceTimersByTime(999));
    expectTargetVisible();
    act(() => vi.advanceTimersByTime(1));
    expectTargetUnavailable();
  });

  it("clears a suspended background tab on visibilitychange after D", async () => {
    const skewedClientStart = OBSERVED_MS - 10_000;
    vi.setSystemTime(skewedClientStart);
    await renderAndReveal();
    vi.setSystemTime(skewedClientStart + 1_001);
    fireEvent(document, new Event("visibilitychange"));
    expectTargetUnavailable();
  });

  it.each(["focus", "pageshow"])("clears a resumed tab on %s after D", async (eventName) => {
    await renderAndReveal();
    vi.setSystemTime(DEADLINE_MS + 1);
    fireEvent(window, new Event(eventName));
    expectTargetUnavailable();
  });

  it("atomically hides a stale target while focus revalidation observes an exhausted cap", async () => {
    await renderAndReveal();
    const pending = deferredResponse();
    vi.mocked(fetch).mockReturnValueOnce(pending.promise);

    fireEvent(window, new Event("focus"));
    expectTargetClearedFromDom();
    expect(screen.getByText("checking funding availability")).toBeTruthy();

    pending.resolve(okResponse(responseBody({ remainingCapWei: "0", target: false })));
    await flushResponse();
    expectTargetClearedFromDom();
    expect(screen.getByText("funding unavailable")).toBeTruthy();
  });

  it("blocks and clears a wallet click at the exact boundary", async () => {
    await renderAndReveal();
    const walletLink = document.querySelector(`a[href="${WALLET_URI}"]`)!;
    vi.setSystemTime(DEADLINE_MS);
    expect(fireEvent.click(walletLink)).toBe(false);
    expectTargetUnavailable();
  });

  it("revalidates the exact target after click before launching the wallet", async () => {
    await renderAndReveal();
    const walletLink = document.querySelector(`a[href="${WALLET_URI}"]`)!;
    const launch = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    expect(fireEvent.click(walletLink)).toBe(false);
    expectTargetClearedFromDom();
    await flushResponse();

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch).toHaveBeenLastCalledWith(`/api/problems/${SLUG}/funding-target`, expect.objectContaining({
      cache: "no-store",
      credentials: "same-origin",
    }));
    expect(launch).toHaveBeenCalledOnce();
  });

  it("does not launch when click-time revalidation observes an exhausted cap", async () => {
    await renderAndReveal();
    vi.mocked(fetch).mockResolvedValueOnce(okResponse(responseBody({ remainingCapWei: "0", target: false })));
    const launch = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    expect(fireEvent.click(document.querySelector(`a[href="${WALLET_URI}"]`)!)).toBe(false);
    expectTargetClearedFromDom();
    await flushResponse();

    expect(launch).not.toHaveBeenCalled();
    expect(screen.getByText("funding unavailable")).toBeTruthy();
  });

  it("does not launch when click-time revalidation changes the target identity", async () => {
    await renderAndReveal();
    vi.mocked(fetch).mockResolvedValueOnce(okResponse(responseBody({ address: B_ADDRESS })));
    const launch = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    expect(fireEvent.click(document.querySelector(`a[href="${WALLET_URI}"]`)!)).toBe(false);
    await flushResponse();

    expect(launch).not.toHaveBeenCalled();
    expectTargetClearedFromDom();
  });
});
