"use client";

import { useEffect, useRef, useState, type MouseEvent } from "react";
import { sitePath } from "@/lib/site-paths";

const MAX_TIMEOUT_MS = 2_147_000_000;
const RESPONSE_SCHEMA = "p42-prizes/funding-target/v1";
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

interface ClientFundingTarget {
  address: string;
  asset: "ETH";
  chain: "Base Sepolia" | "Base";
  chainId: 84532 | 8453;
  explorerUrl: string;
  walletUri: string;
}

interface BoundFundingTarget {
  bindingKey: string;
  target: ClientFundingTarget;
}

interface FundingTargetResponse {
  fundingDeadline: string;
  serverObservedAt: string;
  target: ClientFundingTarget | null;
}

function parsedTimestamp(value: string | null): number | null {
  if (value === null) return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value ? timestamp : null;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && actual.every((key, index) => key === [...keys].sort()[index]);
}

function parseFundingTargetResponse(value: unknown, slug: string): FundingTargetResponse | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const response = value as Record<string, unknown>;
  if (!exactKeys(response, ["fundingDeadline", "schema", "serverObservedAt", "slug", "target"])
    || response.schema !== RESPONSE_SCHEMA || response.slug !== slug
    || typeof response.fundingDeadline !== "string" || parsedTimestamp(response.fundingDeadline) === null
    || typeof response.serverObservedAt !== "string" || parsedTimestamp(response.serverObservedAt) === null) return null;
  if (response.target === null) {
    return {
      fundingDeadline: response.fundingDeadline,
      serverObservedAt: response.serverObservedAt,
      target: null,
    };
  }
  if (typeof response.target !== "object" || Array.isArray(response.target)) return null;
  const target = response.target as Record<string, unknown>;
  if (!exactKeys(target, ["address", "asset", "chain", "chainId", "explorerUrl", "walletUri"])
    || typeof target.address !== "string" || !ADDRESS.test(target.address) || /^0x0{40}$/i.test(target.address)
    || target.asset !== "ETH" || typeof target.explorerUrl !== "string" || typeof target.walletUri !== "string") return null;
  const chainMatches = (target.chain === "Base Sepolia" && target.chainId === 84532)
    || (target.chain === "Base" && target.chainId === 8453);
  if (!chainMatches || target.walletUri !== `ethereum:${target.address}@${target.chainId}`) return null;
  const explorerBase = target.chain === "Base" ? "https://basescan.org" : "https://sepolia.basescan.org";
  if (target.explorerUrl !== `${explorerBase}/address/${target.address}`) return null;
  return {
    fundingDeadline: response.fundingDeadline,
    serverObservedAt: response.serverObservedAt,
    target: target as unknown as ClientFundingTarget,
  };
}

export interface FundingPanelProps {
  slug: string;
  fundingTargetDeployed: boolean;
  fundingDeadline: string | null;
  serverObservedAt: string | null;
  label?: string;
  compact?: boolean;
}

type FundingVisibility = "checking" | "available" | "unavailable";

export function FundingPanel({
  slug,
  fundingTargetDeployed,
  fundingDeadline,
  serverObservedAt,
  label,
  compact = false,
}: FundingPanelProps) {
  const bindingKey = JSON.stringify([slug, fundingDeadline, serverObservedAt, fundingTargetDeployed]);
  const bindingKeyRef = useRef(bindingKey);
  bindingKeyRef.current = bindingKey;
  const deadlineTimestamp = parsedTimestamp(fundingDeadline);
  const observedTimestamp = parsedTimestamp(serverObservedAt);
  const canCheckFunding = fundingTargetDeployed && deadlineTimestamp !== null
    && observedTimestamp !== null && observedTimestamp < deadlineTimestamp;
  const [fundingVisibility, setFundingVisibility] = useState<FundingVisibility>(
    canCheckFunding ? "checking" : "unavailable",
  );
  const [boundTarget, setBoundTarget] = useState<BoundFundingTarget | null>(null);
  const [copied, setCopied] = useState(false);
  const monotonicCutoffRef = useRef<number | null>(null);
  const clientWallStartedRef = useRef<number | null>(null);
  const latestObservedRef = useRef<number | null>(observedTimestamp);
  const requestControllerRef = useRef<AbortController | null>(null);
  const target = boundTarget?.bindingKey === bindingKey ? boundTarget.target : null;
  const targetIdentity = target ? JSON.stringify([bindingKey, target.address]) : null;
  const targetIdentityRef = useRef(targetIdentity);
  targetIdentityRef.current = targetIdentity;
  const copyOperationRef = useRef(0);
  const copyResetTimerRef = useRef<number | null>(null);

  function cancelCopyState() {
    copyOperationRef.current += 1;
    if (copyResetTimerRef.current !== null) {
      window.clearTimeout(copyResetTimerRef.current);
      copyResetTimerRef.current = null;
    }
  }

  function cutoffReached(candidateObserved = latestObservedRef.current): boolean {
    if (deadlineTimestamp === null || candidateObserved === null) return true;
    if (candidateObserved >= deadlineTimestamp || Date.now() >= deadlineTimestamp) return true;
    const clientElapsed = clientWallStartedRef.current === null
      ? 0
      : Math.max(0, Date.now() - clientWallStartedRef.current);
    if (candidateObserved + clientElapsed >= deadlineTimestamp) return true;
    return monotonicCutoffRef.current !== null && performance.now() >= monotonicCutoffRef.current;
  }

  function expireFunding(deadlineClosed = cutoffReached()) {
    requestControllerRef.current?.abort();
    requestControllerRef.current = null;
    monotonicCutoffRef.current = null;
    cancelCopyState();
    setBoundTarget(null);
    setCopied(false);
    setFundingVisibility("unavailable");
    if (deadlineClosed && deadlineTimestamp !== null) latestObservedRef.current = deadlineTimestamp;
  }

  useEffect(() => {
    requestControllerRef.current?.abort();
    requestControllerRef.current = null;
    cancelCopyState();
    setBoundTarget(null);
    setCopied(false);
    setFundingVisibility(canCheckFunding ? "checking" : "unavailable");
    if (!canCheckFunding || deadlineTimestamp === null || observedTimestamp === null) {
      expireFunding(false);
      return;
    }
    let active = true;
    latestObservedRef.current = observedTimestamp;
    clientWallStartedRef.current = Date.now();
    const duration = Math.min(deadlineTimestamp - observedTimestamp, deadlineTimestamp - Date.now());
    if (duration <= 0) {
      expireFunding(true);
      return;
    }

    monotonicCutoffRef.current = performance.now() + duration;
    let timeoutId: number | undefined;
    const reconcile = () => {
      if (cutoffReached()) expireFunding(true);
    };
    const schedule = () => {
      if (cutoffReached()) {
        expireFunding(true);
        return;
      }
      const remaining = monotonicCutoffRef.current! - performance.now();
      timeoutId = window.setTimeout(schedule, Math.min(remaining, MAX_TIMEOUT_MS));
    };
    timeoutId = window.setTimeout(schedule, Math.min(duration, MAX_TIMEOUT_MS));
    document.addEventListener("visibilitychange", reconcile);
    window.addEventListener("focus", reconcile);
    window.addEventListener("pageshow", reconcile);

    const controller = new AbortController();
    requestControllerRef.current = controller;
    void (async () => {
      try {
        const response = await fetch(sitePath(`/api/problems/${encodeURIComponent(slug)}/funding-target`), {
          cache: "no-store",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });
        if (!response.ok) throw new Error("funding target request failed");
        const parsed = parseFundingTargetResponse(await response.json(), slug);
        if (!active || controller.signal.aborted || bindingKeyRef.current !== bindingKey
          || !parsed || parsed.fundingDeadline !== fundingDeadline) {
          if (active && !controller.signal.aborted) expireFunding(false);
          return;
        }
        const responseObserved = parsedTimestamp(parsed.serverObservedAt)!;
        if (parsed.target === null) {
          latestObservedRef.current = responseObserved;
          expireFunding(responseObserved >= deadlineTimestamp);
          return;
        }
        if (responseObserved < observedTimestamp || cutoffReached(responseObserved)) {
          expireFunding(true);
          return;
        }
        latestObservedRef.current = responseObserved;
        clientWallStartedRef.current = Date.now();
        monotonicCutoffRef.current = Math.min(
          monotonicCutoffRef.current!,
          performance.now() + (deadlineTimestamp - responseObserved),
        );
        if (!active || controller.signal.aborted || bindingKeyRef.current !== bindingKey || cutoffReached()) {
          expireFunding(true);
          return;
        }
        setBoundTarget({ bindingKey, target: parsed.target });
        setFundingVisibility("available");
      } catch {
        if (active && !controller.signal.aborted) expireFunding(false);
      }
    })();

    return () => {
      active = false;
      controller.abort();
      cancelCopyState();
      if (requestControllerRef.current === controller) requestControllerRef.current = null;
      if (timeoutId !== undefined) window.clearTimeout(timeoutId);
      document.removeEventListener("visibilitychange", reconcile);
      window.removeEventListener("focus", reconcile);
      window.removeEventListener("pageshow", reconcile);
    };
  }, [bindingKey, canCheckFunding, fundingDeadline, serverObservedAt, slug]);

  async function copyAddress() {
    if (!boundTarget || boundTarget.bindingKey !== bindingKeyRef.current) return;
    if (cutoffReached()) {
      expireFunding(true);
      return;
    }
    cancelCopyState();
    const operation = copyOperationRef.current;
    const copiedBindingKey = boundTarget.bindingKey;
    const copiedTargetIdentity = JSON.stringify([copiedBindingKey, boundTarget.target.address]);
    try {
      await navigator.clipboard?.writeText(boundTarget.target.address);
      if (copyOperationRef.current !== operation
        || bindingKeyRef.current !== copiedBindingKey
        || targetIdentityRef.current !== copiedTargetIdentity
        || cutoffReached()) return;
      setCopied(true);
      const timeoutId = window.setTimeout(() => {
        if (copyOperationRef.current === operation
          && bindingKeyRef.current === copiedBindingKey
          && targetIdentityRef.current === copiedTargetIdentity) setCopied(false);
        if (copyResetTimerRef.current === timeoutId) copyResetTimerRef.current = null;
      }, 1600);
      copyResetTimerRef.current = timeoutId;
    } catch {
      // Clipboard unavailable in this browser context.
    }
  }

  function openWallet(event: MouseEvent<HTMLAnchorElement>) {
    if (!boundTarget || boundTarget.bindingKey !== bindingKeyRef.current) {
      event.preventDefault();
      return;
    }
    if (!cutoffReached()) return;
    event.preventDefault();
    expireFunding(true);
  }

  const deadlineClosed = deadlineTimestamp !== null && latestObservedRef.current !== null
    && latestObservedRef.current >= deadlineTimestamp;
  const fundingNote = fundingVisibility === "checking"
    ? "Funding availability is being checked against the chain deadline. No transfer target is published."
    : deadlineClosed && fundingDeadline
      ? `The portal conservatively stops publishing funding targets at ${fundingDeadline}; the contract funding function rejects transactions after that timestamp.`
      : "The pool is deployed, but no current funding target is available.";

  return (
    <div className="funding">
      <div className="funding-head">
        <h3>Proposed sponsor pool — {label ?? "ETH"}</h3>
        <span className={`status-word ${target ? "pilot" : "locked"}`}>
          {target ? "deployed" : fundingVisibility === "checking"
            ? "checking funding availability"
            : fundingTargetDeployed ? "funding unavailable" : "not deployed"}
        </span>
      </div>
      {!compact && <p className="funding-note">{fundingNote}</p>}
      {target ? (
        <>
          <div className="address-line">
            <code>{target.address}</code>
            <a className="copy-button" href={target.walletUri} onClick={openWallet} aria-label={`Fund ${label ?? "sponsor pool"} with ${target.asset}`}>
              fund {target.asset}
            </a>
            <button className="copy-button" type="button" onClick={copyAddress} aria-label="Copy sponsor pool address">
              {copied ? "copied" : "copy"}
            </button>
            <a className="ref" href={target.explorerUrl} target="_blank" rel="noreferrer">basescan</a>
          </div>
          <p className="testnet-warning">
            {target.chain === "Base Sepolia"
              ? "Base Sepolia testnet only — do not send mainnet ETH."
              : "ETH only. Pool provenance is reconciled to deployed runtime bytecode."}
          </p>
        </>
      ) : (
        <p className="testnet-warning">
          {fundingVisibility === "checking"
            ? "Funding is being checked. No address or transfer action is available yet."
            : fundingTargetDeployed
              ? "Pool deployment is reconciled, but funding is not currently actionable. No transfer target is published."
              : "Pool not deployed. No address or sponsorship-funding action is published until deployment is reconciled."}
        </p>
      )}
    </div>
  );
}
