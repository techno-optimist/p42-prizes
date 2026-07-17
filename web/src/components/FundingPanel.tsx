"use client";

import { useEffect, useRef, useState, type MouseEvent } from "react";
import { sitePath } from "@/lib/site-paths";

const MAX_TIMEOUT_MS = 2_147_000_000;
const RESPONSE_SCHEMA = "p42-prizes/funding-target/v2";
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
  authorizationExpiresAt: string;
  finalizedObservedAt: string;
  fundingDeadline: string;
  remainingCapWei: string;
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
  if (!exactKeys(response, [
    "authorizationExpiresAt", "finalizedObservedAt", "fundingDeadline", "remainingCapWei",
    "schema", "serverObservedAt", "slug", "target",
  ])
    || response.schema !== RESPONSE_SCHEMA || response.slug !== slug
    || typeof response.authorizationExpiresAt !== "string" || parsedTimestamp(response.authorizationExpiresAt) === null
    || typeof response.finalizedObservedAt !== "string" || parsedTimestamp(response.finalizedObservedAt) === null
    || typeof response.fundingDeadline !== "string" || parsedTimestamp(response.fundingDeadline) === null
    || typeof response.remainingCapWei !== "string" || !/^(0|[1-9][0-9]*)$/.test(response.remainingCapWei)
    || typeof response.serverObservedAt !== "string" || parsedTimestamp(response.serverObservedAt) === null) return null;
  if (response.target === null) {
    return {
      authorizationExpiresAt: response.authorizationExpiresAt,
      finalizedObservedAt: response.finalizedObservedAt,
      fundingDeadline: response.fundingDeadline,
      remainingCapWei: response.remainingCapWei,
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
    authorizationExpiresAt: response.authorizationExpiresAt,
    finalizedObservedAt: response.finalizedObservedAt,
    fundingDeadline: response.fundingDeadline,
    remainingCapWei: response.remainingCapWei,
    serverObservedAt: response.serverObservedAt,
    target: target as unknown as ClientFundingTarget,
  };
}

export interface FundingPanelProps {
  slug: string;
  fundingTargetDeployed: boolean;
  authorizationExpiresAt: string | null;
  finalizedObservedAt: string | null;
  fundingDeadline: string | null;
  remainingCapWei: string | null;
  serverObservedAt: string | null;
  label?: string;
  compact?: boolean;
}

type FundingVisibility = "checking" | "available" | "unavailable";

export function FundingPanel({
  slug,
  fundingTargetDeployed,
  authorizationExpiresAt,
  finalizedObservedAt,
  fundingDeadline,
  remainingCapWei,
  serverObservedAt,
  label,
  compact = false,
}: FundingPanelProps) {
  const bindingKey = JSON.stringify([
    slug, authorizationExpiresAt, finalizedObservedAt, fundingDeadline,
    remainingCapWei, serverObservedAt, fundingTargetDeployed,
  ]);
  const bindingKeyRef = useRef(bindingKey);
  bindingKeyRef.current = bindingKey;
  const authorizationTimestamp = parsedTimestamp(authorizationExpiresAt);
  const finalizedTimestamp = parsedTimestamp(finalizedObservedAt);
  const deadlineTimestamp = parsedTimestamp(fundingDeadline);
  const observedTimestamp = parsedTimestamp(serverObservedAt);
  const authorizationCutoffTimestamp = authorizationTimestamp === null ? null : authorizationTimestamp + 1_000;
  const actionCutoffTimestamp = deadlineTimestamp === null || authorizationCutoffTimestamp === null
    ? null
    : Math.min(deadlineTimestamp, authorizationCutoffTimestamp);
  const validRemainingCap = typeof remainingCapWei === "string" && /^(0|[1-9][0-9]*)$/.test(remainingCapWei);
  const canCheckFunding = fundingTargetDeployed && actionCutoffTimestamp !== null
    && finalizedTimestamp !== null && observedTimestamp !== null && validRemainingCap
    && remainingCapWei !== "0" && observedTimestamp < actionCutoffTimestamp;
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
    if (actionCutoffTimestamp === null || candidateObserved === null) return true;
    if (candidateObserved >= actionCutoffTimestamp || Date.now() >= actionCutoffTimestamp) return true;
    const clientElapsed = clientWallStartedRef.current === null
      ? 0
      : Math.max(0, Date.now() - clientWallStartedRef.current);
    if (candidateObserved + clientElapsed >= actionCutoffTimestamp) return true;
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
    if (deadlineClosed && actionCutoffTimestamp !== null) latestObservedRef.current = actionCutoffTimestamp;
  }

  useEffect(() => {
    requestControllerRef.current?.abort();
    requestControllerRef.current = null;
    cancelCopyState();
    setBoundTarget(null);
    setCopied(false);
    setFundingVisibility(canCheckFunding ? "checking" : "unavailable");
    if (!canCheckFunding || actionCutoffTimestamp === null || observedTimestamp === null
      || authorizationExpiresAt === null || finalizedTimestamp === null || fundingDeadline === null) {
      expireFunding(false);
      return;
    }
    let active = true;
    latestObservedRef.current = observedTimestamp;
    clientWallStartedRef.current = Date.now();
    const duration = Math.min(actionCutoffTimestamp - observedTimestamp, actionCutoffTimestamp - Date.now());
    if (duration <= 0) {
      expireFunding(true);
      return;
    }

    monotonicCutoffRef.current = performance.now() + duration;
    let timeoutId: number | undefined;
    const schedule = () => {
      if (cutoffReached()) {
        expireFunding(true);
        return;
      }
      const remaining = monotonicCutoffRef.current! - performance.now();
      timeoutId = window.setTimeout(schedule, Math.min(remaining, MAX_TIMEOUT_MS));
    };
    timeoutId = window.setTimeout(schedule, Math.min(duration, MAX_TIMEOUT_MS));

    let controller: AbortController | null = null;
    const checkTarget = () => {
      controller?.abort();
      setBoundTarget(null);
      setCopied(false);
      setFundingVisibility("checking");
      controller = new AbortController();
      requestControllerRef.current = controller;
      const requestController = controller;
      void (async () => {
        try {
          const response = await fetch(sitePath(`/api/problems/${encodeURIComponent(slug)}/funding-target`), {
            cache: "no-store",
            credentials: "same-origin",
            headers: { Accept: "application/json" },
            signal: requestController.signal,
          });
          if (!response.ok) throw new Error("funding target request failed");
          const parsed = parseFundingTargetResponse(await response.json(), slug);
          if (!active || requestController.signal.aborted || bindingKeyRef.current !== bindingKey
            || !parsed || parsed.authorizationExpiresAt !== authorizationExpiresAt
            || parsed.fundingDeadline !== fundingDeadline
            || parsedTimestamp(parsed.finalizedObservedAt)! < finalizedTimestamp) {
            if (active && !requestController.signal.aborted) expireFunding(false);
            return;
          }
          const responseObserved = parsedTimestamp(parsed.serverObservedAt)!;
          if (parsedTimestamp(parsed.finalizedObservedAt)! > responseObserved) {
            expireFunding(false);
            return;
          }
          if (parsed.target === null || parsed.remainingCapWei === "0") {
            latestObservedRef.current = responseObserved;
            expireFunding(responseObserved >= deadlineTimestamp!);
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
            performance.now() + (actionCutoffTimestamp - responseObserved),
          );
          if (!active || requestController.signal.aborted || bindingKeyRef.current !== bindingKey || cutoffReached()) {
            expireFunding(true);
            return;
          }
          setBoundTarget({ bindingKey, target: parsed.target });
          setFundingVisibility("available");
        } catch {
          if (active && !requestController.signal.aborted) expireFunding(false);
        }
      })();
    };
    const reconcile = () => {
      if (cutoffReached()) expireFunding(true);
      else checkTarget();
    };
    document.addEventListener("visibilitychange", reconcile);
    window.addEventListener("focus", reconcile);
    window.addEventListener("pageshow", reconcile);
    checkTarget();

    return () => {
      active = false;
      controller?.abort();
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
    setCopied(false);
    const operation = copyOperationRef.current;
    const copiedBindingKey = boundTarget.bindingKey;
    const copiedTargetIdentity = JSON.stringify([copiedBindingKey, boundTarget.target.address]);
    const clipboard = navigator.clipboard;
    if (!clipboard || typeof clipboard.writeText !== "function") return;
    try {
      await clipboard.writeText(boundTarget.target.address);
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
  const authorizationExpired = authorizationCutoffTimestamp !== null && latestObservedRef.current !== null
    && latestObservedRef.current >= authorizationCutoffTimestamp;
  const capExhausted = validRemainingCap && remainingCapWei === "0";
  const fundingNote = fundingVisibility === "checking"
    ? "Funding availability is being checked against the chain deadline. No transfer target is published."
    : authorizationExpired && authorizationExpiresAt
      ? `Funding authorization expired after ${authorizationExpiresAt}. No transfer target is published.`
      : capExhausted
        ? "The finalized observation has no remaining funding capacity. No transfer target is published."
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
              ? "Base Sepolia testnet only — do not send mainnet ETH. Remaining capacity is observed, not reserved."
              : "ETH only. Pool provenance is reconciled to deployed runtime bytecode. Remaining capacity is observed, not reserved; a concurrent funding transaction can consume it first."}
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
