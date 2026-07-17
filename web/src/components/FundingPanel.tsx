"use client";

import { useEffect, useRef, useState, type MouseEvent } from "react";
import { sitePath } from "@/lib/site-paths";
import type { FundingTargetEnvelopeV3, FundingTargetV3 } from "@/lib/types";

const MAX_TIMEOUT_MS = 2_147_000_000;
const RESPONSE_SCHEMA = "p42-prizes/funding-target/v3";
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;

type ClientFundingTarget = FundingTargetV3;

interface BoundFundingTarget {
  bindingKey: string;
  launchBindingKey: string;
  target: ClientFundingTarget;
}

type FundingTargetResponse = FundingTargetEnvelopeV3 & {
  authorizationExpiresAt: string;
  finalizedObservedAt: string;
  fundingDeadline: string;
  remainingCapWei: string;
  serverObservedAt: string;
  fundingAuthorizationDigest: string;
  activationCompletionDigest: string;
  checkpointBlock: number;
  checkpointDigest: string;
  activationFinalizedBlock: number;
};

function parsedTimestamp(value: string | null): number | null {
  if (value === null) return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value ? timestamp : null;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && actual.every((key, index) => key === [...keys].sort()[index]);
}

function validDigest(value: unknown): value is string {
  return typeof value === "string" && SHA256.test(value) && value !== ZERO_SHA256;
}

function validBlock(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function abbreviatedDigest(value: string): string {
  return `${value.slice(0, 15)}...${value.slice(-8)}`;
}

function launchBindingKey(response: FundingTargetResponse): string | null {
  if (!response.target) return null;
  return JSON.stringify([
    response.authorizationExpiresAt,
    response.finalizedObservedAt,
    response.fundingDeadline,
    response.fundingAuthorizationDigest,
    response.activationCompletionDigest,
    response.checkpointBlock,
    response.checkpointDigest,
    response.activationFinalizedBlock,
    response.target.address,
    response.target.asset,
    response.target.chain,
    response.target.chainId,
    response.target.explorerUrl,
    response.target.walletUri,
  ]);
}

function parseFundingTargetResponse(value: unknown, slug: string): FundingTargetResponse | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const response = value as Record<string, unknown>;
  if (!exactKeys(response, [
    "activationCompletionDigest", "activationFinalizedBlock", "authorizationExpiresAt",
    "checkpointBlock", "checkpointDigest", "finalizedObservedAt", "fundingAuthorizationDigest", "fundingDeadline",
    "remainingCapWei", "schema", "serverObservedAt", "slug", "target",
  ])
    || response.schema !== RESPONSE_SCHEMA || response.slug !== slug
    || typeof response.authorizationExpiresAt !== "string" || parsedTimestamp(response.authorizationExpiresAt) === null
    || typeof response.finalizedObservedAt !== "string" || parsedTimestamp(response.finalizedObservedAt) === null
    || typeof response.fundingDeadline !== "string" || parsedTimestamp(response.fundingDeadline) === null
    || typeof response.remainingCapWei !== "string" || !/^(0|[1-9][0-9]*)$/.test(response.remainingCapWei)
    || typeof response.serverObservedAt !== "string" || parsedTimestamp(response.serverObservedAt) === null
    || !validDigest(response.fundingAuthorizationDigest)
    || !validDigest(response.activationCompletionDigest)
    || !validBlock(response.checkpointBlock) || !validBlock(response.activationFinalizedBlock)
    || !validDigest(response.checkpointDigest)
    || response.activationFinalizedBlock > response.checkpointBlock) return null;
  if (response.target === null) {
    return {
      authorizationExpiresAt: response.authorizationExpiresAt,
      finalizedObservedAt: response.finalizedObservedAt,
      fundingDeadline: response.fundingDeadline,
      remainingCapWei: response.remainingCapWei,
      serverObservedAt: response.serverObservedAt,
      fundingAuthorizationDigest: response.fundingAuthorizationDigest,
      activationCompletionDigest: response.activationCompletionDigest,
      checkpointBlock: response.checkpointBlock,
      checkpointDigest: response.checkpointDigest,
      activationFinalizedBlock: response.activationFinalizedBlock,
      schema: RESPONSE_SCHEMA,
      slug,
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
    fundingAuthorizationDigest: response.fundingAuthorizationDigest,
    activationCompletionDigest: response.activationCompletionDigest,
    checkpointBlock: response.checkpointBlock,
    checkpointDigest: response.checkpointDigest,
    activationFinalizedBlock: response.activationFinalizedBlock,
    schema: RESPONSE_SCHEMA,
    slug,
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
  fundingAuthorizationDigest: string | null;
  activationCompletionDigest: string | null;
  checkpointBlock: number | null;
  checkpointDigest: string | null;
  activationFinalizedBlock: number | null;
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
  fundingAuthorizationDigest,
  activationCompletionDigest,
  checkpointBlock,
  checkpointDigest,
  activationFinalizedBlock,
  label,
  compact = false,
}: FundingPanelProps) {
  const bindingKey = JSON.stringify([
    slug, authorizationExpiresAt, finalizedObservedAt, fundingDeadline,
    remainingCapWei, serverObservedAt, fundingAuthorizationDigest, activationCompletionDigest,
    checkpointBlock, checkpointDigest, activationFinalizedBlock, fundingTargetDeployed,
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
  const validPolicyBinding = validDigest(fundingAuthorizationDigest) && validDigest(activationCompletionDigest)
    && validBlock(checkpointBlock) && validBlock(activationFinalizedBlock)
    && validDigest(checkpointDigest)
    && activationFinalizedBlock <= checkpointBlock;
  const canCheckFunding = fundingTargetDeployed && actionCutoffTimestamp !== null
    && finalizedTimestamp !== null && observedTimestamp !== null && validRemainingCap && validPolicyBinding
    && remainingCapWei !== "0" && observedTimestamp < actionCutoffTimestamp;
  const [fundingVisibility, setFundingVisibility] = useState<FundingVisibility>(
    canCheckFunding ? "checking" : "unavailable",
  );
  const [boundTarget, setBoundTarget] = useState<BoundFundingTarget | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [walletLaunchIdentity, setWalletLaunchIdentity] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [copiedDigest, setCopiedDigest] = useState<"authorization" | "activation" | "checkpoint" | null>(null);
  const monotonicCutoffRef = useRef<number | null>(null);
  const clientWallStartedRef = useRef<number | null>(null);
  const latestObservedRef = useRef<number | null>(observedTimestamp);
  const requestControllerRef = useRef<AbortController | null>(null);
  const target = boundTarget?.bindingKey === bindingKey ? boundTarget.target : null;
  const targetIdentity = boundTarget?.bindingKey === bindingKey
    ? JSON.stringify([boundTarget.bindingKey, boundTarget.launchBindingKey])
    : null;
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
    setAcknowledged(false);
    setWalletLaunchIdentity(null);
    setCopied(false);
    setCopiedDigest(null);
    setFundingVisibility("unavailable");
    if (deadlineClosed && actionCutoffTimestamp !== null) latestObservedRef.current = actionCutoffTimestamp;
  }

  useEffect(() => {
    requestControllerRef.current?.abort();
    requestControllerRef.current = null;
    cancelCopyState();
    setBoundTarget(null);
    setAcknowledged(false);
    setWalletLaunchIdentity(null);
    setCopied(false);
    setCopiedDigest(null);
    setFundingVisibility(canCheckFunding ? "checking" : "unavailable");
    if (!canCheckFunding || actionCutoffTimestamp === null || observedTimestamp === null
      || authorizationExpiresAt === null || finalizedTimestamp === null || fundingDeadline === null) {
      expireFunding(false);
      return;
    }
    let active = true;
    let bindingInvalidated = false;
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
      requestControllerRef.current?.abort();
      controller?.abort();
      setBoundTarget(null);
      setAcknowledged(false);
      setWalletLaunchIdentity(null);
      setCopied(false);
      setCopiedDigest(null);
      setFundingVisibility("checking");
      if (bindingInvalidated) {
        setFundingVisibility("unavailable");
        return;
      }
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
          if (!active || requestController.signal.aborted || bindingKeyRef.current !== bindingKey || !parsed) {
            if (active && !requestController.signal.aborted) expireFunding(false);
            return;
          }
          const responseObserved = parsedTimestamp(parsed.serverObservedAt)!;
          if (responseObserved < (latestObservedRef.current ?? observedTimestamp)) {
            expireFunding(false);
            return;
          }
          if (parsed.authorizationExpiresAt !== authorizationExpiresAt
            || parsed.fundingDeadline !== fundingDeadline
            || parsed.fundingAuthorizationDigest !== fundingAuthorizationDigest
            || parsed.activationCompletionDigest !== activationCompletionDigest
            || parsed.checkpointBlock !== checkpointBlock
            || parsed.checkpointDigest !== checkpointDigest
            || parsed.activationFinalizedBlock !== activationFinalizedBlock
            || parsedTimestamp(parsed.finalizedObservedAt)! < finalizedTimestamp) {
            latestObservedRef.current = responseObserved;
            bindingInvalidated = true;
            expireFunding(false);
            return;
          }
          if (parsedTimestamp(parsed.finalizedObservedAt)! > responseObserved) {
            expireFunding(false);
            return;
          }
          if (parsed.target === null || parsed.remainingCapWei === "0") {
            latestObservedRef.current = responseObserved;
            bindingInvalidated = true;
            expireFunding(responseObserved >= deadlineTimestamp!);
            return;
          }
          if (cutoffReached(responseObserved)) {
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
          const parsedLaunchBindingKey = launchBindingKey(parsed);
          if (parsedLaunchBindingKey === null) {
            expireFunding(false);
            return;
          }
          setBoundTarget({ bindingKey, launchBindingKey: parsedLaunchBindingKey, target: parsed.target });
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
    setCopiedDigest(null);
    const operation = copyOperationRef.current;
    const copiedBindingKey = boundTarget.bindingKey;
    const copiedTargetIdentity = targetIdentityRef.current;
    if (copiedTargetIdentity === null) return;
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

  async function copyPolicyDigest(kind: "authorization" | "activation" | "checkpoint", digest: string) {
    if (!boundTarget || boundTarget.bindingKey !== bindingKeyRef.current || !validDigest(digest)) return;
    if (cutoffReached()) {
      expireFunding(true);
      return;
    }
    cancelCopyState();
    setCopied(false);
    setCopiedDigest(null);
    const operation = copyOperationRef.current;
    const copiedBindingKey = boundTarget.bindingKey;
    const copiedTargetIdentity = targetIdentityRef.current;
    if (copiedTargetIdentity === null) return;
    const clipboard = navigator.clipboard;
    if (!clipboard || typeof clipboard.writeText !== "function") return;
    try {
      await clipboard.writeText(digest);
      if (copyOperationRef.current !== operation
        || bindingKeyRef.current !== copiedBindingKey
        || targetIdentityRef.current !== copiedTargetIdentity
        || cutoffReached()) return;
      setCopiedDigest(kind);
      const timeoutId = window.setTimeout(() => {
        if (copyOperationRef.current === operation
          && bindingKeyRef.current === copiedBindingKey
          && targetIdentityRef.current === copiedTargetIdentity) setCopiedDigest(null);
        if (copyResetTimerRef.current === timeoutId) copyResetTimerRef.current = null;
      }, 1600);
      copyResetTimerRef.current = timeoutId;
    } catch {
      // Clipboard unavailable in this browser context.
    }
  }

  async function openWallet(event: MouseEvent<HTMLAnchorElement>) {
    const clickedTarget = boundTarget;
    const clickedIdentity = clickedTarget
      ? JSON.stringify([clickedTarget.bindingKey, clickedTarget.launchBindingKey])
      : null;
    if (!acknowledged || !clickedTarget || clickedTarget.bindingKey !== bindingKeyRef.current) {
      event.preventDefault();
      return;
    }
    if (cutoffReached()) {
      event.preventDefault();
      expireFunding(true);
      return;
    }
    if (walletLaunchIdentity === clickedIdentity) {
      setWalletLaunchIdentity(null);
      setAcknowledged(false);
      return;
    }
    event.preventDefault();

    requestControllerRef.current?.abort();
    const controller = new AbortController();
    requestControllerRef.current = controller;
    setBoundTarget(null);
    setWalletLaunchIdentity(null);
    setCopied(false);
    setFundingVisibility("checking");
    try {
      const response = await fetch(sitePath(`/api/problems/${encodeURIComponent(slug)}/funding-target`), {
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (!response.ok) throw new Error("funding target request failed");
      const parsed = parseFundingTargetResponse(await response.json(), slug);
      const responseObserved = parsedTimestamp(parsed?.serverObservedAt ?? null);
      const responseFinalized = parsedTimestamp(parsed?.finalizedObservedAt ?? null);
      if (controller.signal.aborted || requestControllerRef.current !== controller
        || bindingKeyRef.current !== clickedTarget.bindingKey
        || !parsed || !parsed.target || parsed.remainingCapWei === "0"
        || parsed.authorizationExpiresAt !== authorizationExpiresAt
        || parsed.fundingDeadline !== fundingDeadline
        || parsed.fundingAuthorizationDigest !== fundingAuthorizationDigest
        || parsed.activationCompletionDigest !== activationCompletionDigest
        || parsed.checkpointBlock !== checkpointBlock
        || parsed.checkpointDigest !== checkpointDigest
        || parsed.activationFinalizedBlock !== activationFinalizedBlock
        || responseObserved === null || responseFinalized === null
        || responseFinalized < finalizedTimestamp! || responseFinalized > responseObserved
        || responseObserved < (latestObservedRef.current ?? observedTimestamp!)
        || parsed.target.address !== clickedTarget.target.address
        || parsed.target.walletUri !== clickedTarget.target.walletUri
        || parsed.target.chainId !== clickedTarget.target.chainId
        || launchBindingKey(parsed) !== clickedTarget.launchBindingKey
        || cutoffReached(responseObserved)) {
        if (!controller.signal.aborted) expireFunding(false);
        return;
      }

      latestObservedRef.current = responseObserved;
      setBoundTarget(clickedTarget);
      setWalletLaunchIdentity(clickedIdentity);
      setFundingVisibility("available");
    } catch {
      if (!controller.signal.aborted) expireFunding(false);
    } finally {
      if (requestControllerRef.current === controller) requestControllerRef.current = null;
    }
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
            {acknowledged ? (
              <a className="copy-button" href={target.walletUri} onClick={openWallet} aria-label={`Fund ${label ?? "sponsor pool"} with ${target.asset}`}>
                {walletLaunchIdentity === targetIdentity ? "open wallet" : `fund ${target.asset}`}
              </a>
            ) : (
              <button className="copy-button" type="button" disabled aria-label={`Fund ${label ?? "sponsor pool"} with ${target.asset}`}>
                fund {target.asset}
              </button>
            )}
            <button className="copy-button" type="button" onClick={copyAddress} aria-label="Copy sponsor pool address">
              {copied ? "copied" : "copy"}
            </button>
            <a className="ref" href={target.explorerUrl} target="_blank" rel="noreferrer">basescan</a>
          </div>
          <div className="funding-policy-binding">
            <span>authorization <code>{abbreviatedDigest(fundingAuthorizationDigest!)}</code></span>
            <span>activation <code>{abbreviatedDigest(activationCompletionDigest!)}</code></span>
            <span>checkpoint <code>#{checkpointBlock} · {abbreviatedDigest(checkpointDigest!)}</code></span>
          </div>
          <details className="funding-policy-details">
            <summary>Inspect exact policy digests</summary>
            <dl>
              <dt>Funding authorization</dt>
              <dd>
                <code>{fundingAuthorizationDigest}</code>
                <button
                  className="copy-button funding-digest-copy"
                  type="button"
                  onClick={() => void copyPolicyDigest("authorization", fundingAuthorizationDigest!)}
                  aria-label="Copy full funding authorization digest"
                >
                  {copiedDigest === "authorization" ? "copied" : "copy"}
                </button>
              </dd>
              <dt>Activation completion</dt>
              <dd>
                <code>{activationCompletionDigest}</code>
                <button
                  className="copy-button funding-digest-copy"
                  type="button"
                  onClick={() => void copyPolicyDigest("activation", activationCompletionDigest!)}
                  aria-label="Copy full activation completion digest"
                >
                  {copiedDigest === "activation" ? "copied" : "copy"}
                </button>
              </dd>
              <dt>Checkpoint generation</dt>
              <dd>
                <code>{checkpointDigest}</code>
                <button
                  className="copy-button funding-digest-copy"
                  type="button"
                  onClick={() => void copyPolicyDigest("checkpoint", checkpointDigest!)}
                  aria-label="Copy full checkpoint generation digest"
                >
                  {copiedDigest === "checkpoint" ? "copied" : "copy"}
                </button>
              </dd>
            </dl>
          </details>
          <label className="funding-acknowledgement">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.currentTarget.checked)}
            />
            <span>
              I acknowledge the exact authorization, activation, and checkpoint-generation values available in the policy digest disclosure and API for this funding target.
            </span>
          </label>
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
