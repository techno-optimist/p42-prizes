"use client";

import { useState } from "react";
import { publishedDonationTarget } from "@/lib/chain-provenance";
import type { ChainProvenance, DonationWallet } from "@/lib/types";

export function FundingPanel({
  wallet,
  provenance,
  label,
  compact = false,
}: {
  wallet: DonationWallet;
  provenance: ChainProvenance;
  label?: string;
  compact?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const target = publishedDonationTarget(wallet, provenance);

  async function copyAddress() {
    if (!target) return;
    try {
      await navigator.clipboard?.writeText(target.address);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // clipboard unavailable (non-secure context) — the address is shown in full beside the button
    }
  }

  return (
    <div className="funding">
      <div className="funding-head">
        <h3>Proposed sponsor pool — {label ?? `${wallet.chain} ${wallet.asset}`}</h3>
        <span className={`status-word ${target ? "pilot" : "locked"}`}>
          {target ? "deployed" : "not deployed"}
        </span>
      </div>
      {!compact && <p className="funding-note">{wallet.note}</p>}
      {target ? (
        <>
          <div className="address-line">
            <code>{target.address}</code>
            <a className="copy-button" href={target.walletUri} aria-label={`Fund ${label ?? "sponsor pool"} with ${target.asset}`}>
              fund {target.asset}
            </a>
            <button className="copy-button" type="button" onClick={copyAddress} aria-label="Copy sponsor pool address">
              {copied ? "copied" : "copy"}
            </button>
            <a className="ref" href={target.explorerUrl} target="_blank" rel="noreferrer">
              basescan
            </a>
          </div>
          <p className="testnet-warning">
            {target.chain === "Base Sepolia"
              ? "Base Sepolia testnet only — do not send mainnet ETH."
              : "ETH only. Pool provenance is reconciled to deployed runtime bytecode."}
          </p>
        </>
      ) : (
        <p className="testnet-warning">
          Pool not deployed. No address or sponsorship-funding action is published until per-problem chain provenance is
          reconciled to deployed runtime bytecode.
        </p>
      )}
    </div>
  );
}
