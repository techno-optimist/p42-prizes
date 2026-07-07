"use client";

import { useState } from "react";
import { Check, Copy, ExternalLink, Wallet } from "lucide-react";
import type { DonationWallet } from "@/lib/types";
import { shortAddress } from "@/lib/format";

export function FundingPanel({
  wallet,
  label,
  compact = false,
}: {
  wallet: DonationWallet;
  label?: string;
  compact?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  async function copyAddress() {
    await navigator.clipboard.writeText(wallet.address);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className={compact ? "funding-card compact" : "funding-card"}>
      <div className="split">
        <div>
          <p className="eyebrow">Prize pool deposit</p>
          <h2>{label ?? `${wallet.chain} ${wallet.asset}`}</h2>
        </div>
        <span className={`pill ${wallet.status}`}>{wallet.status.replace("-", " ")}</span>
      </div>
      <div className="funding-meta">
        <span>{wallet.chain}</span>
        <span>{wallet.asset}</span>
        <span>Explorer verified</span>
      </div>
      {!compact && <p className="small muted">{wallet.note}</p>}
      <div className="address-box">
        <code>{compact ? shortAddress(wallet.address) : wallet.address}</code>
        <button className="icon-button" type="button" onClick={copyAddress} aria-label="Copy deposit address">
          {copied ? <Check size={15} /> : <Copy size={15} />}
        </button>
      </div>
      <div className="funding-actions">
        <a className="button subtle" href={wallet.explorerUrl} target="_blank" rel="noreferrer">
          <ExternalLink size={15} /> BaseScan
        </a>
        {!compact && (
          <button className="button disabled" type="button" disabled>
            <Wallet size={15} /> Coinbase gated
          </button>
        )}
      </div>
      {!compact && <p className="small warning-copy">Testnet only. Do not send mainnet ETH to this address.</p>}
    </div>
  );
}
