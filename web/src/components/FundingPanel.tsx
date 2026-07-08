"use client";

import { useState } from "react";
import type { DonationWallet } from "@/lib/types";

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
    <div className="funding">
      <div className="funding-head">
        <h3>Deposit — {label ?? `${wallet.chain} ${wallet.asset}`}</h3>
        <span className="status-word locked">{wallet.status.replace("-", " ")}</span>
      </div>
      {!compact && <p className="funding-note">{wallet.note}</p>}
      <div className="address-line">
        <code>{wallet.address}</code>
        <button className="copy-button" type="button" onClick={copyAddress} aria-label="Copy deposit address">
          {copied ? "copied" : "copy"}
        </button>
        <a className="ref" href={wallet.explorerUrl} target="_blank" rel="noreferrer">
          basescan
        </a>
      </div>
      <p className="testnet-warning">
        {wallet.chain} testnet only — do not send mainnet ETH. Fiat onramp stays gated until audited mainnet pools
        exist.
      </p>
    </div>
  );
}
