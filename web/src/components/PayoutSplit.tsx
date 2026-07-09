"use client";

import { useEffect, useRef } from "react";
import type { CSSProperties } from "react";

export interface PayoutSlice {
  solver: string;
  /** exact rational share numerator (Δᵢ) and shared denominator (ΣΔⱼ) */
  shareNum: number;
  shareDen: number;
  /** exact wei paid, verbatim from the simulator run */
  wei: number;
}

/**
 * PayoutSplit — a proportional bar for shareᵢ = Δᵢ / ΣΔⱼ, drawn from the exact
 * simulator numbers already printed in Plate 1. Each segment's width is set by
 * flex-grow equal to its Δ numerator, so the browser divides 6 : 3 : 4 into
 * 6/13, 3/13, 4/13 — the widths are the exact rationals, never a recomputed
 * decimal. Segments are one subtle ink tint, told apart by hairline dividers
 * and labels (not by hue); the largest Δ carries a record-red baseline tick —
 * the frontier the pool pays most for.
 *
 * On first scroll-into-view each fill grows from zero, staggered, once. Without
 * JS or under prefers-reduced-motion the full bar renders. The sr-only list and
 * the figure's aria-label mirror Plate 1 exactly.
 */
export function PayoutSplit({
  slices,
  poolWei,
  feeWei,
  availableWei,
  dustWei,
}: {
  slices: PayoutSlice[];
  poolWei: number;
  feeWei: number;
  availableWei: number;
  dustWei: number;
}) {
  const ref = useRef<HTMLElement>(null);
  const leadWei = Math.max(...slices.map((s) => s.wei));

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          el.classList.add("play");
          observer.disconnect();
        }
      },
      { threshold: 0.5 },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const aria =
    "Payout split, share = delta over total delta: " +
    slices
      .map((s) => `${s.solver} ${s.shareNum}/${s.shareDen}, ${s.wei} wei`)
      .join("; ") +
    `. Pool ${poolWei} wei, fee ${feeWei}, available ${availableWei}, dust ${dustWei}.`;

  return (
    <figure ref={ref} className="payout-split" aria-label={aria}>
      <figcaption className="ps-cap">
        Share of the pool is fraction of total frontier moved — payment is proportional to frontier moved.
      </figcaption>

      <div className="payout-bar" aria-hidden="true">
        {slices.map((s, i) => (
          <div
            key={s.solver}
            className={`payout-seg${s.wei === leadWei ? " is-lead" : ""}`}
            style={{ flexGrow: s.shareNum, flexBasis: 0 }}
          >
            <div className="seg-fill" style={{ "--i": i } as CSSProperties} />
            <span className="seg-share">
              {s.shareNum}/{s.shareDen}
            </span>
          </div>
        ))}
      </div>

      <div className="payout-legend" aria-hidden="true">
        {slices.map((s) => (
          <div key={s.solver} style={{ flexGrow: s.shareNum, flexBasis: 0 }}>
            <span className={`pl-solver${s.wei === leadWei ? " pl-lead" : ""}`}>{s.solver}</span>
            <span className="pl-share">
              Δ {s.shareNum}/{s.shareDen}
            </span>
            <span className="pl-wei">{s.wei} wei</span>
          </div>
        ))}
      </div>

      <div className="payout-foot" aria-hidden="true">
        <span>pool {poolWei} wei</span>
        <span>fee {feeWei}</span>
        <span>available {availableWei}</span>
        <span>dust {dustWei}</span>
      </div>

      <ul className="sr-only">
        {slices.map((s) => (
          <li key={s.solver}>
            {s.solver}: share {s.shareNum}/{s.shareDen}, {s.wei} wei
          </li>
        ))}
        <li>
          Pool {poolWei} wei, fee {feeWei} wei, available {availableWei} wei, integer dust {dustWei} wei.
        </li>
      </ul>
    </figure>
  );
}
