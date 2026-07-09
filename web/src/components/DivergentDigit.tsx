"use client";

import { useEffect, useRef } from "react";
import type { CSSProperties } from "react";

export interface DivergentDigitProps {
  /** small-caps heading for the quantity, e.g. "C₁" (omit for single-result entries) */
  symbol?: string;
  /** the superseded prior numeral, verbatim from the published attribution */
  prior: string;
  /** the prior numeral is a decimal approximation (e.g. π/2 ≈ 1.5707963) */
  priorApprox?: boolean;
  priorLabel: string;
  /** the new certified numeral, verbatim from the published bound */
  next: string;
  /** the new numeral is a decimal approximation of an exact rational */
  nextApprox?: boolean;
  nextLabel?: string;
  /**
   * The one permitted digit motion on the site: teletype-print the red tail
   * once, on first scroll-into-view, under ~600ms. Enabled for at most one
   * device per page so no viewport ever holds two animated elements. Without
   * JS, or under prefers-reduced-motion, the final state simply renders.
   */
  animate?: boolean;
}

/**
 * The divergent digit: the prior record stacked above the new certified bound
 * in digit-aligned tabular Plex Mono. Shared leading digits stay in ink; the
 * digits from the first point of improvement print in record red; the beaten
 * tail of the prior is struck. A hairline tick and a small-caps margin note
 * mark the divergence column, and the full comparison is carried in prose by
 * the figure's aria-label — color is never the only channel.
 */
export function DivergentDigit({
  symbol,
  prior,
  priorApprox,
  priorLabel,
  next,
  nextApprox,
  nextLabel,
  animate = false,
}: DivergentDigitProps) {
  const ref = useRef<HTMLElement>(null);

  useEffect(() => {
    if (!animate) return;
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
  }, [animate]);

  let split = 0;
  while (split < prior.length && split < next.length && prior[split] === next[split]) split += 1;
  const shared = next.slice(0, split);
  const tail = next.slice(split);
  const priorShared = prior.slice(0, split);
  const priorStruck = prior.slice(split);
  const colStyle = { "--div-col": `${split}ch` } as CSSProperties;

  const aria =
    `${symbol ? `${symbol}: ` : ""}prior record ${priorApprox ? "approximately " : ""}${prior} (${priorLabel}), superseded; ` +
    `new certified bound ${nextApprox ? "approximately " : ""}${next}${nextLabel ? ` (${nextLabel})` : ""}. ` +
    `The two agree on “${shared}” and diverge at the next digit.`;

  return (
    <figure ref={ref} className="divergent" aria-label={aria}>
      {symbol && (
        <figcaption className="div-symbol" aria-hidden="true">
          {symbol}
        </figcaption>
      )}
      <div className="div-rows" aria-hidden="true">
        <div className="div-row">
          <span className="div-label">Prior</span>
          <span className="div-digits div-prior-digits" style={colStyle}>
            <span className="div-note">improvement begins</span>
            <span className="div-tick" />
            <span className="div-approx">{priorApprox ? "≈" : ""}</span>
            {priorShared}
            <s className="div-struck">{priorStruck}</s>
          </span>
          <span className="div-attrib">{priorLabel}</span>
        </div>
        <div className="div-row">
          <span className="div-label">New</span>
          <span className="div-digits">
            <span className="div-approx">{nextApprox ? "≈" : ""}</span>
            {shared}
            <span className="div-tail">
              {tail.split("").map((digit, index) => (
                <span key={index} style={{ "--pi": index } as CSSProperties}>
                  {digit}
                </span>
              ))}
            </span>
          </span>
          {nextLabel && <span className="div-attrib">{nextLabel}</span>}
        </div>
      </div>
    </figure>
  );
}
