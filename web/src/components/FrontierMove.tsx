"use client";

import { useEffect, useRef } from "react";

export interface FrontierMoveProps {
  /** the full sentence twin read by assistive tech */
  ariaLabel: string;
  /** numeric position of the certified bound (float — used ONLY to place a
   *  tick; the label carries the exact published string, never this number) */
  boundValue: number;
  /** exact published bound numeral for the label, e.g. "≈0.39921356" */
  boundText: string;
  /** which way is "better" for this result's objective */
  better: "left" | "right";
  /** present only where discoveries.ts gives a real prior numeral */
  prior?: {
    value: number;
    text: string;
    label: string;
    /** printed as "held since {year}" when a year is on record */
    year?: string;
  };
  /** for results with no prior numeral: the prior stated as text, never plotted */
  priorAnnotation?: string;
  /** the open-frontier label past the bound (a board's Δ-gate, or its absence) */
  openLabel: string;
  compact?: boolean;
  animate?: boolean;
}

const PLOT_L = 56;
const PLOT_R = 664;
const AXIS_Y = 62;

function anchorFor(x: number): "start" | "middle" | "end" {
  if (x < 118) return "start";
  if (x > 602) return "end";
  return "middle";
}

/**
 * FrontierMove — an animated "record move" chart, one per result. A hairline
 * value axis; where a real prior numeral exists, an ink tick (attribution +
 * "held since {year}") and a 2px record-red Δ segment drawn from prior to the
 * certified-bound tick — the same stroke as the frontier staircase's payout
 * drop, because it is the same quantity: the distance the protocol pays for.
 * Where no prior numeral exists, only the certified tick lands (prior as text).
 *
 * The Δ segment / bound tick draw once on first scroll-into-view. Without JS or
 * under prefers-reduced-motion the chart renders in its finished state — the
 * base styles are the final frame; motion is layered on by the `play` class.
 * Never plots a number that is not in the real data: a lone bound draws only
 * its own tick, never a fabricated second point.
 */
export function FrontierMove({
  ariaLabel,
  boundValue,
  boundText,
  better,
  prior,
  priorAnnotation,
  openLabel,
  compact = false,
  animate = false,
}: FrontierMoveProps) {
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
      { threshold: 0.4 },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [animate]);

  // Domain: with a prior, span both values and pad each side (the padding on
  // the better side hosts the open-frontier continuation). Without a prior,
  // a modest symmetric window centred on the lone bound — no implied second
  // point, just breathing room and a direction.
  let dLo: number;
  let dHi: number;
  if (prior) {
    const lo = Math.min(prior.value, boundValue);
    const hi = Math.max(prior.value, boundValue);
    const span = Math.max(hi - lo, 1e-12);
    dLo = lo - span * 0.5;
    dHi = hi + span * 0.5;
  } else {
    const hw = Math.max(Math.abs(boundValue) * 0.05, 0.02);
    dLo = boundValue - hw;
    dHi = boundValue + hw;
  }
  const x = (v: number) => PLOT_L + ((v - dLo) / (dHi - dLo)) * (PLOT_R - PLOT_L);
  const bx = x(boundValue);

  const betterEdge = better === "right" ? PLOT_R : PLOT_L;
  const arrowTip = betterEdge;
  const arrowBase = better === "right" ? betterEdge - 8 : betterEdge + 8;
  const arrowPts =
    better === "right"
      ? `${arrowTip},${AXIS_Y} ${arrowBase},${AXIS_Y - 4} ${arrowBase},${AXIS_Y + 4}`
      : `${arrowTip},${AXIS_Y} ${arrowBase},${AXIS_Y - 4} ${arrowBase},${AXIS_Y + 4}`;
  const openLabelX = better === "right" ? PLOT_R : PLOT_L;
  const openLabelAnchor = better === "right" ? "end" : "start";

  return (
    <figure
      ref={ref}
      className={`frontier-move${compact ? " is-compact" : ""}${prior ? "" : " is-noprior"}`}
    >
      <svg viewBox="0 0 720 112" role="img" aria-label={ariaLabel}>
        {/* the value axis — chrome, always present */}
        <line className="fm-axis" x1={PLOT_L} y1={AXIS_Y} x2={PLOT_R} y2={AXIS_Y} />

        {/* open-frontier continuation past the bound, toward "better" */}
        <g className="fm-open-g">
          <line className="fm-open" x1={bx} y1={AXIS_Y} x2={arrowBase} y2={AXIS_Y} />
          <polygon className="fm-arrow" points={arrowPts} />
          <text
            className="fm-label fm-open-label"
            x={openLabelX}
            y={AXIS_Y - 12}
            textAnchor={openLabelAnchor}
          >
            {openLabel}
          </text>
        </g>

        {prior && (
          <>
            {/* the record-red Δ segment: the distance the protocol pays for */}
            <line
              className="fm-delta"
              x1={x(prior.value)}
              y1={AXIS_Y}
              x2={bx}
              y2={AXIS_Y}
              pathLength={1}
            />
            <g className="fm-prior-g">
              <line
                className="fm-tick-prior"
                x1={x(prior.value)}
                y1={AXIS_Y - 7}
                x2={x(prior.value)}
                y2={AXIS_Y + 7}
              />
              <text
                className="fm-label fm-value"
                x={x(prior.value)}
                y={AXIS_Y - 16}
                textAnchor={anchorFor(x(prior.value))}
              >
                {prior.text}
              </text>
              <text
                className="fm-label fm-attrib"
                x={x(prior.value)}
                y={AXIS_Y + 24}
                textAnchor={anchorFor(x(prior.value))}
              >
                {prior.label}
              </text>
              {prior.year && (
                <text
                  className="fm-label fm-since"
                  x={x(prior.value)}
                  y={AXIS_Y + 37}
                  textAnchor={anchorFor(x(prior.value))}
                >
                  held since {prior.year}
                </text>
              )}
            </g>
          </>
        )}

        {!prior && (
          <line className="fm-sweep" x1={bx - 26} y1={AXIS_Y} x2={bx} y2={AXIS_Y} pathLength={1} />
        )}

        {/* the certified-bound tick — record red */}
        <g className="fm-bound-g">
          <line className="fm-tick-bound" x1={bx} y1={AXIS_Y - 9} x2={bx} y2={AXIS_Y + 9} />
          <text
            className="fm-label fm-value is-bound"
            x={bx}
            y={AXIS_Y - 16}
            textAnchor={anchorFor(bx)}
          >
            {boundText}
          </text>
          <text className="fm-label fm-attrib" x={bx} y={AXIS_Y + 24} textAnchor={anchorFor(bx)}>
            certified bound
          </text>
          {priorAnnotation && (
            <text className="fm-annot" x={bx} y={AXIS_Y + 37} textAnchor={anchorFor(bx)}>
              {priorAnnotation}
            </text>
          )}
        </g>
      </svg>
    </figure>
  );
}
