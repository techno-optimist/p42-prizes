"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";

export interface FrontierPoint {
  /** ordinal position on the record ladder: 0 = declared seed, then each verified record */
  x: number;
  /** exact rational score, e.g. "6/1" */
  score: string;
  /** who established it: "seed" or the agent name */
  label: string;
  /** real date string for verified records; empty for the declared seed */
  dateLabel: string;
}

function toNumber(rational: string): number {
  const [num, den = "1"] = rational.split("/");
  return Number(num) / Number(den);
}

const W = 620;
const H = 190;
const PAD = { top: 18, right: 132, bottom: 26, left: 44 };

/**
 * The frontier staircase: the record score by record number. A step holds
 * until a verified submission beats it — the vertical drop drawn in record
 * red is the exact improvement the payout rule pays for. Single series; the
 * record citations beside it are the accessible twin. The x-axis is ordinal
 * (record №), never a fabricated timeline.
 */
export function FrontierChart({
  points,
  direction,
  scoreName,
  openGate,
}: {
  points: FrontierPoint[];
  direction: "minimize" | "maximize";
  scoreName: string;
  /** the blank-paper continuation past the last record: a board's admissible
   *  Δ-gate, or "optimum reached" where the record already sits at optimum */
  openGate?: string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const figureRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const el = figureRef.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          el.classList.add("play");
          observer.disconnect();
        }
      },
      { threshold: 0.35 },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const geom = useMemo(() => {
    const values = points.map((p) => toNumber(p.score));
    const x0 = Math.min(...points.map((p) => p.x));
    const x1 = Math.max(...points.map((p) => p.x));
    const span = Math.max(x1 - x0, 1);
    const vMin = Math.min(...values, 0);
    const vMax = Math.max(...values);
    const vSpan = Math.max(vMax - vMin, 1e-9);
    const x = (v: number) => PAD.left + ((v - x0) / span) * (W - PAD.left - PAD.right);
    const y = (v: number) => PAD.top + ((vMax - v) / vSpan) * (H - PAD.top - PAD.bottom);
    return { values, x, y, vMin, vMax };
  }, [points]);

  if (points.length === 0) return null;

  const { values, x, y, vMax, vMin } = geom;
  const endX = W - PAD.right;

  // step-after: a record holds until the next lands. Horizontal runs are ink;
  // the vertical drops (the paid-for improvement) are record red.
  const runs: string[] = [];
  const drops: string[] = [];
  for (let i = 0; i < points.length; i += 1) {
    const px = x(points[i].x);
    const py = y(values[i]);
    const nextX = i + 1 < points.length ? x(points[i + 1].x) : endX;
    runs.push(`M${px.toFixed(1)} ${py.toFixed(1)} H${nextX.toFixed(1)}`);
    if (i + 1 < points.length) {
      drops.push(`M${nextX.toFixed(1)} ${py.toFixed(1)} V${y(values[i + 1]).toFixed(1)}`);
    }
  }

  const last = points[points.length - 1];
  const lastY = y(values[values.length - 1]);

  const gridValues = [vMax, (vMax + vMin) / 2, vMin].filter(
    (v, i, arr) => arr.findIndex((w) => Math.abs(w - v) < 1e-9) === i,
  );

  function onMove(event: React.PointerEvent<SVGSVGElement>) {
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const px = ((event.clientX - rect.left) / rect.width) * W;
    let nearest = 0;
    let best = Infinity;
    points.forEach((p, i) => {
      const dx = Math.abs(x(p.x) - px);
      if (dx < best) {
        best = dx;
        nearest = i;
      }
    });
    setHover(nearest);
  }

  const hovered = hover === null ? null : points[hover];

  const stepCount = points.length;

  return (
    <figure className="frontier-chart" ref={figureRef} style={{ "--n": stepCount } as CSSProperties}>
      <figcaption>
        <span>
          Record {scoreName} by record № — {direction === "minimize" ? "lower is better" : "higher is better"}
        </span>
        <span className="frontier-direction">drops in red are the paid-for Δ</span>
      </figcaption>
      <div className="frontier-plot">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          role="img"
          aria-label={`Record ${scoreName}; current record ${last.score} held by ${last.label}${
            openGate ? `; ${openGate}` : ""
          }`}
          onPointerMove={onMove}
          onPointerLeave={() => setHover(null)}
          tabIndex={0}
          onKeyDown={(event) => {
            if (event.key === "ArrowRight") {
              event.preventDefault();
              setHover((h) => Math.min((h ?? -1) + 1, points.length - 1));
            }
            if (event.key === "ArrowLeft") {
              event.preventDefault();
              setHover((h) => Math.max((h ?? points.length) - 1, 0));
            }
            if (event.key === "Escape") setHover(null);
          }}
        >
          {gridValues.map((v) => (
            <g key={v}>
              <line className="chart-grid" x1={PAD.left} x2={endX} y1={y(v)} y2={y(v)} />
              <text className="chart-tick" x={PAD.left - 8} y={y(v) + 3} textAnchor="end">
                {Number.isInteger(v) ? v : `≈${v.toFixed(2)}`}
              </text>
            </g>
          ))}
          <line className="chart-axis" x1={PAD.left} x2={endX} y1={H - PAD.bottom} y2={H - PAD.bottom} />

          {hovered && (
            <line className="chart-crosshair" x1={x(hovered.x)} x2={x(hovered.x)} y1={PAD.top} y2={H - PAD.bottom} />
          )}

          {runs.map((d, i) => (
            <path
              key={d}
              className="chart-line"
              d={d}
              fill="none"
              pathLength={1}
              style={{ "--i": i } as CSSProperties}
            />
          ))}
          {drops.map((d, i) => (
            <path
              key={d}
              className="chart-drop"
              d={d}
              fill="none"
              pathLength={1}
              style={{ "--i": i } as CSSProperties}
            />
          ))}

          {/* open-frontier continuation: blank ruled paper past the last record */}
          {openGate && (
            <g className="chart-open-g">
              <line className="chart-open" x1={endX} y1={lastY} x2={W - 10} y2={lastY} pathLength={1} />
              <text className="chart-open-label" x={W - 10} y={lastY - 8} textAnchor="end">
                {openGate}
              </text>
            </g>
          )}

          {points.map((p, i) => (
            <circle
              key={`${p.x}-${p.score}`}
              className={`chart-dot ${i === points.length - 1 ? "is-last" : "is-step"}${
                i === hover ? " hovered" : ""
              }`}
              cx={x(p.x)}
              cy={y(toNumber(p.score))}
              r={i === points.length - 1 ? 4.5 : 3.5}
              style={{ "--i": i } as CSSProperties}
            />
          ))}

          <text className="chart-end-label" x={endX + 8} y={lastY - 8}>
            {last.score}
          </text>
        </svg>
        {hovered && (
          <div className="chart-tooltip" role="status">
            <strong>{hovered.score}</strong>
            <span>
              {hovered.label}
              {hovered.dateLabel ? ` · ${hovered.dateLabel}` : ""}
            </span>
          </div>
        )}
      </div>
    </figure>
  );
}
