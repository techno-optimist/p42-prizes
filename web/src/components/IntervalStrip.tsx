/**
 * Interval strip: a full-measure number line with a hairline axis, an ink
 * tick at the prior record and a record-red tick at the certified bound. The
 * traversed span is drawn as a 2px record-red segment — the same stroke as
 * the frontier chart's payout drop, because it is the same object: the Δ the
 * protocol pays for. Rendered static by design: the discovery entries'
 * one-animation-per-viewport budget is spent on the divergent-digit print.
 *
 * Number() here positions marks on a decorative axis only — the certified
 * quantities themselves are never computed with floats anywhere on the site.
 */
export function IntervalStrip({
  priorValue,
  priorApprox,
  priorLabel,
  boundValue,
  boundApprox,
  boundText,
}: {
  priorValue: string;
  priorApprox?: boolean;
  priorLabel: string;
  boundValue: string;
  boundApprox?: boolean;
  /** the full published bound, carried verbatim in the aria-label */
  boundText: string;
}) {
  const a = Number(priorValue);
  const b = Number(boundValue);
  const lo = Math.min(a, b);
  const hi = Math.max(a, b);
  const pad = (hi - lo) * 0.35 || 1;
  const x = (v: number) => 24 + ((v - (lo - pad)) / ((hi + pad) - (lo - pad))) * (720 - 48);
  const xa = x(a);
  const xb = x(b);
  const axisY = 34;
  const anchor = (xx: number) => (xx < 90 ? "start" : xx > 630 ? "end" : "middle");

  return (
    <figure className="interval-strip">
      <svg
        viewBox="0 0 720 56"
        role="img"
        aria-label={`Number line: prior record at ${priorApprox ? "approximately " : ""}${priorValue} (${priorLabel}); certified bound: ${boundText}. The record-red segment spans the distance between them — the frontier improvement the protocol pays for.`}
      >
        <line className="strip-axis" x1="8" y1={axisY} x2="712" y2={axisY} />
        <line className="strip-span" x1={xa} y1={axisY} x2={xb} y2={axisY} />
        <line className="strip-tick-prior" x1={xa} y1={axisY - 7} x2={xa} y2={axisY + 7} />
        <line className="strip-tick-new" x1={xb} y1={axisY - 9} x2={xb} y2={axisY + 9} />
        <text className="strip-value" x={xa} y={axisY - 13} textAnchor={anchor(xa)}>
          {priorApprox ? "≈ " : ""}
          {priorValue}
        </text>
        <text className="strip-label" x={xa} y={axisY + 18} textAnchor={anchor(xa)}>
          {priorLabel}
        </text>
        <text className="strip-value is-new" x={xb} y={axisY - 13} textAnchor={anchor(xb)}>
          {boundApprox ? "≈ " : ""}
          {boundValue}
        </text>
        <text className="strip-label" x={xb} y={axisY + 18} textAnchor={anchor(xb)}>
          certified bound
        </text>
      </svg>
    </figure>
  );
}
