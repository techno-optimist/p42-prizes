import Link from "next/link";
import type { ReactNode } from "react";
import { DivergentDigit } from "@/components/DivergentDigit";
import { IntervalStrip } from "@/components/IntervalStrip";
import { MathBlock } from "@/components/Math";
import { getProblemBySlug } from "@/lib/data";
import type { Discovery, DiscoveryResult } from "@/lib/discoveries";

export const ROMAN = ["I", "II", "III", "IV"] as const;

/** thin-space grouping of a decimal's digits in blocks of five —
 *  the mathematical-table convention. Display only; never computed with. */
export function groupDigits(value: string): string {
  const dot = value.indexOf(".");
  if (dot === -1) return value;
  return value.slice(0, dot + 1) + value.slice(dot + 1).replace(/(\d{5})(?=\d)/g, "$1 ");
}

/** the trailing numeral of a published bound string, e.g.
 *  "μ ≤ Q < 0.3808…" → "0.3808…". Extraction, not transcription. */
export function finalNumeral(bound: string): string {
  return bound.slice(bound.lastIndexOf(" ") + 1);
}

/**
 * A bound specimen: the certified numeral in Plex Mono, grouped in blocks of
 * five with thin spaces, a 2px record-red tick ruled beneath, one attribution
 * line. The sr-only twin carries the ungrouped bound.
 */
export function BoundSpecimen({
  rel,
  bound,
  attribution,
  hero = false,
}: {
  rel?: string;
  bound: string;
  attribution: ReactNode;
  hero?: boolean;
}) {
  return (
    <figure className={hero ? "specimen specimen-hero" : "specimen"}>
      <p className="specimen-line">
        {rel && (
          <span className="specimen-rel" aria-hidden="true">
            {rel}
          </span>
        )}
        <span className="specimen-digits" aria-hidden="true">
          {groupDigits(bound)}
        </span>
        <span className="sr-only">{rel ? `${rel} ${bound}` : bound}</span>
      </p>
      <span className="specimen-tick" aria-hidden="true" />
      <figcaption className="specimen-attrib">{attribution}</figcaption>
    </figure>
  );
}

/* The divergent-digit devices. Used ONLY where discoveries.ts records BOTH
 * the new bound and a prior numeral; every numeral and attribution below is
 * transcribed from the `prior` / `bound` fields — nothing is invented. */
interface DigitDevice {
  symbol?: string;
  resultSymbol: string;
  prior: string;
  priorApprox?: boolean;
  priorLabel: string;
  stripPriorLabel: string;
  next: string;
  nextApprox?: boolean;
  nextLabel?: string;
}

const DIGIT_DEVICES: Record<string, DigitDevice[]> = {
  "minimum-autocorrelation": [
    {
      resultSymbol: "C",
      prior: "0.37",
      priorLabel: "Barnard & Steinerberger (2020)",
      stripPriorLabel: "Barnard & Steinerberger (2020)",
      next: "0.39921356",
      nextApprox: true,
      nextLabel: "exact: 2378625/5958277",
    },
  ],
  "autoconvolution-inequalities": [
    {
      symbol: "C₁",
      resultSymbol: "C₁",
      prior: "1.5707963",
      priorApprox: true,
      priorLabel: "π/2 (Schinzel–Schmidt)",
      stripPriorLabel: "π/2 · Schinzel–Schmidt",
      next: "1.50285031",
      nextLabel: "certified upper bound",
    },
    {
      symbol: "C₂",
      resultSymbol: "C₂",
      prior: "0.94136",
      priorLabel: "Jaech & Joseph (float-only)",
      stripPriorLabel: "Jaech & Joseph · float-only",
      next: "0.96290110",
      nextLabel: "certified lower bound",
    },
  ],
};

/* The bound each open board is seeded from — verbatim decimals from
 * discoveries.ts, mapped to the board that pays for beating them. Boards
 * with no unambiguous seed bound (the sparse construction split) get none. */
const BRIDGE_TARGETS: Record<string, string> = {
  "erdos-min-overlap": "0.3808669097979875909124431",
  "autoconvolution-c1-upper": "1.50285031",
  "autoconvolution-c2-lower": "0.96290110",
  "signed-autoconvolution-c3-upper": "1.45230434",
  "mertens-lp-ceiling-k12000": "0.9974876103072528157057480",
};

/** Priors that read as superseded records are struck in record red; a
 *  benchmark name or "no prior existed" statement is not a record and is
 *  never struck. The strike pairs with the words themselves, so color is
 *  not the only channel. */
function PriorText({ slug, result }: { slug: string; result: DiscoveryResult }) {
  if (slug === "erdos-minimum-overlap" || slug === "minimum-autocorrelation" || result.symbol === "C₂") {
    return <s className="prior-struck">{result.prior}</s>;
  }
  if (result.symbol === "C₁") {
    const splitAt = result.prior.indexOf("; ");
    if (splitAt !== -1) {
      return (
        <>
          <s className="prior-struck">{result.prior.slice(0, splitAt)}</s>
          {result.prior.slice(splitAt)}
        </>
      );
    }
  }
  return <>{result.prior}</>;
}

/** The bridge from a record to the board that pays for beating it. Board
 *  status is read live from the register: "Now open" is printed only for a
 *  board that is actually runnable; boards under admission say so, in gate
 *  umber; a missing board is an honest em-dash. */
function BridgeLines({ discovery }: { discovery: Discovery }) {
  if (discovery.boardSlugs.length === 0) {
    return <p className="bridge-none">— no board yet · admission pending</p>;
  }
  return (
    <div className="disc-bridge">
      {discovery.boardSlugs.map((slug) => {
        const problem = getProblemBySlug(slug);
        if (!problem) return null;
        const target = BRIDGE_TARGETS[slug];
        const open = problem.status === "open" || problem.status === "pilot";
        return (
          <p key={slug}>
            {open ? <>Now open — </> : <span className="bridge-gate">In admission — </span>}
            <Link className="bridge-link" href={`/problems/${slug}`}>
              Board № {problem.id} · {target ? <>beat {groupDigits(target)}</> : problem.title} →
            </Link>
            {!open && <span className="bridge-gate"> · gates published, not yet runnable</span>}
          </p>
        );
      })}
    </div>
  );
}

function headlineCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

/**
 * One discovery, set as a scaled-up bibliography record: constant, paper
 * title, running mono line, the certified inequality (or a mini book-table
 * for multi-result entries), the divergent digit or bound specimen, the
 * PRIOR / METHOD / CERTIFICATE apparatus, an evidence-tier stamp, and the
 * bridge to the board that pays. `full` adds the headline, per-result
 * significance, and the interval strips for /discoveries.
 */
export function DiscoveryEntry({
  discovery,
  numeral,
  full = false,
}: {
  discovery: Discovery;
  numeral: string;
  full?: boolean;
}) {
  const single = discovery.results.length === 1;
  const devices = DIGIT_DEVICES[discovery.slug] ?? [];
  const repoShort = discovery.repoUrl.replace("https://github.com/", "");

  return (
    <article className="discovery" id={discovery.slug}>
      <span className="disc-numeral" aria-hidden="true">
        {numeral}.
      </span>
      <div className="disc-body">
        <div className="disc-head">
          <div>
            <h3 className="disc-constant">
              <span className="sr-only">{numeral}. </span>
              {headlineCase(discovery.constant)}
            </h3>
            <p className="disc-paper">{discovery.paperTitle}</p>
            <p className="disc-running">
              <span>{discovery.date}</span>
              <a className="ref" href={discovery.doiUrl} target="_blank" rel="noreferrer">
                doi:{discovery.doi}
              </a>
              <a className="ref" href={discovery.repoUrl} target="_blank" rel="noreferrer">
                {repoShort}
              </a>
            </p>
          </div>
          <span className="fixture-stamp disc-stamp">published record · DOI resolves · claimed-elsewhere tier</span>
        </div>

        {full && <p className="disc-headline">{discovery.headline}</p>}

        {single ? (
          <>
            <div className="disc-math" aria-hidden="true">
              <MathBlock tex={discovery.results[0].tex} />
            </div>
            <p className="sr-only">Certified: {discovery.results[0].bound}</p>
          </>
        ) : (
          <div className="disc-table-wrap">
            <table className="register disc-table">
              <thead>
                <tr>
                  <th>Quantity</th>
                  <th>Certified bound</th>
                  <th>Direction</th>
                  <th>Prior</th>
                </tr>
              </thead>
              <tbody>
                {discovery.results.map((result) => (
                  <tr key={result.symbol}>
                    <td className="num">{result.symbol}</td>
                    <td className="num">{result.bound}</td>
                    <td className="disc-dir">{result.direction}</td>
                    <td className="disc-prior-cell">
                      <PriorText slug={discovery.slug} result={result} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Per-result significance earns its place only in multi-result entries,
            where it distinguishes the rows. For a single result the headline (and,
            for Erdős, the specimen attribution) already carries it — no echo. */}
        {full && !single && (
          <ul className="disc-signifs">
            {discovery.results.map((result) => (
              <li key={result.symbol}>
                <span className="num">{result.symbol}</span> — {result.significance}
              </li>
            ))}
          </ul>
        )}

        {discovery.slug === "erdos-minimum-overlap" && (
          <BoundSpecimen
            rel="μ ≤ Q <"
            bound={finalNumeral(discovery.results[0].bound)}
            attribution={
              <>
                Prior record <s className="prior-struck">Haugland (2016)</s> — {discovery.results[0].significance}
              </>
            }
          />
        )}

        {devices.map((device) => (
          <DivergentDigit
            key={device.resultSymbol}
            symbol={device.symbol}
            prior={device.prior}
            priorApprox={device.priorApprox}
            priorLabel={device.priorLabel}
            next={device.next}
            nextApprox={device.nextApprox}
            nextLabel={device.nextLabel}
            animate={discovery.slug === "minimum-autocorrelation"}
          />
        ))}

        {full &&
          devices.map((device) => {
            const result = discovery.results.find((r) => r.symbol === device.resultSymbol);
            if (!result) return null;
            return (
              <IntervalStrip
                key={`strip-${device.resultSymbol}`}
                priorValue={device.prior}
                priorApprox={device.priorApprox}
                priorLabel={device.stripPriorLabel}
                boundValue={device.next}
                boundApprox={device.nextApprox}
                boundText={result.bound}
              />
            );
          })}

        <dl className="apparatus">
          {single && (
            <div>
              <dt>Prior</dt>
              <dd>
                <PriorText slug={discovery.slug} result={discovery.results[0]} />
              </dd>
            </div>
          )}
          <div>
            <dt>Method</dt>
            <dd className="mono-line">{discovery.method}</dd>
          </div>
          <div>
            <dt>Certificate</dt>
            <dd>
              <a className="ref" href={discovery.doiUrl} target="_blank" rel="noreferrer">
                doi:{discovery.doi}
              </a>{" "}
              ·{" "}
              <a className="ref" href={discovery.repoUrl} target="_blank" rel="noreferrer">
                {repoShort}
              </a>
            </dd>
          </div>
        </dl>

        <BridgeLines discovery={discovery} />
      </div>
    </article>
  );
}
