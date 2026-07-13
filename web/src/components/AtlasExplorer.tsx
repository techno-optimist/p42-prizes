"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useDeferredValue, useEffect, useMemo, useState } from "react";

type RawEntry = Record<string, unknown>;

type AtlasRow = {
  raw: RawEntry;
  id: string;
  number: string;
  title: string;
  summary: string;
  boardability: string;
  reach: string;
  lane: string;
  fit: number;
  impact: number;
};

const text = (entry: RawEntry, keys: string[], fallback = "") => {
  for (const key of keys) {
    const value = entry[key];
    if (typeof value === "string" || typeof value === "number") return String(value);
  }
  return fallback;
};

const score = (entry: RawEntry, keys: string[], fallback: number) => {
  const value = Number(text(entry, keys));
  if (!Number.isFinite(value)) return fallback;
  return Math.min(100, value * 10);
};

function normalize(entry: unknown, index: number): AtlasRow {
  const raw = entry as RawEntry;
  const id = text(raw, ["id", "slug", "problemId"], String(index + 1));
  return {
    raw,
    id,
    number: text(raw, ["number", "erdosNumber", "problemNumber"], id),
    title: text(raw, ["title", "name", "problem"], `Erdős problem ${id}`),
    summary: text(raw, ["summary", "current_record", "statement"]),
    boardability: text(raw, ["board_class"], "unassessed"),
    reach: text(raw, ["beatable"], "unassessed"),
    lane: text(raw, ["lane", "attackLane", "category"], "unclassified"),
    fit: score(raw, ["fit_score"], 50),
    impact: score(raw, ["impact_score"], 50),
  };
}

const unique = (rows: AtlasRow[], key: "boardability" | "reach" | "lane") =>
  [...new Set(rows.map((row) => row[key]).filter(Boolean))].sort((a, b) => a.localeCompare(b));

export function AtlasExplorer({ entries }: { entries: unknown[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const rows = useMemo(() => entries.map(normalize), [entries]);
  const [query, setQuery] = useState(() => params.get("q") ?? "");
  const [selected, setSelected] = useState<string | null>(null);
  const deferredQuery = useDeferredValue(query.trim().toLowerCase());
  const board = params.get("boardability") ?? "all";
  const reach = params.get("reach") ?? "all";
  const lane = params.get("lane") ?? "all";

  const updateUrl = useCallback((changes: Record<string, string>) => {
    const next = new URLSearchParams(params.toString());
    for (const [key, value] of Object.entries(changes)) {
      if (!value || value === "all") next.delete(key);
      else next.set(key, value);
    }
    router.replace(`${pathname}${next.size ? `?${next}` : ""}`, { scroll: false });
  }, [params, pathname, router]);

  useEffect(() => {
    const timer = window.setTimeout(() => updateUrl({ q: query.trim() }), 180);
    return () => window.clearTimeout(timer);
  }, [query, updateUrl]);

  const filtered = useMemo(() => rows.filter((row) => {
    const haystack = `${row.number} ${row.title} ${row.summary} ${row.lane}`.toLowerCase();
    return (!deferredQuery || haystack.includes(deferredQuery))
      && (board === "all" || row.boardability === board)
      && (reach === "all" || row.reach === reach)
      && (lane === "all" || row.lane === lane);
  }), [board, deferredQuery, lane, reach, rows]);

  const clear = () => {
    setQuery("");
    router.replace(pathname, { scroll: false });
  };

  return (
    <section className="atlas-explorer" aria-labelledby="atlas-explorer-title">
      <div className="atlas-section-head">
        <div>
          <p className="atlas-kicker">Interactive index</p>
          <h2 id="atlas-explorer-title">Fit against impact</h2>
        </div>
        <output aria-live="polite">{filtered.length} of {rows.length} entries</output>
      </div>

      <form className="atlas-controls" role="search" onSubmit={(event) => event.preventDefault()}>
        <label className="atlas-search">
          <span>Search title, frontier, or number</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} type="search" placeholder="e.g. discrepancy or 241" />
        </label>
        <AtlasSelect label="Boardability" value={board} values={unique(rows, "boardability")} onChange={(value) => updateUrl({ boardability: value })} />
        <AtlasSelect label="Research reach" value={reach} values={unique(rows, "reach")} onChange={(value) => updateUrl({ reach: value })} />
        <AtlasSelect label="Attack lane" value={lane} values={unique(rows, "lane")} onChange={(value) => updateUrl({ lane: value })} />
        <button className="atlas-clear" type="button" onClick={clear} disabled={!query && board === "all" && reach === "all" && lane === "all"}>Clear</button>
      </form>

      <div className="atlas-map-wrap">
        <div className="atlas-map-heading">
          <p><b>Region map.</b> Each mark is one surveyed problem. Focus or hover a mark to locate its table row.</p>
          <span aria-hidden="true">higher impact ↑</span>
        </div>
        <svg className="atlas-map" viewBox="0 0 1000 520" role="img" aria-labelledby="atlas-map-title atlas-map-desc">
          <title id="atlas-map-title">Erdős problems by verifier fit and mathematical impact</title>
          <desc id="atlas-map-desc">An interactive scatter plot. Horizontal position is verifier fit; vertical position is mathematical impact. Every point is also listed in the table below.</desc>
          <g aria-hidden="true" className="atlas-regions">
            <rect x="65" y="25" width="450" height="225" /><rect x="515" y="25" width="450" height="225" />
            <rect x="65" y="250" width="450" height="225" /><rect x="515" y="250" width="450" height="225" />
            <text x="88" y="58">deep theory</text><text x="538" y="58">priority frontier</text>
            <text x="88" y="452">long-horizon survey</text><text x="538" y="452">verifier workshop</text>
            <line x1="65" y1="475" x2="965" y2="475" /><line x1="65" y1="25" x2="65" y2="475" />
            <text x="515" y="510" textAnchor="middle">verifier fit →</text>
          </g>
          <g>
            {filtered.map((row) => (
              <Link key={row.id} href={`/atlas/${encodeURIComponent(row.id)}`} aria-label={`Erdős ${row.number}: ${row.title}. Verifier fit ${Math.round(row.fit)}, impact ${Math.round(row.impact)}.`}>
                <circle className={selected === row.id ? "is-selected" : ""} cx={65 + row.fit * 9} cy={475 - row.impact * 4.5} r={selected === row.id ? 10 : 7} tabIndex={0} onMouseEnter={() => setSelected(row.id)} onMouseLeave={() => setSelected(null)} onFocus={() => setSelected(row.id)} onBlur={() => setSelected(null)} />
              </Link>
            ))}
          </g>
        </svg>
      </div>

      <div className="atlas-table-wrap" tabIndex={0} aria-label="Scrollable Atlas results">
        <table className="atlas-table">
          <thead><tr><th scope="col">№</th><th scope="col">Problem and frontier</th><th scope="col">Boardability</th><th scope="col">Reach</th><th scope="col">Lane</th><th scope="col">Fit / impact</th></tr></thead>
          <tbody>
            {filtered.map((row) => (
              <tr key={row.id} className={selected === row.id ? "is-selected" : undefined} onMouseEnter={() => setSelected(row.id)} onMouseLeave={() => setSelected(null)}>
                <td className="atlas-number">{row.number}</td>
                <th scope="row"><Link href={`/atlas/${encodeURIComponent(row.id)}`} onFocus={() => setSelected(row.id)} onBlur={() => setSelected(null)}>{row.title}</Link>{row.summary && <small>{row.summary}</small>}</th>
                <td><span className="atlas-tag">{row.boardability}</span></td><td>{row.reach}</td><td>{row.lane}</td><td className="atlas-scores"><b>{Math.round(row.fit / 10)}</b><span>/</span>{Math.round(row.impact / 10)}</td>
              </tr>
            ))}
            {filtered.length === 0 && <tr><td colSpan={6} className="atlas-empty">No entries match these filters. <button type="button" onClick={clear}>Reset the index</button></td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function AtlasSelect({ label, value, values, onChange }: { label: string; value: string; values: string[]; onChange: (value: string) => void }) {
  return <label><span>{label}</span><select value={value} onChange={(event) => onChange(event.target.value)}><option value="all">All</option>{values.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>;
}
