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
  packaged: boolean;
  plotX: number;
  plotY: number;
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
    packaged: Boolean(text(raw, ["p42_slug"])),
    plotX: 0,
    plotY: 0,
  };
}

function layoutRows(entries: unknown[]): AtlasRow[] {
  const rows = entries.map(normalize);
  const groups = new Map<string, AtlasRow[]>();
  for (const row of rows) {
    const key = `${row.fit}:${row.impact}`;
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  for (const group of groups.values()) {
    group.sort((left, right) => Number(left.id) - Number(right.id));
    group.forEach((row, index) => {
      if (group.length === 1) {
        row.plotX = 65 + row.fit * 9;
        row.plotY = 475 - row.impact * 4.5;
        return;
      }
      const angle = (index / group.length) * Math.PI * 2 - Math.PI / 2;
      const radius = 6 + Math.min(group.length, 5) * 1.5;
      row.plotX = 65 + row.fit * 9 + Math.cos(angle) * radius;
      row.plotY = 475 - row.impact * 4.5 + Math.sin(angle) * radius;
    });
  }
  return rows;
}

const unique = (rows: AtlasRow[], key: "boardability" | "reach" | "lane") =>
  [...new Set(rows.map((row) => row[key]).filter(Boolean))].sort((a, b) => a.localeCompare(b));

export function AtlasExplorer({ entries }: { entries: unknown[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const rows = useMemo(() => layoutRows(entries), [entries]);
  const [query, setQuery] = useState(() => params.get("q") ?? "");
  const [selected, setSelected] = useState<string | null>(null);
  const deferredQuery = useDeferredValue(query.trim().toLowerCase());
  const board = params.get("boardability") ?? "all";
  const reach = params.get("reach") ?? "all";
  const lane = params.get("lane") ?? "all";
  const packageState = params.get("package") ?? "all";

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
      && (lane === "all" || row.lane === lane)
      && (packageState === "all" || row.packaged === (packageState === "packaged"));
  }), [board, deferredQuery, lane, packageState, reach, rows]);

  const recommended = rows.filter((row) => row.boardability === "READY" && row.reach === "MOVABLE" && !row.packaged);
  const reserve = rows.filter((row) => row.boardability === "READY" && !row.packaged);

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

      <nav className="atlas-routes" aria-label="Atlas routing views">
        <RouteButton label="All deep audits" count={rows.length} active={board === "all" && reach === "all" && packageState === "all"} onClick={() => updateUrl({ boardability: "all", reach: "all", package: "all" })} />
        <RouteButton label="Recommended next" count={recommended.length} active={board === "READY" && reach === "MOVABLE" && packageState === "unpackaged"} onClick={() => updateUrl({ boardability: "READY", reach: "MOVABLE", package: "unpackaged" })} />
        <RouteButton label="Reserve boards" count={reserve.length} active={board === "READY" && reach === "all" && packageState === "unpackaged"} onClick={() => updateUrl({ boardability: "READY", reach: "all", package: "unpackaged" })} />
        <RouteButton label="Heavy verification" count={rows.filter((row) => row.boardability === "HEAVY").length} active={board === "HEAVY" && reach === "all"} onClick={() => updateUrl({ boardability: "HEAVY", reach: "all", package: "all" })} />
        <RouteButton label="Known walls" count={rows.filter((row) => row.boardability === "NONE").length} active={board === "NONE" && reach === "all"} onClick={() => updateUrl({ boardability: "NONE", reach: "all", package: "all" })} />
        <RouteButton label="P42 packages" count={rows.filter((row) => row.packaged).length} active={board === "all" && reach === "all" && packageState === "packaged"} onClick={() => updateUrl({ boardability: "all", reach: "all", package: "packaged" })} />
      </nav>

      <form className="atlas-controls" role="search" onSubmit={(event) => event.preventDefault()}>
        <label className="atlas-search">
          <span>Search title, frontier, or number</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} type="search" placeholder="e.g. discrepancy or 241" />
        </label>
        <AtlasSelect label="Boardability" value={board} values={unique(rows, "boardability")} onChange={(value) => updateUrl({ boardability: value })} />
        <AtlasSelect label="Research reach" value={reach} values={unique(rows, "reach")} onChange={(value) => updateUrl({ reach: value })} />
        <AtlasSelect label="Attack lane" value={lane} values={unique(rows, "lane")} onChange={(value) => updateUrl({ lane: value })} />
        <button className="atlas-clear" type="button" onClick={clear} disabled={!query && board === "all" && reach === "all" && lane === "all" && packageState === "all"}>Clear</button>
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
                <circle className="atlas-map-hit" cx={row.plotX} cy={row.plotY} r="18" aria-hidden="true" />
                <circle className={selected === row.id ? "atlas-map-dot is-selected" : "atlas-map-dot"} cx={row.plotX} cy={row.plotY} r={selected === row.id ? 10 : 7} onMouseEnter={() => setSelected(row.id)} onMouseLeave={() => setSelected(null)} onFocus={() => setSelected(row.id)} onBlur={() => setSelected(null)} />
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

function RouteButton({ label, count, active, onClick }: { label: string; count: number; active: boolean; onClick: () => void }) {
  return <button type="button" className={active ? "is-active" : undefined} aria-pressed={active} onClick={onClick}><span>{label}</span><b>{count}</b></button>;
}

function AtlasSelect({ label, value, values, onChange }: { label: string; value: string; values: string[]; onChange: (value: string) => void }) {
  return <label><span>{label}</span><select value={value} onChange={(event) => onChange(event.target.value)}><option value="all">All</option>{values.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>;
}
