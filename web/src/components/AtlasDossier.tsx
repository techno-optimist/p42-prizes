import Link from "next/link";
import { MathProse } from "@/components/MathProse";
import { sitePath } from "@/lib/site-paths";

type Entry = Record<string, unknown>;
const read = (entry: Entry, ...keys: string[]) => {
  for (const key of keys) if (entry[key] !== undefined && entry[key] !== null) return entry[key];
  return undefined;
};
const words = (value: unknown, fallback = "Not yet recorded in this snapshot.") => typeof value === "string" || typeof value === "number" ? String(value) : fallback;
const list = (value: unknown): unknown[] => Array.isArray(value) ? value : value ? [value] : [];

export function AtlasDossier({ entry: value }: { entry: unknown }) {
  const entry = value as Entry;
  const id = words(read(entry, "id", "slug", "problemId"), "unlisted");
  const number = words(read(entry, "number", "erdosNumber", "problemNumber"), id);
  const title = words(read(entry, "title", "name", "problem"), `Erdős problem ${number}`);
  const boardability = words(read(entry, "board_class"), "unassessed");
  const reach = words(read(entry, "beatable"), "unassessed");
  const lane = words(read(entry, "lane", "attackLane", "category"), "unclassified");
  const links = read(entry, "links") as Entry | undefined;
  const citations = [read(entry, "erdos_url"), ...list(links?.oeis), ...list(links?.arxiv)].filter(Boolean);
  const join = read(entry, "p42_slug");
  const compute = read(entry, "compute");

  return <article className="atlas-page atlas-dossier">
    <div className="running-head"><span>P42 Prizes · Erdős Atlas</span><span>entry {number} · research dossier</span></div>
    <nav className="atlas-back" aria-label="Breadcrumb"><Link href="/atlas">Atlas index</Link><span aria-hidden="true">/</span><span>Problem {number}</span></nav>
    <header className="atlas-dossier-head">
      <p className="atlas-kicker">Erdős problem {number} · {boardability}</p>
      <h1><MathProse>{title}</MathProse></h1>
      <p className="atlas-deck"><MathProse>{words(read(entry, "summary", "statement", "description", "abstract"))}</MathProse></p>
      <dl className="atlas-dossier-facts"><div><dt>Boardability</dt><dd>{boardability}</dd></div><div><dt>Research reach</dt><dd>{reach}</dd></div><div><dt>Attack lane</dt><dd>{lane}</dd></div></dl>
    </header>
    <div className="atlas-dossier-grid">
      <div className="atlas-dossier-body">
        <DossierSection no="01" title="Current frontier evidence" value={frontierText(entry)} />
        <DossierSection no="02" title="Finite object" value={read(entry, "finite_object")} />
        <DossierSection no="03" title="Verifier" value={read(entry, "verifier")} />
        <DossierSection no="04" title="Attack lane" value={read(entry, "attack")} />
        <HistoricalAssessment value={read(entry, "verdict")} />
        <DossierSection no="06" title="Why this verifier class" value={read(entry, "board_class_reason")} />
        <DossierSection no="07" title="Why pursue or stop" value={read(entry, "beatable_reason", "wall_reason")} />
        <DossierSection no="08" title="Prior campaign findings" value={read(entry, "campaign_finding")} />
        {compute !== undefined && <ComputeCoverage value={compute} />}
      </div>
      <aside className="atlas-dossier-aside" aria-label="Dossier references and scope">
        <section><h2>Citations</h2>{citations.length ? <ol className="atlas-citations">{citations.map((citation, index) => <Citation key={index} citation={citation} />)}</ol> : <p>No bibliography was recorded for this entry in the snapshot.</p>}</section>
        <section><h2>Research scores</h2><p>Verifier fit: {words(read(entry, "fit_score"), "unscored")}/10<br />Mathematical impact: {words(read(entry, "impact_score"), "unscored")}/10</p></section>
        <section><h2>Impact rationale</h2><p><MathProse>{words(read(entry, "impact_reason"))}</MathProse></p></section>
        <section><h2>Scope note</h2><p>This dossier is a research-routing assessment. READY means an exact finite verifier is plausible; it is not a compute recommendation. Only READY + MOVABLE entries enter the recommended queue. No label asserts that the problem is solved, that a finite check proves the original statement, or that a P42 prize board has been admitted.</p></section>
        {join !== undefined && <section className="atlas-join"><h2>P42 join</h2><Join value={join} /></section>}
      </aside>
    </div>
  </article>;
}

function HistoricalAssessment({ value }: { value: unknown }) {
  if (value === undefined || value === null) return null;
  return <section className="atlas-dossier-section atlas-historical-assessment"><span>05</span><div>
    <h2>Historical snapshot assessment</h2>
    <p className="atlas-assessment-note">Retained for provenance. Current routing follows the frontier evidence and charted compute above.</p>
    <p><MathProse>{words(value)}</MathProse></p>
  </div></section>;
}

function ComputeCoverage({ value }: { value: unknown }) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const compute = value as Entry;
  const coverage = list(read(compute, "coverage")).filter((item) => item && typeof item === "object") as Entry[];
  return <section className="atlas-dossier-section atlas-compute"><span>09</span><div>
    <h2>Charted compute</h2>
    <p><MathProse>{words(read(compute, "result", "limits"))}</MathProse></p>
    {coverage.length > 0 && <div className="atlas-coverage" role="list" aria-label="Recorded compute coverage">
      {coverage.map((record, index) => {
        const axis = words(read(record, "axis"), "parameter");
        const start = words(read(record, "start"), "?");
        const end = words(read(record, "end"), start);
        const where = read(record, "where");
        const constraints = where && typeof where === "object" && !Array.isArray(where)
          ? Object.entries(where as Entry).map(([key, item]) => `${key}=${words(item, "?")}`).join(", ")
          : "";
        return <article key={`${axis}-${start}-${end}-${index}`} role="listitem">
          <div><b>{words(read(record, "status"), "RECORDED")}</b><span>{axis} {start === end ? start : `${start}–${end}`}{constraints ? ` · ${constraints}` : ""}</span></div>
          <p><MathProse>{words(read(record, "result"))}</MathProse></p>
        </article>;
      })}
    </div>}
    <small>Coverage records route compute; they do not establish prize eligibility or settlement authority.</small>
  </div></section>;
}

function DossierSection({ no, title, value }: { no: string; title: string; value: unknown }) {
  return <section className="atlas-dossier-section"><span>{no}</span><div><h2>{title}</h2>{Array.isArray(value) ? <ul>{value.map((item, index) => <li key={index}><MathProse>{words(typeof item === "object" ? JSON.stringify(item) : item)}</MathProse></li>)}</ul> : <p><MathProse>{words(value)}</MathProse></p>}</div></section>;
}

function frontierText(entry: Entry) {
  const frontier = read(entry, "frontier");
  if (frontier && typeof frontier === "object") {
    const item = frontier as Entry;
    return [read(item, "summary", "value"), read(item, "holder") && `Holder: ${words(read(item, "holder"))}.`, read(item, "year") && `Recorded: ${words(read(item, "year"))}.`, read(item, "note")].filter(Boolean).join(" ");
  }
  return read(entry, "current_record");
}

function Citation({ citation }: { citation: unknown }) {
  if (typeof citation === "string") {
    const href = citation.startsWith("http") ? citation : citation.startsWith("A") ? `https://oeis.org/${citation}` : `https://arxiv.org/abs/${citation}`;
    const label = citation.includes("erdosproblems.com") ? "Erdős Problems source entry" : citation.startsWith("A") ? `OEIS ${citation}` : citation.startsWith("http") ? citation : `arXiv:${citation}`;
    return <li><a href={href} target="_blank" rel="noreferrer">{label}</a></li>;
  }
  const item = citation as Entry;
  const label = words(read(item, "label", "title", "citation", "name"), "Source");
  const href = read(item, "url", "href", "doiUrl");
  return <li>{typeof href === "string" ? <a href={href} target="_blank" rel="noreferrer">{label}</a> : label}</li>;
}

function Join({ value }: { value: unknown }) {
  if (typeof value === "string") return <a className="atlas-join-link" href={sitePath(`/problems/${encodeURIComponent(value)}`)}>Open P42 board →</a>;
  if (typeof value === "boolean") return <p>{value ? "A P42 connection is recorded for this entry." : "No P42 board is currently joined."}</p>;
  const join = value as Entry;
  const href = read(join, "url", "href", "path");
  return <>{read(join, "note", "status", "description") && <p>{words(read(join, "note", "status", "description"))}</p>}{typeof href === "string" && <a className="atlas-join-link" href={href}>Open P42 board →</a>}</>;
}
