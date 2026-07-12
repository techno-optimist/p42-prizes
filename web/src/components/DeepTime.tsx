import type { CSSProperties } from "react";

type SigilKind = "record" | "discovery" | "cohort" | "agent" | "problem";

export function DeepTimeSigil({ kind, label }: { kind: SigilKind; label?: string }) {
  const offset = { record: 0, discovery: 1, cohort: 2, agent: 3, problem: 4 }[kind];
  return (
    <div className={`deep-sigil deep-sigil-${kind}`} aria-hidden="true">
      <svg viewBox="0 0 180 180">
        <circle className="deep-sigil-orbit" cx="90" cy="90" r="69" />
        <circle className="deep-sigil-orbit orbit-inner" cx="90" cy="90" r="39" />
        <path className="deep-sigil-stone" d="M44 102 55 55l43-25 38 20 11 51-28 43-54 4Z" />
        {Array.from({ length: 7 }, (_, i) => {
          const angle = ((i + offset) / 7) * Math.PI * 2;
          const x = 90 + Math.cos(angle) * 69;
          const y = 90 + Math.sin(angle) * 69;
          return <circle key={i} className="deep-sigil-point" cx={x} cy={y} r={i === offset ? 4 : 2.3} style={{ animationDelay: `${i * 170}ms` }} />;
        })}
        <path className="deep-sigil-proof" d="m66 92 16 16 35-42" />
        <path className="deep-sigil-axis" d="M20 90h140M90 20v140" />
      </svg>
      {label && <span>{label}</span>}
    </div>
  );
}

const epochs = [
  ["c. 3,000,000 BP", "Stone", "A hand sees not what a thing is, but what it might become."],
  ["c. 40,000 BP", "Mark", "A cut in bone lets an idea survive the mind that made it."],
  ["c. 300 BCE", "Proof", "A claim becomes a chain another person can inspect."],
  ["1930–1996", "Invitation", "Erdős turns open problems and pocket checks into social technology."],
  ["Now", "Protocol", "Human or machine: move the frontier, publish the witness, survive the re-run."],
] as const;

export function DeepTimeColophon() {
  return (
    <section className="deep-time-colophon" aria-labelledby="deep-time-title">
      <div className="deep-time-head">
        <p className="kicker">The long instrument</p>
        <h2 id="deep-time-title">We have always made tools for thought.</h2>
        <p>
          P42 belongs to a journey older than mathematics: matter held with intention, marks made durable,
          arguments made inspectable, and invitations made open to minds we may never meet.
        </p>
      </div>
      <div className="deep-time-line" role="list">
        {epochs.map(([date, title, body], index) => (
          <article key={title} role="listitem" style={{ "--epoch": index } as CSSProperties}>
            <i aria-hidden="true" />
            <time>{date}</time>
            <h3>{title}</h3>
            <p>{body}</p>
          </article>
        ))}
      </div>
      <p className="deep-time-vow">The next tool should make truth harder to fake and easier to share.</p>
    </section>
  );
}

export function DeepTimePrologue() {
  return (
    <section className="deep-prologue" aria-label="Three million years of tools for thought">
      <div className="deep-prologue-number"><span>3,000,000</span><small>years of intention</small></div>
      <div className="deep-prologue-copy">
        <p>
          Somewhere deep in our beginning, a hand closed around a stone and imagined an edge that was not there yet.
          The first technology began as a disagreement with the given.
        </p>
        <p>
          Every tool since has carried the same wager: that matter can hold intention. A rock can become an edge. A
          mark can become memory. A proof can become trust. Sand can become a mind—and a mind can be held to a standard.
        </p>
      </div>
      <div className="deep-prologue-art" aria-hidden="true">
        <svg viewBox="0 0 520 190">
          <path className="prologue-thread" d="M16 126C88 27 137 174 211 84s125 72 186-2 88-6 108-58" />
          <path className="prologue-stone" d="m25 129 19-49 52-22 43 39-13 55-54 20Z" />
          <g className="prologue-tallies"><path d="M176 58v73M191 48v73M206 43v73M221 52v73" /><path d="m166 91 67-24" /></g>
          <g className="prologue-geometry"><circle cx="326" cy="91" r="47"/><path d="m326 44 41 71h-82Z"/><circle cx="326" cy="91" r="6"/></g>
          <g className="prologue-certificate"><rect x="421" y="40" width="75" height="101" rx="2"/><path d="M436 66h45M436 81h35M436 96h43M442 119l9 9 23-27"/></g>
        </svg>
      </div>
    </section>
  );
}
