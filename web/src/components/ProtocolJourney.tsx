"use client";

import { useEffect, useMemo, useState } from "react";
type Mode = "search" | "construct" | "verify";
const modes: Record<Mode, { label: string; note: string; readout: string }> = {
  search: { label: "Continuous search", note: "A smooth optimizer can approach the boundary indefinitely without landing on the exact crystal.", readout: "loss ↓ · margin → 0" },
  construct: { label: "Exact construction", note: "The hidden symmetry appears: every point has an antipode. Geometry becomes 302 lines through the origin.", readout: "x ↦ −x · 302 pairs" },
  verify: { label: "Certificate", note: "The checker recomputes every inner product from rational coordinates. Nothing is accepted on trust.", readout: "exact · gap 0 · accepted" },
};
function makePoints(count: number) {
  return Array.from({ length: count }, (_, index) => {
    const pair = Math.floor(index / 2), theta = pair * 2.399963229728653;
    const ring = 0.31 + ((pair * 17) % 61) / 100, antipode = index % 2 ? Math.PI : 0;
    return { x: 50 + Math.cos(theta + antipode) * ring * 39, y: 50 + Math.sin(theta + antipode) * ring * 39 };
  });
}
export function PackingLab() {
  const [mode, setMode] = useState<Mode>("search");
  const [active, setActive] = useState(0);
  const cloud = useMemo(() => makePoints(94), []);
  useEffect(() => {
    if (mode !== "search") return;
    const timer = window.setInterval(() => setActive((v) => (v + 1) % cloud.length), 90);
    return () => window.clearInterval(timer);
  }, [cloud.length, mode]);
  return <div className={`packing-lab packing-${mode}`}>
    <div className="packing-controls" role="group" aria-label="Packing demonstration mode">
      {(Object.keys(modes) as Mode[]).map((key, i) => <button key={key} className={mode === key ? "active" : ""} onClick={() => setMode(key)}><span>0{i + 1}</span>{modes[key].label}</button>)}
    </div>
    <div className="packing-stage">
      <svg viewBox="0 0 100 100" role="img" aria-label={`${modes[mode].label} projection`}>
        <circle className="packing-boundary" cx="50" cy="50" r="42" />
        {mode !== "search" && cloud.filter((_, i) => i % 2 === 0).map((p, i) => <line key={i} x1={p.x} y1={p.y} x2={100-p.x} y2={100-p.y} />)}
        {cloud.map((p, i) => <circle key={i} className={`packing-point ${i === active ? "probe" : ""}`} cx={mode === "search" ? p.x + Math.sin(active*.2+i)*1.7 : p.x} cy={mode === "search" ? p.y + Math.cos(active*.17+i)*1.7 : p.y} r={mode === "verify" && i%2===0 ? 1.18 : .82} />)}
        <circle className="packing-core" cx="50" cy="50" r="8.5" />
        {mode === "verify" && <path className="packing-check" d="M75 78l5 5 10-13" />}
      </svg>
      <div className="packing-readout"><span className="smallcaps">Current lens</span><strong>{modes[mode].label}</strong><p>{modes[mode].note}</p><code>{modes[mode].readout}</code></div>
    </div>
  </div>;
}
export function VerifierSwitch() {
  const [verified, setVerified] = useState(false);
  return <div className={`verifier-switch ${verified ? "is-verified" : ""}`}>
    <div className="verifier-input"><span className="smallcaps">Candidate witness</span><code>coordinates.json</code><span>604 vectors · rational entries</span></div>
    <button onClick={() => setVerified(v => !v)}><span>{verified ? "Reset proof" : "Run exact verifier"}</span><i>→</i></button>
    <div className="verifier-output" aria-live="polite"><span className="smallcaps">Verdict report</span><strong>{verified ? "ACCEPTED" : "WAITING"}</strong><code>{verified ? "gap = 0 · exact" : "no claim yet"}</code></div>
  </div>;
}
export function Reveal({ children, className="" }: { children: React.ReactNode; className?: string }) {
  const [visible, setVisible] = useState(false), [node, setNode] = useState<HTMLDivElement|null>(null);
  useEffect(() => { if (!node) return; const o = new IntersectionObserver(([e]) => e.isIntersecting && setVisible(true), {threshold:.16}); o.observe(node); return () => o.disconnect(); }, [node]);
  return <div ref={setNode} className={`journey-reveal ${visible ? "is-visible" : ""} ${className}`}>{children}</div>;
}
