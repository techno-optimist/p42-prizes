"use client";

import { useEffect, useMemo, useState } from "react";
import type { CSSProperties } from "react";
import { H4, Mark } from "@/components/Mark";

const PAIRS = [
  [0, 1],
  [0, 2],
  [0, 3],
  [1, 2],
  [1, 3],
  [2, 3],
] as const;

const ENTRY_VECTORS = [
  [-148, -128, -16],
  [-42, -158, 11],
  [72, -146, -9],
  [158, -92, 15],
  [-172, -34, 10],
  [94, -86, -20],
  [-106, 72, 14],
  [180, 8, -13],
  [-138, 96, -11],
  [-28, 138, 17],
  [82, 104, -18],
  [154, 64, 8],
  [-98, 174, 14],
  [18, 152, -8],
  [114, 162, 12],
  [176, 126, -17],
] as const;

function rowLabel(index: number) {
  return `r${index + 1}`;
}

function sign(value: number) {
  return value === 1 ? "+" : "-";
}

function dotTerms(a: number, b: number) {
  return H4[a].map((value, index) => value * H4[b][index]);
}

function phaseLabel(step: number) {
  if (step < 3) return "seed H1";
  if (step < 9) return "sylvester lift";
  if (step < 16) return "grow H4";
  if (step < 23) return "orthogonality sweep";
  return "record sealed";
}

export function HadamardEasterEgg() {
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);
  const proofRows = useMemo(
    () =>
      PAIRS.map(([a, b]) => {
        const terms = dotTerms(a, b);
        return {
          id: `${a}-${b}`,
          lhs: `${rowLabel(a)} · ${rowLabel(b)}`,
          terms: terms.map((value) => (value === 1 ? "+1" : "-1")).join(" "),
          value: terms.reduce((sum, value) => sum + value, 0),
        };
      }),
    [],
  );

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("mark") === "1" || window.location.hash === "#mark") {
      setOpen(true);
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    setStep(0);
    const interval = window.setInterval(() => {
      setStep((current) => Math.min(current + 1, 26));
    }, 120);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.clearInterval(interval);
      document.body.style.overflow = previousOverflow;
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  return (
    <>
      <button
        className="brand-mark-button"
        type="button"
        aria-label="Open the Hadamard mark"
        title="Hadamard mark"
        onClick={() => setOpen(true)}
      >
        <Mark size={30} animated />
      </button>

      {open ? (
        <div className="hadamard-modal" role="presentation" onMouseDown={() => setOpen(false)}>
          <section
            className="hadamard-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="hadamard-dialog-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <button className="hadamard-close" type="button" aria-label="Close" onClick={() => setOpen(false)}>
              ×
            </button>
            <div className="hadamard-stage" aria-hidden="true">
              <div className="hadamard-orbit">
                <Mark size={112} animated className="hadamard-stage-mark" />
              </div>
              <div className="hadamard-matrix" style={{ "--egg-step": step } as CSSProperties}>
                {H4.flatMap((row, i) =>
                  row.map((value, j) => {
                    const index = i * 4 + j;
                    const [fromX, fromY, fromRotate] = ENTRY_VECTORS[index];
                    return (
                      <span
                        key={`${i}-${j}`}
                        className={`hadamard-cell ${value === 1 ? "is-plus" : "is-minus"}${
                          step >= index ? " is-live" : ""
                        }`}
                        style={
                          {
                            "--cell-index": index,
                            "--from-x": `${fromX}px`,
                            "--from-y": `${fromY}px`,
                            "--from-rotate": `${fromRotate}deg`,
                          } as CSSProperties
                        }
                      >
                        {sign(value)}
                      </span>
                    );
                  }),
                )}
              </div>
              <div className="hadamard-readout">
                <div>
                  <span>{phaseLabel(step)}</span>
                  <code>{String(Math.min(step, 23)).padStart(2, "0")}/23</code>
                </div>
                <i style={{ "--readout-progress": Math.min(step, 23) / 23 } as CSSProperties} />
              </div>
            </div>
            <div className="hadamard-proof">
              <p className="smallcaps">The mark is not decoration</p>
              <h2 id="hadamard-dialog-title">H₄ verifies itself.</h2>
              <p>
                The logo is the solved order-4 Hadamard instance: sixteen signs, six row-pair checks, one canonical
                zero-defect witness.
              </p>
              <div className="proof-trace" aria-label="Hadamard row orthogonality trace">
                {proofRows.map((row, index) => {
                  const active = step >= 16 + index;
                  return (
                    <div key={row.id} className={`proof-line${active ? " is-live" : ""}`}>
                      <span>{row.lhs}</span>
                      <code>{active ? `${row.terms} = ${row.value}` : "···"}</code>
                    </div>
                  );
                })}
              </div>
              <div className={`verdict-seal${step >= 23 ? " is-live" : ""}`}>
                <span>VerdictReport</span>
                <strong>valid · defect 0/1 · improvement 1/1</strong>
              </div>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}
