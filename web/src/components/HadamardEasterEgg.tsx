"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";
import { createPortal } from "react-dom";
import { H4, Mark } from "@/components/Mark";

const PAIRS = [
  [0, 1],
  [0, 2],
  [0, 3],
  [1, 2],
  [1, 3],
  [2, 3],
] as const;

const MAX_STEP = 23;
const TICK_MS = 135;
const SOLVED_HOLD_TICKS = 14;
const UNSOLVED_HOLD_TICKS = 6;
const THEME_STORAGE_KEY = "p42-prizes-theme";
const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

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

type Direction = 1 | -1;
type Theme = "light" | "dark";

function isTheme(value: string | null): value is Theme {
  return value === "light" || value === "dark";
}

function applySiteTheme(nextTheme: Theme) {
  document.documentElement.dataset.theme = nextTheme;
  document.documentElement.style.colorScheme = nextTheme;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
  } catch {
    // Theme persistence is a convenience; the toggle should still work without storage.
  }
}

function rowLabel(index: number) {
  return `r${index + 1}`;
}

function sign(value: number) {
  return value === 1 ? "+" : "-";
}

function dotTerms(a: number, b: number) {
  return H4[a].map((value, index) => value * H4[b][index]);
}

function phaseLabel(step: number, direction: Direction, hold: number) {
  if (step >= MAX_STEP && hold > 0) return "record sealed";
  if (direction === -1) {
    if (step >= MAX_STEP) return "release witness";
    if (step > 16) return "unseal proof";
    if (step > 8) return "unsolve H4";
    if (step > 0) return "candidate drift";
    return "seed cloud";
  }
  if (step < 3) return "seed H1";
  if (step < 9) return "sylvester lift";
  if (step < 16) return "grow H4";
  if (step < MAX_STEP) return "orthogonality sweep";
  return "record sealed";
}

function visibleFocusableElements(dialog: HTMLElement) {
  return Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter((element) => {
    if (element.hasAttribute("disabled") || element.getAttribute("aria-hidden") === "true") return false;
    return element.offsetParent !== null || element === document.activeElement;
  });
}

export function HadamardEasterEgg() {
  const [mounted, setMounted] = useState(false);
  const [open, setOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>("light");
  const [loop, setLoop] = useState<{ direction: Direction; hold: number; step: number }>({
    direction: 1,
    hold: 0,
    step: 0,
  });
  const triggerRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);
  const { direction, hold, step } = loop;
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
    setMounted(true);
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const requestedTheme = params.get("theme") ?? params.get("eggTheme");
    let storedTheme: string | null = null;
    try {
      storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
    } catch {
      storedTheme = null;
    }
    const preferredTheme =
      window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    const nextTheme = isTheme(requestedTheme)
      ? requestedTheme
      : isTheme(storedTheme)
        ? storedTheme
        : preferredTheme;
    setTheme(nextTheme);
    applySiteTheme(nextTheme);
    if (params.get("mark") === "1" || window.location.hash === "#mark") {
      setOpen(true);
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    setLoop({ direction: 1, hold: 0, step: 0 });
    const interval = window.setInterval(() => {
      setLoop((current) => {
        if (current.hold > 0) return { ...current, hold: current.hold - 1 };
        if (current.direction === 1) {
          if (current.step >= MAX_STEP) {
            return { direction: -1, hold: SOLVED_HOLD_TICKS, step: MAX_STEP };
          }
          return { ...current, step: current.step + 1 };
        }
        if (current.step <= 0) return { direction: 1, hold: UNSOLVED_HOLD_TICKS, step: 0 };
        return { ...current, step: current.step - 1 };
      });
    }, TICK_MS);
    return () => {
      window.clearInterval(interval);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false);
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = visibleFocusableElements(dialog);
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (event.shiftKey) {
        if (active === first || !dialog.contains(active)) {
          event.preventDefault();
          last.focus();
        }
        return;
      }
      if (active === last || !dialog.contains(active)) {
        event.preventDefault();
        first.focus();
      }
    };

    const background = document.querySelector<HTMLElement>(".shell");
    const previousActive = document.activeElement instanceof HTMLElement ? document.activeElement : triggerRef.current;
    const previousOverflow = document.body.style.overflow;
    const previousInert = background?.inert ?? false;
    const previousAriaHidden = background ? background.getAttribute("aria-hidden") : null;
    restoreFocusRef.current = previousActive;
    document.body.style.overflow = "hidden";
    if (background) {
      background.inert = true;
      background.setAttribute("aria-hidden", "true");
    }
    window.setTimeout(() => {
      (closeButtonRef.current ?? dialogRef.current)?.focus();
    }, 0);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
      if (background) {
        background.inert = previousInert;
        if (previousAriaHidden === null) {
          background.removeAttribute("aria-hidden");
        } else {
          background.setAttribute("aria-hidden", previousAriaHidden);
        }
      }
      const restoreTarget = restoreFocusRef.current;
      if (restoreTarget && document.contains(restoreTarget)) {
        restoreTarget.focus();
      }
      restoreFocusRef.current = null;
    };
  }, [open]);

  const modal = open ? (
    <div className="hadamard-modal" role="presentation" onMouseDown={() => setOpen(false)}>
      <section
        ref={dialogRef}
        className="hadamard-dialog"
        data-egg-theme={theme}
        role="dialog"
        aria-modal="true"
        aria-labelledby="hadamard-dialog-title"
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="hadamard-controls">
          <button
            className="hadamard-theme-toggle"
            type="button"
            aria-label={`Switch site to ${theme === "light" ? "dark" : "light"} mode`}
            aria-pressed={theme === "dark"}
            onClick={() => {
              const nextTheme = theme === "light" ? "dark" : "light";
              setTheme(nextTheme);
              applySiteTheme(nextTheme);
            }}
          >
            <span className={theme === "light" ? "is-active" : ""}>Light</span>
            <span className={theme === "dark" ? "is-active" : ""}>Dark</span>
          </button>
          <button
            ref={closeButtonRef}
            className="hadamard-close"
            type="button"
            aria-label="Close"
            onClick={() => setOpen(false)}
          >
            ×
          </button>
        </div>
        <div className="hadamard-stage" aria-hidden="true">
          <div className="hadamard-orbit">
            <Mark size={112} animated className="hadamard-stage-mark" />
          </div>
          <div
            className={`hadamard-matrix ${direction === -1 ? "is-releasing" : "is-solving"}`}
            style={{ "--egg-step": step } as CSSProperties}
          >
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
                        "--exit-index": 15 - index,
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
              <span>{phaseLabel(step, direction, hold)}</span>
              <code>{String(Math.min(step, MAX_STEP)).padStart(2, "0")}/{MAX_STEP}</code>
            </div>
            <i style={{ "--readout-progress": Math.min(step, MAX_STEP) / MAX_STEP } as CSSProperties} />
          </div>
        </div>
        <div className="hadamard-proof">
          <p className="smallcaps">The mark is not decoration</p>
          <h2 id="hadamard-dialog-title">H₄ verifies itself.</h2>
          <p>
            The logo starts as an unsolved digital 42 display, then resolves into the order-4 Hadamard witness:
            sixteen signs, six row-pair checks, one canonical zero-defect certificate.
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
  ) : null;

  return (
    <>
      <button
        ref={triggerRef}
        className="brand-mark-button"
        type="button"
        aria-label="Open the Hadamard mark"
        title="Hadamard mark"
        onClick={() => setOpen(true)}
      >
        <Mark size={30} animated />
      </button>
      {mounted && modal ? createPortal(modal, document.body) : null}
    </>
  );
}
