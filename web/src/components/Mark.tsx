import type { CSSProperties } from "react";

export const H4 = [
  [1, 1, 1, 1],
  [1, -1, 1, -1],
  [1, 1, -1, -1],
  [1, -1, -1, 1],
];

const CELL = 20;
const GAP = 4;
const PAD = 2;
const DIGIT_Y = 10;
const DIGIT_W = 38;
const DIGIT_H = 76;
const DIGIT_T = 7;

const SEGMENTS = {
  a: (x: number) => ({ x: x + DIGIT_T, y: DIGIT_Y, width: DIGIT_W - 2 * DIGIT_T, height: DIGIT_T }),
  b: (x: number) => ({
    x: x + DIGIT_W - DIGIT_T,
    y: DIGIT_Y + DIGIT_T,
    width: DIGIT_T,
    height: DIGIT_H / 2 - DIGIT_T * 1.5,
  }),
  c: (x: number) => ({
    x: x + DIGIT_W - DIGIT_T,
    y: DIGIT_Y + DIGIT_H / 2 + DIGIT_T / 2,
    width: DIGIT_T,
    height: DIGIT_H / 2 - DIGIT_T * 1.5,
  }),
  d: (x: number) => ({
    x: x + DIGIT_T,
    y: DIGIT_Y + DIGIT_H - DIGIT_T,
    width: DIGIT_W - 2 * DIGIT_T,
    height: DIGIT_T,
  }),
  e: (x: number) => ({
    x,
    y: DIGIT_Y + DIGIT_H / 2 + DIGIT_T / 2,
    width: DIGIT_T,
    height: DIGIT_H / 2 - DIGIT_T * 1.5,
  }),
  f: (x: number) => ({
    x,
    y: DIGIT_Y + DIGIT_T,
    width: DIGIT_T,
    height: DIGIT_H / 2 - DIGIT_T * 1.5,
  }),
  g: (x: number) => ({
    x: x + DIGIT_T,
    y: DIGIT_Y + DIGIT_H / 2 - DIGIT_T / 2,
    width: DIGIT_W - 2 * DIGIT_T,
    height: DIGIT_T,
  }),
};

const DIGIT_SEGMENTS = [
  ...(["f", "g", "b", "c"] as const).map((segment) => SEGMENTS[segment](5)),
  ...(["a", "b", "g", "e", "d"] as const).map((segment) => SEGMENTS[segment](53)),
];

/**
 * The P42 mark rests as an unsolved digital "42" display and resolves into the
 * order-4 Hadamard matrix: every pair of rows orthogonal, defect 0/1.
 */
export function Mark({
  size = 34,
  title = "P42 mark: digital 42 resolving into the order-4 Hadamard matrix",
  className = "",
  animated = false,
}: {
  size?: number;
  title?: string;
  className?: string;
  animated?: boolean;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 96 96"
      role="img"
      aria-label={title}
      className={`p42-mark${animated ? " p42-mark-animated" : ""}${className ? ` ${className}` : ""}`}
    >
      {H4.flatMap((row, i) =>
        row.map((v, j) => {
          const index = i * 4 + j;
          return (
            <rect
              key={`${i}-${j}`}
              className={`p42-mark-cell ${v === 1 ? "is-plus" : "is-minus"}`}
              style={
                {
                  "--mark-i": index,
                  "--mark-solved-opacity": v === 1 ? 1 : 0.18,
                } as CSSProperties
              }
              x={PAD + j * (CELL + GAP)}
              y={PAD + i * (CELL + GAP)}
              width={CELL}
              height={CELL}
              rx={3}
              ry={3}
            />
          );
        }),
      )}
      {DIGIT_SEGMENTS.map((segment, index) => (
        <rect
          key={`digit-${index}`}
          className="p42-mark-digit-segment"
          style={{ "--segment-i": index } as CSSProperties}
          {...segment}
          rx={2}
          ry={2}
        />
      ))}
    </svg>
  );
}
