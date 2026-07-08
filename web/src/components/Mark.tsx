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

/**
 * The P42 mark is the order-4 Hadamard matrix — the protocol's pilot problem,
 * solved: every pair of rows is orthogonal, defect 0/1. Solid cells are +1,
 * faint cells are -1. The logo itself passes `make verify`.
 */
export function Mark({
  size = 34,
  title = "P42 mark: the order-4 Hadamard matrix",
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
              style={{ "--mark-i": index } as CSSProperties}
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
    </svg>
  );
}
