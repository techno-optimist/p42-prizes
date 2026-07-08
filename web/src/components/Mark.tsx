const H4 = [
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
export function Mark({ size = 34, title = "P42 mark: the order-4 Hadamard matrix" }: { size?: number; title?: string }) {
  const plus: string[] = [];
  const minus: string[] = [];
  H4.forEach((row, i) =>
    row.forEach((v, j) => {
      const x = PAD + j * (CELL + GAP);
      const y = PAD + i * (CELL + GAP);
      (v === 1 ? plus : minus).push(`M${x} ${y + 3}a3 3 0 0 1 3-3h14a3 3 0 0 1 3 3v14a3 3 0 0 1-3 3h-14a3 3 0 0 1-3-3z`);
    }),
  );
  return (
    <svg width={size} height={size} viewBox="0 0 96 96" role="img" aria-label={title} className="p42-mark">
      <path d={plus.join("")} fill="currentColor" />
      <path d={minus.join("")} fill="currentColor" fillOpacity={0.18} />
    </svg>
  );
}
