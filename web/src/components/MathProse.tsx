import { Fragment } from "react";
import katex from "katex";
import { MathInline } from "@/components/Math";

const EXPLICIT_MATH = /^\$(.+)\$$/s;
const EDGE_PUNCTUATION = /^(.*?)([;:!?.,]+)$/s;

export function MathProse({ children, className }: { children: string; className?: string }) {
  const pieces = children.split(/(\s+)/);
  return <span className={className ? `math-prose ${className}` : "math-prose"}>
    {pieces.map((piece, index) => {
      if (!piece || /^\s+$/.test(piece)) return <Fragment key={index}>{piece}</Fragment>;
      const edge = piece.match(EDGE_PUNCTUATION);
      const core = edge?.[1] || piece;
      const punctuation = edge?.[2] || "";
      const explicit = core.match(EXPLICIT_MATH);
      if (!explicit && !looksMathematical(core)) return <Fragment key={index}>{piece}</Fragment>;
      const tex = explicit ? explicit[1] : proseTokenToTex(core);
      if (!isValidTex(tex)) return <Fragment key={index}>{piece}</Fragment>;
      return <Fragment key={index}><MathInline tex={tex} />{punctuation}</Fragment>;
    })}
  </span>;
}

export function looksMathematical(token: string): boolean {
  if (!token || /^\$\d/.test(token)) return false;
  if (EXPLICIT_MATH.test(token)) return true;
  if (/#/.test(token) || /-[a-z]{2,}/.test(token) || !hasBalancedDelimiters(token)) return false;
  return (
    /[≤≥≪≫≳≈∞∈⊂⊆∩∪Στχαε√]/.test(token)
    || /[_^][{A-Za-z0-9+-]/.test(token)
    || /[A-Za-z0-9)]\|(?=[A-Za-z0-9(])/.test(token)
    || /[A-Za-z0-9|})][<>=+](?=[A-Za-z0-9|{(])/.test(token)
    || /^\|[^|]+\|/.test(token)
    || /^(?:[A-Za-z]{1,3}|lim|max|min|log|exp)\([^)]*[A-Za-z0-9][^)]*\)$/.test(token)
    || /^\{[^}]+\}$/.test(token)
  );
}

export function proseTokenToTex(token: string): string {
  return token
    .replace(/(?<![_^])\{([^{}]+)\}/g, String.raw`\left\{$1\right\}`)
    .replace(/\.\./g, String.raw`,\ldots,`)
    .replace(/…/g, String.raw`\ldots`)
    .replace(/<=|≤/g, String.raw`\le `)
    .replace(/>=|≥/g, String.raw`\ge `)
    .replace(/≪/g, String.raw`\ll `)
    .replace(/≫/g, String.raw`\gg `)
    .replace(/≳/g, String.raw`\gtrsim `)
    .replace(/≈/g, String.raw`\approx `)
    .replace(/∞/g, String.raw`\infty `)
    .replace(/∈/g, String.raw`\in `)
    .replace(/⊂/g, String.raw`\subset `)
    .replace(/⊆/g, String.raw`\subseteq `)
    .replace(/∩/g, String.raw`\cap `)
    .replace(/∪/g, String.raw`\cup `)
    .replace(/Σ/g, String.raw`\sum `)
    .replace(/√/g, String.raw`\sqrt `)
    .replace(/τ/g, String.raw`\tau `)
    .replace(/χ/g, String.raw`\chi `)
    .replace(/α/g, String.raw`\alpha `)
    .replace(/ε/g, String.raw`\varepsilon `)
    .replace(/([A-Za-z0-9)])\|(?=[A-Za-z0-9(])/g, String.raw`$1\mid `)
    .replace(/\|([^|]+)\|/g, String.raw`\lvert $1\rvert`)
    .replace(/\b(lim|max|min|log|exp)(?=\()/g, String.raw`\$1`)
    .replace(/_([A-Za-z0-9]+)/g, "_{$1}")
    .replace(/\^([A-Za-z0-9]+)/g, "^{$1}");
}

export function isValidTex(tex: string): boolean {
  try {
    katex.renderToString(tex, { throwOnError: true, strict: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function hasBalancedDelimiters(value: string): boolean {
  const pairs: Record<string, string> = { ")": "(", "]": "[", "}": "{" };
  const stack: string[] = [];
  for (const character of value) {
    if (character === "(" || character === "[" || character === "{") stack.push(character);
    if (character in pairs && stack.pop() !== pairs[character]) return false;
  }
  return stack.length === 0;
}
