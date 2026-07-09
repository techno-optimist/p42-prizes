import katex from "katex";

export function MathBlock({ tex, className }: { tex: string; className?: string }) {
  const html = katex.renderToString(tex, {
    displayMode: true,
    throwOnError: false,
    strict: "ignore",
  });
  return (
    <div
      className={className ? `math-block ${className}` : "math-block"}
      role="math"
      aria-label={tex}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

export function MathInline({ tex }: { tex: string }) {
  const html = katex.renderToString(tex, {
    displayMode: false,
    throwOnError: false,
    strict: "ignore",
  });
  return <span className="math-inline" role="math" aria-label={tex} dangerouslySetInnerHTML={{ __html: html }} />;
}
