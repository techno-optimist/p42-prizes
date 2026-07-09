import type { ReactNode } from "react";

const TOKEN = /("(?:sha256:|0x)[0-9a-fA-F:]+[^"]*"|sha256:[0-9a-f]{8,}|0x[0-9a-fA-F]{8,}|"-?\d+\/\d+"|"valid": true|"valid": false|\$ )/g;

function highlight(text: string): ReactNode[] {
  return text.split(TOKEN).map((part, i) => {
    if (i % 2 === 0) return part;
    if (part === "$ ") {
      return (
        <span key={i} className="tok-prompt">
          {part}
        </span>
      );
    }
    if (part.startsWith('"valid"')) {
      return (
        <span key={i} className={part.endsWith("true") ? "tok-valid" : "tok-hash"}>
          {part}
        </span>
      );
    }
    if (/^"?-?\d+\/\d+"?$/.test(part)) {
      return (
        <span key={i} className="tok-rational">
          {part}
        </span>
      );
    }
    return (
      <span key={i} className="tok-hash">
        {part}
      </span>
    );
  });
}

/**
 * A plate: the page's only dark object — machine output, quoted like a
 * numbered figure. The caption must always tell the reader how to
 * regenerate the plate's contents.
 */
export function Plate({ no, body, caption }: { no: string; body: string; caption: ReactNode }) {
  return (
    <figure className="plate">
      <div className="plate-body">
        <pre>{highlight(body)}</pre>
      </div>
      <figcaption className="plate-caption">
        <span className="plate-no">Plate {no}. </span>
        {caption}
      </figcaption>
    </figure>
  );
}
