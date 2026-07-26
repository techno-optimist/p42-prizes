import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { isValidTex, looksMathematical, MathProse, proseTokenToTex } from "@/components/MathProse";
import { AtlasDossier } from "@/components/AtlasDossier";
import { atlasEntries } from "@/lib/atlas";

describe("Atlas math prose", () => {
  it("renders compact mathematical tokens through KaTeX", () => {
    const markup = renderToStaticMarkup(
      createElement(MathProse, null, "For A⊆{1..N}, test |A|≤N/3+O(1) and N_0 exactly."),
    );

    expect(markup).toContain("katex");
    expect(markup).toContain("subseteq");
    expect(markup).toContain("N_{0}");
  });

  it("does not treat prize amounts as math delimiters", () => {
    const markup = renderToStaticMarkup(createElement(MathProse, null, "The settled prize was $100."));
    expect(markup).not.toContain("katex");
    expect(markup).toContain("$100");
  });

  it("normalizes common Atlas notation into TeX", () => {
    expect(looksMathematical("a|(b+c)")).toBe(true);
    expect(proseTokenToTex("a|(b+c)")).toContain(String.raw`a\mid (b+c)`);
    expect(proseTokenToTex("|A|≤N_0")).toContain(String.raw`\lvert A\rvert\le N_{0}`);
    expect(proseTokenToTex("R(k)^{1/k}")).toContain("^{1/k}");
    expect(proseTokenToTex("b_i+b_j+b_k")).toBe("b_{i}+b_{j}+b_{k}");
    expect(looksMathematical("2^k-block")).toBe(false);
    expect(isValidTex("min_{x")).toBe(false);
  });

  it("renders every Atlas dossier without KaTeX parse errors", () => {
    const markup = atlasEntries
      .map((entry) => renderToStaticMarkup(createElement(AtlasDossier, { entry })))
      .join("");

    expect(markup).toContain("katex");
    expect(markup).not.toContain("katex-error");
  });

  it("labels legacy snapshot verdicts as historical context", () => {
    const corrected = atlasEntries.find((entry) => entry.id === 552);
    expect(corrected).toBeDefined();
    const markup = renderToStaticMarkup(createElement(AtlasDossier, { entry: corrected! }));

    expect(markup).toContain("Current frontier evidence");
    expect(markup).toContain("Historical snapshot assessment");
    expect(markup).toContain("Current routing follows the frontier evidence and charted compute above.");
  });
});
