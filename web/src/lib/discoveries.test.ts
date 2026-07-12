import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { DiscoveryEntry, ROMAN } from "@/components/DiscoveryEntry";
import { discoveries, DISCOVERIES_META } from "@/lib/discoveries";

describe("discoveries archive", () => {
  it("keeps catalogue metadata, numerals, and DOIs in one-to-one agreement", () => {
    expect(discoveries).toHaveLength(DISCOVERIES_META.count);
    expect(ROMAN.length).toBeGreaterThanOrEqual(discoveries.length);
    expect(new Set(discoveries.map((discovery) => discovery.doi)).size).toBe(discoveries.length);
  });

  it("renders every published entry without invalid numeric SVG attributes", () => {
    const markup = discoveries
      .map((discovery, index) =>
        renderToStaticMarkup(
          createElement(DiscoveryEntry, {
            discovery,
            numeral: ROMAN[index],
            full: true,
          }),
        ),
      )
      .join("");

    expect(markup).not.toContain('="NaN"');
    expect(markup).toContain("VI.");
    expect(markup).toContain("10.5281/zenodo.21318881");
  });
});
