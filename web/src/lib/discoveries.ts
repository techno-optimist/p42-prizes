/*
 * The discoveries — the four DOI'd, exact-certificate results the ProjectForty2
 * / CHRONOS agent stack produced before opening the protocol. This is the
 * credibility spearhead: real, published mathematics a forger cannot fake.
 *
 * Every value here is transcribed verbatim from the published Zenodo records
 * and their source repositories. DO NOT alter a bound, DOI, date, or prior-
 * record attribution — these are published claims, cited by DOI. Decimals that
 * are not the published exact value are marked ≈ and never computed with.
 *
 * Sources:
 *   - doi.org/10.5281/zenodo.21246903  (Erdős minimum overlap)
 *   - doi.org/10.5281/zenodo.21227361  (minimum autocorrelation)
 *   - doi.org/10.5281/zenodo.21221207  (Mertens-type LP ceilings)
 *   - doi.org/10.5281/zenodo.21194862  (three autoconvolution inequalities)
 */

export interface DiscoveryResult {
  /** the constant or quantity bounded, e.g. "C₁" or "S*(12000)" */
  symbol: string;
  /** KaTeX for the certified inequality, e.g. "\\mu \\le Q < 0.38086\\ldots" */
  tex: string;
  /** plain-text bound as published */
  bound: string;
  /** "upper" or "lower" bound */
  direction: "upper" | "lower";
  /** the prior record this improves on, with attribution */
  prior: string;
  /** one line on why this result matters */
  significance: string;
}

export interface Discovery {
  slug: string;
  /** short headline name of the object studied */
  constant: string;
  /** the published paper title */
  paperTitle: string;
  /** concept DOI, e.g. "10.5281/zenodo.21246903" */
  doi: string;
  doiUrl: string;
  /** ISO publication date of the cited version */
  date: string;
  repoUrl: string;
  /** what makes the certificate un-fakeable */
  method: string;
  /** one-sentence signal */
  headline: string;
  results: DiscoveryResult[];
  /** related on-site boards now open to push further */
  boardSlugs: string[];
}

export const DISCOVERIES_META = {
  count: 5,
  span: "4–9 July 2026",
  author: "Kevin Russell",
  lab: "ProjectForty2 · CHRONOS agent",
  // The shared property every result has and no forger can counterfeit.
  invariant: "exact integer / rational arithmetic — no floating point in the certified inequality",
} as const;

export const discoveries: Discovery[] = [
  {
    slug: "erdos-minimum-overlap",
    constant: "Erdős minimum overlap constant",
    paperTitle: "A tighter upper bound for the Erdős minimum overlap constant",
    doi: "10.5281/zenodo.21246903",
    doiUrl: "https://doi.org/10.5281/zenodo.21246903",
    date: "2026-07-07",
    repoUrl: "https://github.com/techno-optimist/erdos-minimum-overlap-bound",
    method: "Explicit step construction; overlap functional evaluated in exact integer arithmetic.",
    headline: "First proven improvement of the Erdős minimum-overlap upper bound since 2016.",
    results: [
      {
        symbol: "μ",
        tex: "\\mu \\;\\le\\; Q \\;<\\; 0.3808669097979875909124431",
        bound: "μ ≤ Q < 0.3808669097979875909124431",
        direction: "upper",
        prior: "Haugland (2016)",
        significance: "First proven improvement of the upper bound in a decade.",
      },
    ],
    boardSlugs: ["erdos-min-overlap"],
  },
  {
    slug: "minimum-autocorrelation",
    constant: "minimum-autocorrelation constant",
    paperTitle: "A certified lower bound for the minimum-autocorrelation constant",
    doi: "10.5281/zenodo.21227361",
    doiUrl: "https://doi.org/10.5281/zenodo.21227361",
    date: "2026-07-06",
    repoUrl: "https://github.com/techno-optimist/minimum-autocorrelation-bound",
    method: "Nonnegative step-function witness; certified exact-rational evaluation.",
    headline: "First improvement of the minimum-autocorrelation lower bound since 2020.",
    results: [
      {
        symbol: "C",
        tex: "C \\;\\ge\\; \\tfrac{2378625}{5958277} \\;\\approx\\; 0.39921356",
        bound: "C ≥ 2378625/5958277 ≈ 0.39921356",
        direction: "lower",
        prior: "Barnard & Steinerberger (2020), 0.37",
        significance: "First improvement of the lower bound since 2020.",
      },
    ],
    boardSlugs: [],
  },
  {
    slug: "mertens-lp-ceiling",
    constant: "Mertens-type extremal LP",
    paperTitle: "Certified ceilings for a finitary Mertens-type extremal problem (EinsteinArena PNT benchmark)",
    doi: "10.5281/zenodo.21221207",
    doiUrl: "https://doi.org/10.5281/zenodo.21221207",
    date: "2026-07-06",
    repoUrl: "https://github.com/techno-optimist/pnt-ceiling-certificates",
    method:
      "Exact-rational weak-duality dual certificates; interval arithmetic and big-integer residuals, no unenclosed floats in the certified inequality.",
    headline: "Provable ceilings for the EinsteinArena PNT extremal program, in exact arithmetic.",
    results: [
      {
        symbol: "S*(4800)",
        tex: "S^{*}(4800) \\;\\le\\; 0.9963688817172828744325041",
        bound: "S*(4800) ≤ 0.9963688817172828744325041",
        direction: "upper",
        prior: "EinsteinArena PNT benchmark",
        significance: "Certified ceiling on the scoring rule at reach 4800.",
      },
      {
        symbol: "S*(12000)",
        tex: "S^{*}(12000) \\;\\le\\; 0.9974876103072528157057480",
        bound: "S*(12000) ≤ 0.9974876103072528157057480",
        direction: "upper",
        prior: "EinsteinArena PNT benchmark",
        significance: "Certified ceiling at reach 12000.",
      },
    ],
    boardSlugs: ["mertens-lp-ceiling-k12000", "pnt-sparse-mertens-construction"],
  },
  {
    slug: "autoconvolution-inequalities",
    constant: "three autoconvolution inequalities",
    paperTitle:
      "Exact-arithmetic certificates for three autoconvolution inequalities, with machine-verified re-evaluations of four published constructions",
    doi: "10.5281/zenodo.21194862",
    doiUrl: "https://doi.org/10.5281/zenodo.21194862",
    date: "2026-07-04",
    repoUrl: "https://github.com/techno-optimist/autoconvolution-inequality-certificates",
    method: "Machine-verified re-evaluation of published constructions, promoted to exact proven status.",
    headline: "Three autoconvolution inequalities certified exactly — two beat the prior float-only records.",
    results: [
      {
        symbol: "C₁",
        tex: "C_1 \\;\\le\\; Q_1 \\;<\\; 1.50285031",
        bound: "C₁ ≤ Q₁ < 1.50285031",
        direction: "upper",
        prior: "π/2 ≈ 1.5707963 (Schinzel–Schmidt); sub-1.51 literature was float-only",
        significance: "Best proven upper bound in the sub-1.51 regime.",
      },
      {
        symbol: "C₂",
        tex: "C_2 \\;\\ge\\; Q_2 \\;>\\; 0.96290110",
        bound: "C₂ ≥ Q₂ > 0.96290110",
        direction: "lower",
        prior: "0.94136 (Jaech & Joseph, float-only)",
        significance: "Re-certified their construction to exact proven status, exceeding it.",
      },
      {
        symbol: "C₃",
        tex: "C_3 \\;\\le\\; Q_3 \\;<\\; 1.45230434",
        bound: "C₃ ≤ Q₃ < 1.45230434",
        direction: "upper",
        prior: "no rigorously certified nontrivial bound existed, either direction",
        significance: "First exact-certified bound for the signed variant.",
      },
    ],
    boardSlugs: ["autoconvolution-c1-upper", "autoconvolution-c2-lower", "signed-autoconvolution-c3-upper"],
  },
  {
    slug: "antipodal-kissing",
    constant: "60°-line systems & antipodal kissing (dims 11–12)",
    paperTitle: "Exact certificates for 60-degree line systems and antipodal kissing in R^11 and R^12",
    doi: "10.5281/zenodo.21285878",
    doiUrl: "https://doi.org/10.5281/zenodo.21285878",
    date: "2026-07-09",
    repoUrl: "https://github.com/techno-optimist/antipodal-kissing-bounds",
    method:
      "Delsarte linear-programming bound in exact rational arithmetic — rational Gegenbauer recurrence over ℚ and Sturm root counting to prove negativity on [−1/2, 1/2]; no floating point in the certified inequality.",
    headline:
      "Improved exact upper bounds for antipodal kissing configurations in dimensions 11 and 12 — beating the 2024 numerical record with an exact certificate.",
    results: [
      {
        symbol: "60° lines, ℝ¹¹",
        tex: "N_{11} \\le 410",
        bound: "≤ 410",
        direction: "upper",
        prior: "434 (trivial halving)",
        significance: "Improved 60°-line-system upper bound in ℝ¹¹, below the trivial-halving 434.",
      },
      {
        symbol: "60° lines, ℝ¹²",
        tex: "N_{12} \\le 614",
        bound: "≤ 614",
        direction: "upper",
        prior: "677 (trivial halving)",
        significance: "Improved 60°-line-system upper bound in ℝ¹², below the trivial-halving 677.",
      },
      {
        symbol: "antipodal kissing, ℝ¹¹",
        tex: "K_{11} \\le 820",
        bound: "≤ 820",
        direction: "upper",
        prior: "868 (Leijenhorst & de Laat, 2024)",
        significance:
          "First exact-certificate improvement of the antipodal kissing bound in ℝ¹¹, beating Leijenhorst & de Laat (2024).",
      },
      {
        symbol: "antipodal kissing, ℝ¹²",
        tex: "K_{12} \\le 1228",
        bound: "≤ 1228",
        direction: "upper",
        prior: "1355 (Leijenhorst & de Laat, 2024)",
        significance:
          "First exact-certificate improvement of the antipodal kissing bound in ℝ¹², beating Leijenhorst & de Laat (2024).",
      },
    ],
    boardSlugs: [],
  },
];
