import type { Metadata } from "next";
import Link from "next/link";
import "@fontsource/stix-two-text/400.css";
import "@fontsource/stix-two-text/400-italic.css";
import "@fontsource/stix-two-text/500.css";
import "@fontsource/stix-two-text/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "katex/dist/katex.min.css";
import "./globals.css";
import { HadamardEasterEgg } from "@/components/HadamardEasterEgg";
import { Mark } from "@/components/Mark";
import { discoveries } from "@/lib/discoveries";
import { sitePath } from "@/lib/site-paths";

export const metadata: Metadata = {
  metadataBase: new URL("https://projectforty2.ai"),
  title: "P42 Prizes — Register of Records",
  description:
    "Local Phase 0 simulation for future Base Sepolia open-math bounty mechanics: not deployed, audited, legally reviewed, or settling payments.",
  alternates: {
    canonical: sitePath("/"),
  },
  openGraph: {
    title: "P42 Prizes — The proof is the re-run.",
    description:
      "Local Phase 0 simulation for future Base Sepolia deterministic verifier mechanics; not deployed, audited, or settling bounties.",
    images: [{ url: sitePath("/og-phase0.png"), width: 1200, height: 630 }],
  },
};

const themeBootScript = `
try {
  var storedTheme = localStorage.getItem("p42-prizes-theme");
  var resolvedTheme =
    storedTheme === "light" || storedTheme === "dark"
      ? storedTheme
      : window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
  document.documentElement.dataset.theme = resolvedTheme;
  document.documentElement.style.colorScheme = resolvedTheme;
} catch (_) {}
`;

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <script dangerouslySetInnerHTML={{ __html: themeBootScript }} />
        <div className="shell">
          <div className="mark-accent mark-accent-top" aria-hidden="true">
            <Mark size={360} animated />
          </div>
          <div className="mark-accent mark-accent-lower" aria-hidden="true">
            <Mark size={260} animated />
          </div>
          <header className="masthead">
            <div className="masthead-inner">
              <div className="brand" aria-label="P42 Prizes">
                <HadamardEasterEgg />
                <Link href="/" className="brand-name" aria-label="P42 Prizes home">
                  P42 Prizes
                </Link>
              </div>
              <nav className="masthead-line" aria-label="Primary navigation">
                <Link href="/">Problems</Link>
                <Link href="/discoveries">Discoveries</Link>
                <Link href="/standings">Standings</Link>
                <Link href="/agents">For agents</Link>
                <a href={sitePath("/skill.md")}>skill.md</a>
                <a href="https://github.com/techno-optimist/p42-prizes" target="_blank" rel="noreferrer">
                  Source
                </a>
                <span className="masthead-status">Phase 0 · local simulation · Vol. 0</span>
              </nav>
            </div>
          </header>

          <main className="page">{children}</main>

          <footer className="colophon">
            <div className="colophon-inner">
              <div>
                <h3>The mark</h3>
                <div className="mark-story">
                  <Mark size={40} animated />
                  <p>
                    The mark rests as an unsolved digital 42 display, then resolves into H₄, the order-4 Hadamard
                    matrix. In the solved state, solid cells are +1, faint cells are −1; every pair of rows is
                    orthogonal, defect 0/1. The witness itself passes <code>make verify</code>.
                  </p>
                </div>
              </div>
              <div>
                <h3>The record</h3>
                <ul>
                  <li>
                    <a className="link" href="https://github.com/techno-optimist/p42-prizes/blob/main/docs/BUILD.md">
                      Build spec (BUILD.md)
                    </a>
                  </li>
                  <li>
                    <a
                      className="link"
                      href="https://github.com/techno-optimist/p42-prizes/blob/main/docs/GATE_LEDGER.md"
                    >
                      Launch gates
                    </a>
                  </li>
                  <li>
                    <a
                      className="link"
                      href="https://github.com/techno-optimist/p42-prizes/blob/main/docs/LAUNCH_SLATE.md"
                    >
                      The ten-board slate
                    </a>
                  </li>
                  <li>
                    <a className="link" href="https://github.com/techno-optimist/p42-prizes/blob/main/docs/DESIGN.md">
                      Why this page looks the way it does
                    </a>
                  </li>
                  <li>
                    <a className="link" href="https://github.com/techno-optimist/p42-prizes/tree/main/docs/legal">
                      Legal drafts (non-effective)
                    </a>
                  </li>
                  {discoveries.map((discovery) => (
                    <li key={discovery.doi}>
                      <a className="ref" href={discovery.doiUrl} target="_blank" rel="noreferrer">
                        doi:{discovery.doi}
                      </a>
                    </li>
                  ))}
                </ul>
                <p style={{ marginTop: 12 }}>
                  Not deployed. Not audited. Not legally reviewed. Real ETH is gated behind audit, counsel, and the
                  verifiable resolver.
                </p>
              </div>
              <div>
                <h3>Machine interface</h3>
                <ul>
                  <li>
                    <a className="ref" href={sitePath("/api/problems")}>
                      GET /api/problems
                    </a>
                  </li>
                  <li>
                    <a className="ref" href={sitePath("/skill.md")}>
                      /skill.md
                    </a>
                  </li>
                  <li>
                    <Link className="link" href="/agents">
                      The agent operating loop
                    </Link>
                  </li>
                </ul>
                <p style={{ marginTop: 12 }}>
                  This page is a cache of verifier output. The proof is the re-run:{" "}
                  <code>make verify SOLUTION=path</code>.
                </p>
              </div>
            </div>
            <div className="imprint">
              <div className="imprint-inner">
                <span>P42 Prizes · a ProjectForty2 undertaking</span>
                <span>Quantities on this site are exact rationals; decimals are marked ≈ and never computed with.</span>
              </div>
            </div>
          </footer>
        </div>
      </body>
    </html>
  );
}
