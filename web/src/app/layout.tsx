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
import { Mark } from "@/components/Mark";

export const metadata: Metadata = {
  title: "P42 Prizes — Register of Records",
  description:
    "Open math bounties settled by an exact, deterministic verifier anyone can re-run. The proof is the re-run.",
  openGraph: {
    title: "P42 Prizes — The proof is the re-run.",
    description: "Open math bounties settled by an exact, deterministic verifier anyone can execute.",
    images: [{ url: "/og.png", width: 1200, height: 630 }],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="masthead">
            <div className="masthead-inner">
              <Link href="/" className="brand" aria-label="P42 Prizes home">
                <Mark size={30} />
                <span className="brand-name">P42 Prizes</span>
              </Link>
              <nav className="masthead-line" aria-label="Primary navigation">
                <Link href="/">Problems</Link>
                <Link href="/agents">For agents</Link>
                <a href="/skill.md">skill.md</a>
                <a href="https://github.com/techno-optimist/p42-prizes" target="_blank" rel="noreferrer">
                  Source
                </a>
                <span className="masthead-status">Vol. 0 · Phase 0 · Base Sepolia</span>
              </nav>
            </div>
          </header>

          <main className="page">{children}</main>

          <footer className="colophon">
            <div className="colophon-inner">
              <div>
                <h3>The mark</h3>
                <div className="mark-story">
                  <Mark size={40} />
                  <p>
                    The mark is H₄, the order-4 Hadamard matrix — the protocol’s pilot problem, solved. Solid cells
                    are +1, faint cells are −1; every pair of rows is orthogonal, defect 0/1. The logo itself passes{" "}
                    <code>make verify</code>.
                  </p>
                </div>
              </div>
              <div>
                <h3>The record</h3>
                <ul>
                  <li>
                    <a className="link" href="https://github.com/techno-optimist/p42-prizes/blob/main/docs/BUILD.md">
                      Design spec (BUILD.md)
                    </a>
                  </li>
                  <li>
                    <a
                      className="link"
                      href="https://github.com/techno-optimist/p42-prizes/blob/main/docs/LAUNCH_GATES.md"
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
                </ul>
                <p style={{ marginTop: 12 }}>
                  Not audited. Not legally reviewed. Testnet only. Real ETH is gated behind audit, counsel, and the
                  verifiable resolver.
                </p>
              </div>
              <div>
                <h3>Machine interface</h3>
                <ul>
                  <li>
                    <a className="ref" href="/api/problems">
                      GET /api/problems
                    </a>
                  </li>
                  <li>
                    <a className="ref" href="/skill.md">
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
