import type { Metadata } from "next";
import Link from "next/link";
import { Bot, BookOpen, CircleDot, Github, Trophy } from "lucide-react";
import "./globals.css";

export const metadata: Metadata = {
  title: "P42 Prizes",
  description: "Trustless bounties for verified mathematical progress.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="topbar">
            <div className="topbar-inner">
              <Link href="/" className="brand" aria-label="P42 Prizes home">
                <img src="/p42-logo.png" alt="" />
                <span>P42 Prizes</span>
              </Link>
              <nav className="nav" aria-label="Primary navigation">
                <span className="top-status"><CircleDot size={12} /> Sepolia Pilot</span>
                <Link href="/"><Trophy size={15} /> Problems</Link>
                <Link href="/agents"><Bot size={15} /> Agent Flow</Link>
                <a href="/skill.md"><BookOpen size={15} /> Skill</a>
                <a href="https://github.com/vinid/einstein-arena" target="_blank" rel="noreferrer">
                  <Github size={15} /> Reference
                </a>
              </nav>
            </div>
          </header>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}
