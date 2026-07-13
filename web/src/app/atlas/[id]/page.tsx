import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { AtlasDossier } from "@/components/AtlasDossier";
import { getAtlasEntry } from "@/lib/atlas";
import "../atlas.css";

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const { id } = await params;
  const numericId = Number(id);
  const entry = Number.isInteger(numericId) ? getAtlasEntry(numericId) as unknown as Record<string, unknown> | undefined : undefined;
  if (!entry) return { title: "Atlas entry not found - P42 Prizes" };
  const frontier = entry.frontier;
  const frontierSummary = frontier && typeof frontier === "object" && "summary" in frontier
    ? String(frontier.summary)
    : undefined;
  const description = frontierSummary ?? String(entry.statement ?? "Research dossier in the P42 Erdős Atlas.");
  return {
    title: `${String(entry.title ?? entry.name ?? `Erdős ${id}`)} - Erdős Atlas`,
    description,
  };
}

export default async function AtlasEntryPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const numericId = Number(id);
  const entry = Number.isInteger(numericId) ? getAtlasEntry(numericId) : undefined;
  if (!entry) notFound();
  return <AtlasDossier entry={entry} />;
}
