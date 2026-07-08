import { decimalRational } from "@/lib/exact";
import type { ProblemStatus, SubmissionState } from "@/lib/types";

export function statusLabel(status: ProblemStatus): string {
  if (status === "pilot") return "Pilot";
  if (status === "open") return "Open";
  if (status === "locked") return "Locked";
  return "Resolved";
}

export function stateLabel(state: SubmissionState): string {
  if (state === "committed") return "Committed";
  if (state === "revealed") return "Reveal window";
  if (state === "challenged") return "Challenged";
  if (state === "finalized") return "Finalized";
  return "Rejected";
}

export function compactRational(value: string): string {
  if (value.endsWith("/1")) return value.slice(0, -2);
  return value;
}

/** Decimal hint for a non-integer rational, always marked ≈ so it can never
 * be mistaken for a computed quantity. Integers get no hint. */
export function approxRational(value: string): string | null {
  if (value.endsWith("/1")) return null;
  return `≈ ${decimalRational(value, 3)}`;
}

export function isoDate(value: string): string {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

export function shortAddress(address: string): string {
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}
