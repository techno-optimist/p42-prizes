import { json } from "@/lib/api";

export async function POST() {
  return json(
    {
      error: "Coinbase Onramp is disabled for P42 Prizes v1",
      capability: "disabled",
      status_detail: "No Onramp session or reviewed funding flow is available.",
    },
    { status: 503 },
  );
}
