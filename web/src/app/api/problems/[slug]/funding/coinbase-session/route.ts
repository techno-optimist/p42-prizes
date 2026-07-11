import { json } from "@/lib/api";

export async function POST() {
  return json(
    {
      error: "Coinbase Onramp is disabled for P42 Prizes v1",
      capability: "disabled",
      future_flow: "wallet-first: onramp to a user-controlled wallet, then explicitly sign pool.fund()",
    },
    { status: 503 },
  );
}
